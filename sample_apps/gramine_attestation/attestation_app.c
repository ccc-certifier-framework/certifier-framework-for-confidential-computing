/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *               2020, Intel Labs
 */

/*
 * SSL server demonstration program (with RA-TLS)
 * This program is originally based on an mbedTLS example ssl_server.c but uses RA-TLS flows (SGX
 * Remote Attestation flows) if RA-TLS library is required by user.
 * Note that this program builds against mbedTLS 3.x.
 */

#include "mbedtls/build_info.h"

#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <iostream>
//#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <fcntl.h>

#define mbedtls_fprintf fprintf
#define mbedtls_printf printf

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509.h"

#include "mbedtls/sha256.h"

// Certifier
#include "sgx_arch.h"
#include "sgx_attest.h"

#include "gramine_trusted.h"

uint8_t g_quote[SGX_QUOTE_MAX_SIZE];

enum { SUCCESS = 0, FAILURE = -1 };

// Certifier
typedef unsigned char byte;

/* RA-TLS: on server, only need ra_tls_create_key_and_crt_der() to create keypair and X.509 cert */
int (*ra_tls_create_key_and_crt_der_f)(uint8_t** der_key, size_t* der_key_size, uint8_t** der_crt,
                                       size_t* der_crt_size);

#define HTTP_RESPONSE                                    \
    "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n" \
    "<h2>mbed TLS Test Server</h2>\r\n"                  \
    "<p>Successful connection using: %s</p>\r\n"

#define DEBUG_LEVEL 0

#define MALICIOUS_STR "MALICIOUS DATA"

#define CA_CRT_PATH "ssl/ca.crt"
#define SRV_CRT_PATH "ssl/server.crt"
#define SRV_KEY_PATH "ssl/server.key"

static void my_debug(void* ctx, int level, const char* file, int line, const char* str) {
    ((void)level);

    mbedtls_fprintf((FILE*)ctx, "%s:%04d: %s\n", file, line, str);
    fflush((FILE*)ctx);
}

static ssize_t file_read(const char* path, char* buf, size_t count) {
    FILE* f = fopen(path, "r");
    if (!f)
        return -errno;

    ssize_t bytes = fread(buf, 1, count, f);
    if (bytes <= 0) {
        int errsv = errno;
        fclose(f);
        return -errsv;
    }

    int close_ret = fclose(f);
    if (close_ret < 0)
        return -errno;

    return bytes;
}

static ssize_t rw_file(const char* path, uint8_t* buf, size_t len, bool do_write) {
    ssize_t bytes = 0;
    ssize_t ret = 0;

    int fd = open(path, do_write ? O_WRONLY : O_RDONLY);
    if (fd < 0)
        return fd;

    while ((ssize_t)len > bytes) {
        if (do_write)
            ret = write(fd, buf + bytes, len - bytes);
        else
            ret = read(fd, buf + bytes, len - bytes);

        if (ret > 0) {
            bytes += ret;
        } else if (ret == 0) {
            /* end of file */
            break;
        } else {
            if (ret < 0 && (errno == EAGAIN || errno == EINTR))
                continue;
            break;
        }
    }

    close(fd);
    return ret < 0 ? ret : bytes;
}
#if 0
static ssize_t file_write(const char* path, uint8_t* buf, size_t len) {
    ssize_t bytes = 0;
    ssize_t ret = 0;

    int fd = open(path, O_WRONLY);
    if (fd < 0)
        return fd;

    while ((ssize_t)len > bytes) {
        ret = write(fd, buf + bytes, len - bytes);

        if (ret > 0) {
            bytes += ret;
        } else if (ret == 0) {
            /* end of file */
            break;
        } else {
            if (ret < 0 && (errno == EAGAIN || errno == EINTR))
                continue;
            break;
        }
    }

    close(fd);
    return ret < 0 ? ret : bytes;
}
#endif

static const char* paths[] = {
    "/dev/attestation/user_report_data",
    "/dev/attestation/target_info",
    "/dev/attestation/my_target_info",
    "/dev/attestation/report",
    "/dev/attestation/protected_files_key",
};

uint8_t user_quote[64];

/*!
 * \brief Test quote interface (currently SGX quote obtained from the Quoting Enclave).
 *
 * Perform the following steps in order:
 *   1. write some custom data to `user_report_data` file
 *   2. read `quote` file
 *   3. verify report data read from `quote`
 *
 * \returns 0 if the test succeeds, -1 otherwise.
 */
static int test_quote_interface(void) {
    ssize_t bytes;

    printf("Test quote interface begin\n");

    /* 1. write some custom data to `user_report_data` file */
    sgx_report_data_t user_report_data = {0};
    uint8_t data[SGX_REPORT_DATA_SIZE];
    memcpy((uint8_t*) data, "795fa68798a644d32c1d8e2cfe5834f2390e097f0223d94b4758298d1b5501e5", 64);

    memcpy((void*)&user_report_data, (void*)data, sizeof(user_report_data));

    printf("Test quote interface prep user_data\n");

    bytes = rw_file("/dev/attestation/user_report_data", (uint8_t*)&user_report_data,
                         sizeof(user_report_data), /*do_write=*/true);
    if (bytes != sizeof(user_report_data)) {
        /* error is already printed by rw_file() */
        printf("Test quote interface prep user_data failed %d\n", errno);
        return FAILURE;
    }

    printf("Test quote interface prep done\n");

    /* 2. read `quote` file */
    bytes = rw_file("/dev/attestation/quote", (uint8_t*)&g_quote, sizeof(g_quote),
		    /*do_write=*/false);
    if (bytes < 0) {
        /* error is already printed by rw_file() */
        return FAILURE;
    }

    printf("Test quote interface read done\n");

    /* 3. verify report data read from `quote` */
    if ((size_t)bytes < sizeof(sgx_quote_body_t)) {
        fprintf(stderr, "obtained SGX quote is too small: %ldB (must be at least %ldB)\n", bytes,
                sizeof(sgx_quote_body_t));
        return FAILURE;
    }
    printf("Test quote interface verify done\n");

    sgx_quote_body_t* quote_body = (sgx_quote_body_t*)g_quote;

    if (quote_body->version != /*EPID*/2 && quote_body->version != /*DCAP*/3) {
        fprintf(stderr, "version of SGX quote is not EPID (2) and not ECDSA/DCAP (3)\n");
        return FAILURE;
    }

    int ret = memcmp(quote_body->report_body.report_data.d, user_report_data.d,
                     sizeof(user_report_data));
    if (ret) {
        fprintf(stderr, "comparison of report data in SGX quote failed\n");
        return FAILURE;
    }

    printf("Test quote interface verify quote done\n");

    return SUCCESS;
}

void print_bytes(int n, byte* buf) {
  for(int i = 0; i < n; i++)
    printf("%02x", buf[i]);
}

bool Attest(int claims_size, byte* claims, int* size_out, byte* out) {
    ssize_t bytes;

    printf("Attest quote interface, claims size: %d\n", claims_size);
    print_bytes(claims_size, claims);

    /* 1. write some custom data to `user_report_data` file */
    sgx_report_data_t user_report_data = {0};

    mbedtls_sha256(claims, claims_size, user_report_data.d, 0);

    printf("Attest quote interface prep user_data size: %ld\n", sizeof(user_report_data));

    bytes = rw_file("/dev/attestation/user_report_data", (uint8_t*)&user_report_data,
                         sizeof(user_report_data), /*do_write=*/true);

    printf("Attest quote interface prep bytes size: %ld\n", bytes);

    if (bytes != sizeof(user_report_data)) {
        /* error is already printed by rw_file() */
        printf("Attest quote interface prep user_data failed %d\n", errno);
        return false;
    }

    printf("Attest quote interface prep done\n");

    /* 2. read `quote` file */
    bytes = rw_file("/dev/attestation/quote", (uint8_t*)&g_quote, sizeof(g_quote),
		    /*do_write=*/false);
    if (bytes < 0) {
        /* error is already printed by rw_file() */
        return false;
    }

    /* Copy out the assertion/quote */
    memcpy(out, g_quote, bytes); 
    *size_out = bytes;
    printf("Test quote interface read done\n");

    return true;
}

bool Verify(int user_data_size, byte* user_data, int assertion_size, byte *assertion, int* size_out, byte* out) {
    ssize_t bytes;
    int ret = -1;

    printf("Gramine Verify called user_data_size: %d assertion_size: %d\n", user_data_size, assertion_size);

    /* 1. write some custom data to `user_report_data` file */
    sgx_report_data_t user_report_data = {0};

    /* Get a SHA256 of user_data */
    mbedtls_sha256(user_data, user_data_size, user_report_data.d, 0);

    bytes = rw_file("/dev/attestation/user_report_data", (uint8_t*)&user_report_data,
                         sizeof(user_report_data), /*do_write=*/true);
    if (bytes != sizeof(user_report_data)) {
        /* error is already printed by rw_file() */
        printf("Test quote interface prep user_data failed %d\n", errno);
        return false;
    }

    /* 2. read `quote` file */
    bytes = rw_file("/dev/attestation/quote", (uint8_t*)&g_quote, sizeof(g_quote),
		    /*do_write=*/false);
    if (bytes < 0) {
        /* error is already printed by rw_file() */
        return FAILURE;
    }

    sgx_quote_body_t* quote_body_expected = (sgx_quote_body_t*)assertion;
    sgx_quote_body_t* quote_body_received = (sgx_quote_body_t*)g_quote;

    if (quote_body_expected->version != /*EPID*/2 && quote_body_expected->version != /*DCAP*/3) {
        printf("version of SGX quote is not EPID (2) and not ECDSA/DCAP (3)\n");
        return false;
    }

    /* Compare user report and actual report */
    printf("Comparing user report data in SGX quote size: %ld\n",
           sizeof(quote_body_expected->report_body.report_data.d));

    ret = memcmp(quote_body_received->report_body.report_data.d, user_report_data.d,
                 sizeof(user_report_data));
    if (ret) {
        printf("comparison of user report data in SGX quote failed\n");
        return false;
    }

    /* Compare expected and actual report */
    printf("Comparing quote report data in SGX quote size: %ld\n",
           sizeof(quote_body_expected->report_body.report_data.d));

    ret = memcmp(quote_body_expected->report_body.report_data.d,
                 quote_body_received->report_body.report_data.d,
                 sizeof(quote_body_expected->report_body.report_data.d));
    if (ret) {
        printf("comparison of quote report data in SGX quote failed\n");
        return false;
    }

    printf("\nTest quote interface mr_enclave: size: %d\n", 32);
    print_bytes(32, quote_body_expected->report_body.mr_enclave.m);

    /* Copy out quote info */
    memcpy(out, quote_body_expected->report_body.mr_signer.m, 32);
    *size_out = 32;

    printf("\nTest quote interface compare done, output: size: %d\n", *size_out);
    print_bytes(*size_out, out);
    printf("\n");

    return true;
}

int main(int argc, char** argv) {
    int ret;
    size_t len;
    mbedtls_net_context listen_fd;
    mbedtls_net_context client_fd;
    unsigned char buf[1024];
    const char* pers = "ssl_server";
    void* ra_tls_attest_lib;

    uint8_t* der_key = NULL;
    uint8_t* der_crt = NULL;

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt srvcert;
    mbedtls_pk_context pkey;

    mbedtls_net_init(&listen_fd);
    mbedtls_net_init(&client_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&srvcert);
    mbedtls_pk_init(&pkey);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif

    printf("Attestation type:\n");
    char attestation_type_str[32] = {0};

    ret = file_read("/dev/attestation/attestation_type", attestation_type_str,
                    sizeof(attestation_type_str) - 1);
    if (ret < 0 && ret != -ENOENT) {
        mbedtls_printf("User requested RA-TLS attestation but cannot read SGX-specific file "
                       "/dev/attestation/attestation_type\n");
        return 1;
    }
    printf("Attestation type: %s\n", attestation_type_str);

    if (ret == -ENOENT || !strcmp(attestation_type_str, "none")) {
        ra_tls_attest_lib = NULL;
        ra_tls_create_key_and_crt_der_f = NULL;
    } else if (!strcmp(attestation_type_str, "epid") || !strcmp(attestation_type_str, "dcap")) {
        ra_tls_attest_lib = dlopen("libra_tls_attest.so", RTLD_LAZY);
        if (!ra_tls_attest_lib) {
            mbedtls_printf("User requested RA-TLS attestation but cannot find lib\n");
            return 1;
        }
#if 0 
        char* error;
        ra_tls_create_key_and_crt_der_f = dlsym(ra_tls_attest_lib, "ra_tls_create_key_and_crt_der");
        if ((error = dlerror()) != NULL) {
            mbedtls_printf("%s\n", error);
            return 1;
        }
#endif
    } else {
        mbedtls_printf("Unrecognized remote attestation type: %s\n", attestation_type_str);
        return 1;
    }

    bool cert_result = false;

    mbedtls_printf("  . Seeding the random number generator...");
    fflush(stdout);

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                (const unsigned char*)pers, strlen(pers));
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    /* Certifier local attest and seal tests */
    GramineCertifierFunctions gramineFuncs;
    gramineFuncs.Attest = &Attest;
    gramineFuncs.Verify = &Verify;
    //gramineFuncs.Seal = &Seal;
    //gramineFuncs.Unseal = &Unseal;

    gramine_setup_certifier_functions(gramineFuncs);
    printf("Invoking certifier...\n");

    cert_result = gramine_local_certify();
    if (!cert_result) {
        printf("gramine_local_certify failed: result = %d\n", cert_result);
    fflush(stdout);
        goto exit;
    }
    fflush(stdout);

exit:
#ifdef MBEDTLS_ERROR_C
    if (ret != 0) {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        mbedtls_printf("Last error was: %d - %s\n\n", ret, error_buf);
    }
#endif

    if (ra_tls_attest_lib)
        dlclose(ra_tls_attest_lib);
#if 0
    mbedtls_net_free(&client_fd);
    mbedtls_net_free(&listen_fd);

    mbedtls_x509_crt_free(&srvcert);
    mbedtls_pk_free(&pkey);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    free(der_key);
    free(der_crt);
#endif
    return ret;
}
