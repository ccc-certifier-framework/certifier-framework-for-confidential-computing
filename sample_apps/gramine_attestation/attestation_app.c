//  Copyright (c) 2021-22, VMware Inc, and the Certifier Authors.  All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *               2020, Intel Labs
 */

/*
 * Attest/Verify sample application
 * Note that this program builds against mbedTLS 3.x.
 */

#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <iostream>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <fcntl.h>

#include "mbedtls/ssl.h"
#include "mbedtls/x509.h"
#include "mbedtls/sha256.h"
#include "mbedtls/aes.h"
#include "mbedtls/gcm.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

// SGX includes
#include "sgx_arch.h"
#include "sgx_attest.h"
#include "enclave_api.h"

#include "gramine_trusted.h"

uint8_t g_quote[SGX_QUOTE_MAX_SIZE];

enum { SUCCESS = 0, FAILURE = -1 };

// Certifier
typedef unsigned char byte;

/* RA-TLS: on server, only need ra_tls_create_key_and_crt_der() to create keypair and X.509 cert */
int (*ra_tls_create_key_and_crt_der_f)(uint8_t** der_key, size_t* der_key_size, uint8_t** der_crt,
                                       size_t* der_crt_size);

#define SGX_QUOTE_SIZE 32

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

static const char* paths[] = {
    "/dev/attestation/user_report_data",
    "/dev/attestation/target_info",
    "/dev/attestation/my_target_info",
    "/dev/attestation/report",
    "/dev/attestation/protected_files_key",
};

uint8_t user_quote[64];

void print_bytes(int n, byte* buf) {
  for(int i = 0; i < n; i++)
    printf("%02x", buf[i]);
}

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

    /* 1. write some custom data to `user_report_data` file */
    sgx_report_data_t user_report_data = {0};
    uint8_t data[SGX_REPORT_DATA_SIZE];

    /* Test user data */
    memcpy((uint8_t*) data,
           "795fa68798a644d32c1d8e2cfe5834f2390e097f0223d94b4758298d1b5501e5", 64);

    memcpy((void*)&user_report_data, (void*)data, sizeof(user_report_data));

    bytes = rw_file("/dev/attestation/user_report_data", (uint8_t*)&user_report_data,
                         sizeof(user_report_data), /*do_write=*/true);
    if (bytes != sizeof(user_report_data)) {
        printf("Test prep user_data failed %d\n", errno);
        return FAILURE;
    }

    /* 2. read `quote` file */
    bytes = rw_file("/dev/attestation/quote", (uint8_t*)&g_quote, sizeof(g_quote),
		    /*do_write=*/false);
    if (bytes < 0) {
        printf("Test quote interface for user_data failed %d\n", errno);
        return FAILURE;
    }

    /* 3. verify report data read from `quote` */
    if ((size_t)bytes < sizeof(sgx_quote_body_t)) {
        fprintf(stderr, "obtained SGX quote is too small: %ldB (must be at least %ldB)\n", bytes,
                sizeof(sgx_quote_body_t));
        return FAILURE;
    }

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

static inline int64_t local_sgx_getkey(sgx_key_request_t * keyrequest,
                                       sgx_key_128bit_t* key)
{
    int64_t rax = EGETKEY;
    __asm__ volatile(
    ENCLU "\n"
    : "+a"(rax)
    : "b"(keyrequest), "c"(key)
    : "memory");
    return rax;
}

static int getkey(sgx_key_128bit_t* key) {
    ssize_t bytes;


    /* 1. write some custom data to `user_report_data` file */
    sgx_report_data_t user_report_data = {0};
    uint8_t data[SGX_REPORT_DATA_SIZE];

    /* Test user data */
    memcpy((uint8_t*) data,
           "795fa68798a644d32c1d8e2cfe5834f2390e097f0223d94b4758298d1b5501e5", 64);

    memcpy((void*)&user_report_data, (void*)data, sizeof(user_report_data));

    bytes = rw_file("/dev/attestation/user_report_data", (uint8_t*)&user_report_data,
                         sizeof(user_report_data), /*do_write=*/true);
    if (bytes != sizeof(user_report_data)) {
        printf("Test prep user_data failed %d\n", errno);
        return FAILURE;
    }

    /* 4. read `report` file */
    sgx_report_t report;
    bytes = rw_file("/dev/attestation/report", (uint8_t*)&report, sizeof(report), false);
    if (bytes != sizeof(report)) {
        /* error is already printed by file_read_f() */
        return FAILURE;
    }

    /* setup key request structure */
    __sgx_mem_aligned sgx_key_request_t key_request;
    memset(&key_request, 0, sizeof(key_request));
    key_request.key_name = SGX_SEAL_KEY;
    memcpy(&key_request.key_id, &(report.key_id), sizeof(key_request.key_id));

    /* retrieve key via EGETKEY instruction leaf */
    memset(*key, 0, sizeof(*key));
    local_sgx_getkey(&key_request, key);

    printf("Got key:\n");
    print_bytes(sizeof(*key), *key);
    printf("\n");

    return SUCCESS;
}

#define BUF_SIZE 10
#define TAG_SIZE 16
#define KEY_SIZE 16

/*!
 * \brief Test seal interface
 *
 * Perform the following steps in order:
 *   1. Seal some custom data with sealing key
 *   2. Unseal with same key
 *   3. Validate input and output
 *
 * \returns 0 if the test succeeds, -1 otherwise.
 */
static int test_seal_interface(void) {
    int ret = 0;
    int status = SUCCESS;
    __sgx_mem_aligned uint8_t key[KEY_SIZE];
    uint8_t tag[TAG_SIZE];
    unsigned char buf[BUF_SIZE];
    unsigned char enc_buf[BUF_SIZE];
    unsigned char dec_buf[BUF_SIZE];
    mbedtls_gcm_context gcm;

    /* Test with a small buffer */
    memset(buf, 1, sizeof(buf));
    memset(enc_buf, 0, sizeof(enc_buf));
    memset(dec_buf, 0, sizeof(dec_buf));

    /* Get SGX Sealing Key */
    if (getkey(&key) == FAILURE) {
        printf("getkey failed to retrieve SGX Sealing Key\n");
	return FAILURE;
    }

    /* Use GCM encrypt/decrypt */
    mbedtls_gcm_init(&gcm);
    ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 128);

    if (ret != 0) {
        printf("mbedtls_gcm_setkey failed: %d\n", ret);
	status = FAILURE;
	goto done;
    }

    printf("Testing seal interface\n");

    ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, BUF_SIZE, key, KEY_SIZE,
		                    NULL, 0, buf, enc_buf, TAG_SIZE, tag);

    if (ret != 0) {
        printf("mbedtls_gcm_crypt_and_tag failed: %d\n", ret);
	status = FAILURE;
	goto done;
    }

    printf("Testing seal interface - input buf:\n");
    print_bytes(BUF_SIZE, buf);
    printf("\n");
    printf("Testing seal interface - encrypted buf:\n");
    print_bytes(BUF_SIZE, enc_buf);
    printf("\n");
    printf("Testing seal interface - tag:\n");
    print_bytes(TAG_SIZE, tag);
    printf("\n");

    ret = mbedtls_gcm_auth_decrypt(&gcm, BUF_SIZE, key, KEY_SIZE, NULL, 0,
		                   tag, TAG_SIZE, enc_buf, dec_buf);
    if (ret != 0) {
        printf("mbedtls_gcm_auth_decrypt failed: %d\n", ret);
	status = FAILURE;
	goto done;
    }

    printf("Testing seal interface - decrypted buf:\n");
    print_bytes(BUF_SIZE, dec_buf);
    printf("\n");

    ret = memcmp(buf, dec_buf, sizeof(enc_buf));
    if (ret) {
        printf("comparison of encrypted and decrypted buffers failed\n");
	status = FAILURE;
	goto done;
    }

    printf("Testing seal interface - memcmp success\n");
done:
    mbedtls_gcm_free(&gcm);

    return status;
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

    if (bytes != sizeof(user_report_data)) {
        printf("Attest prep user_data failed %d\n", errno);
        return false;
    }

    /* 2. read `quote` file */
    bytes = rw_file("/dev/attestation/quote", (uint8_t*)&g_quote, sizeof(g_quote),
		    /*do_write=*/false);
    if (bytes < 0) {
        printf("Attest quote interface for user_data failed %d\n", errno);
        return false;
    }

    /* Copy out the assertion/quote */
    memcpy(out, g_quote, bytes);
    *size_out = bytes;
    printf("Gramine Attest done\n");

    return true;
}

bool Verify(int user_data_size, byte* user_data, int assertion_size, byte *assertion, int* size_out, byte* out) {
    ssize_t bytes;
    int ret = -1;

    printf("Gramine Verify called user_data_size: %d assertion_size: %d\n",
           user_data_size, assertion_size);

    /* 1. write some custom data to `user_report_data` file */
    sgx_report_data_t user_report_data = {0};

    /* Get a SHA256 of user_data */
    mbedtls_sha256(user_data, user_data_size, user_report_data.d, 0);

    bytes = rw_file("/dev/attestation/user_report_data", (uint8_t*)&user_report_data,
                    sizeof(user_report_data), /*do_write=*/true);
    if (bytes != sizeof(user_report_data)) {
        printf("Verify prep user_data failed %d\n", errno);
        return false;
    }

    /* 2. read `quote` file */
    bytes = rw_file("/dev/attestation/quote", (uint8_t*)&g_quote, sizeof(g_quote),
		    /*do_write=*/false);
    if (bytes < 0) {
        printf("Verify quote interface for user_data failed %d\n", errno);
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

    printf("\nGramine verify quote interface mr_enclave: ");
    print_bytes(SGX_QUOTE_SIZE, quote_body_expected->report_body.mr_enclave.m);

    /* Copy out quote info */
    memcpy(out, quote_body_expected->report_body.mr_signer.m, SGX_QUOTE_SIZE);
    *size_out = SGX_QUOTE_SIZE;

    printf("\nGramine verify quote interface compare done, output: \n");
    print_bytes(*size_out, out);
    printf("\n");

    return true;
}

bool Seal(int in_size, byte* in, int* size_out, byte* out) {
    int ret = 0;
    bool status = true;
    __sgx_mem_aligned uint8_t key[KEY_SIZE];
    uint8_t tag[TAG_SIZE];
    unsigned char buf[BUF_SIZE];
    unsigned char enc_buf[in_size];
    mbedtls_gcm_context gcm;

    printf("Seal: Input size: %d\n", in_size);

    memset(enc_buf, 0, sizeof(enc_buf));

    /* Get SGX Sealing Key */
    if (getkey(&key) == FAILURE) {
        printf("getkey failed to retrieve SGX Sealing Key\n");
	return false;
    }

    /* Use GCM encrypt/decrypt */
    mbedtls_gcm_init(&gcm);
    ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 128);

    if (ret != 0) {
        printf("mbedtls_gcm_setkey failed: %d\n", ret);
        status = false;
	goto done;
    }

    printf("Testing seal interface\n");

    ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, BUF_SIZE, key, KEY_SIZE,
		                    NULL, 0, buf, enc_buf, TAG_SIZE, tag);

    if (ret != 0) {
        printf("mbedtls_gcm_crypt_and_tag failed: %d\n", ret);
        status = false;
	goto done;
    }

    printf("Testing seal interface - input buf:\n");
    print_bytes(BUF_SIZE, buf);
    printf("\n");
    printf("Testing seal interface - encrypted buf:\n");
    print_bytes(BUF_SIZE, enc_buf);
    printf("\n");
    printf("Testing seal interface - tag:\n");
    print_bytes(TAG_SIZE, tag);
    printf("\n");

    memcpy(out, enc_buf, sizeof(enc_buf));
    *size_out = sizeof(enc_buf);
    printf("Testing seal interface - out:\n");
    print_bytes(*size_out, out);
    printf("\n");

    printf("Seal: Successfully sealed size: %d\n", *size_out);
done:
    return status;
}

bool Unseal(int in_size, byte* in, int* size_out, byte* out) {
    printf("Preparing Unsealer size: %d\n", in_size);

    printf("Input to Unseal:\n");
    print_bytes(in_size, in);

    /* Invoke unseal */


    /* Set size */

    printf("Successfully unsealed size: %d, buffer: \n", *size_out);
    print_bytes(*size_out, out);

    return true;
}


int main(int argc, char** argv) {
    int ret;
    size_t len;
    void* ra_tls_attest_lib;

    uint8_t* der_key = NULL;
    uint8_t* der_crt = NULL;

    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;

    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);

    printf("Attestation type:\n");
    char attestation_type_str[SGX_QUOTE_SIZE] = {0};

    ret = rw_file("/dev/attestation/attestation_type", (uint8_t*)attestation_type_str,
                  sizeof(attestation_type_str) - 1, /*do_write=*/false);
    if (ret < 0 && ret != -ENOENT) {
        printf("User requested RA-TLS attestation but cannot read SGX-specific file "
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
            printf("User requested RA-TLS attestation but cannot find lib\n");
            return 1;
        }
    } else {
        printf("Unrecognized remote attestation type: %s\n", attestation_type_str);
        return 1;
    }

    /* A. Gramine Local Tests */
    printf("Test quote interface... %s\n",
            test_quote_interface() == SUCCESS ? "SUCCESS" : "FAIL");

    printf("Test seal/unseal interface... %s\n",
            test_seal_interface() == SUCCESS ? "SUCCESS" : "FAIL");

    /* B. Certifier integrated Attest/Verify */
    bool cert_result = false;

    GramineCertifierFunctions gramineFuncs;
    gramineFuncs.Attest = &Attest;
    gramineFuncs.Verify = &Verify;
    gramineFuncs.Seal = &Seal;
    gramineFuncs.Unseal = &Unseal;

    gramine_setup_certifier_functions(gramineFuncs);
    printf("Invoking certifier...\n");

    cert_result = gramine_local_certify();
    if (!cert_result) {
        printf("gramine_local_certify failed: result = %d\n", cert_result);
        goto exit;
    }

    /* Certifier integrated Seal/Unseal */
    cert_result = gramine_seal();
    if (!cert_result) {
        printf("gramine_seal failed: result = %d\n", cert_result);
        goto exit;
    }

    printf("Done with certifier tests\n");
    fflush(stdout);

exit:

    if (ra_tls_attest_lib)
        dlclose(ra_tls_attest_lib);

    return ret;
}
