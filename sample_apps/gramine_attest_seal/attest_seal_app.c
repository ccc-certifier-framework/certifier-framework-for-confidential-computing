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

#include "attestation.h"
#include "gramine_api.h"

// #define DEBUG

uint8_t g_quote[SGX_QUOTE_MAX_SIZE];

enum { SUCCESS = 0, FAILURE = -1 };

// Certifier
typedef unsigned char byte;

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

uint8_t measurement[SGX_REPORT_DATA_SIZE];
#define measurement_file "./binary_trusted_measurements_file.bin"

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
#if 0
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

    /* Test user data */
    unsigned char user_data[] = "795fa68798a644d32c1d8e2cfe5834f2390e097f0223d94b4758298d1b5501e5";

    /* Get SGX Sealing Key */
    if (gramine_Getkey(user_data, &key) == FAILURE) {
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

    ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, BUF_SIZE, key, KEY_SIZE,
		                    NULL, 0, buf, enc_buf, TAG_SIZE, tag);

    if (ret != 0) {
        printf("mbedtls_gcm_crypt_and_tag failed: %d\n", ret);
	status = FAILURE;
	goto done;
    }

#ifdef DEBUG
    printf("Testing seal interface - input buf:\n");
    print_bytes(BUF_SIZE, buf);
    printf("\n");
    printf("Testing seal interface - encrypted buf:\n");
    print_bytes(BUF_SIZE, enc_buf);
    printf("\n");
    printf("Testing seal interface - tag:\n");
    print_bytes(TAG_SIZE, tag);
    printf("\n");
#endif

    ret = mbedtls_gcm_auth_decrypt(&gcm, BUF_SIZE, key, KEY_SIZE, NULL, 0,
		                   tag, TAG_SIZE, enc_buf, dec_buf);
    if (ret != 0) {
        printf("mbedtls_gcm_auth_decrypt failed: %d\n", ret);
	status = FAILURE;
	goto done;
    }

#ifdef DEBUG
    printf("Testing seal interface - decrypted buf:\n");
    print_bytes(BUF_SIZE, dec_buf);
    printf("\n");
#endif

    ret = memcmp(buf, dec_buf, sizeof(enc_buf));
    if (ret) {
        printf("comparison of encrypted and decrypted buffers failed\n");
	status = FAILURE;
	goto done;
    }

done:
    mbedtls_gcm_free(&gcm);

    return status;
}
#endif

#define BUF_SIZE 10

int main(int argc, char** argv) {
    int ret;
    size_t len;
    void* ra_tls_attest_lib;
    int mr_size;
    int measurement_size;
    int assertion_size;
    int sealed_size;
    int unsealed_size;

    bool status = false;
    byte assertion[MAX_ASSERTION_SIZE];
    byte measurement_recd[SGX_REPORT_DATA_SIZE];
    byte mr_recd[SGX_HASH_SIZE];

    byte buf[BUF_SIZE];
    byte enc_buf[BUF_SIZE];
    byte dec_buf[BUF_SIZE];

    status = gramine_Init(measurement_file, measurement);
    if (status != true) {
        printf("gramine_Init failed\n");
	return -1;
    }

    status = gramine_Attest(SGX_REPORT_DATA_SIZE, measurement, &assertion_size, assertion);
    if (status != true) {
        printf("gramine_Assist failed\n");
	return -1;
    }

    status = gramine_Verify(assertion_size, assertion, &measurement_size, measurement_recd, &mr_size, mr_recd);
    if (status != true) {
        printf("gramine_Verify failed\n");
	return -1;
    }

    /* Test with a small buffer */
    memset(buf, 1, sizeof(buf));
    memset(enc_buf, 0, sizeof(enc_buf));
    memset(dec_buf, 0, sizeof(dec_buf));

    printf("gramine_Seal test begin\n");

    status = gramine_Seal(BUF_SIZE, buf, &sealed_size, enc_buf);
    if (status != true) {
        printf("gramine_Seal failed\n");
	return -1;
    }

    status = gramine_Unseal(BUF_SIZE, enc_buf, &unsealed_size, dec_buf);
    if (status != true) {
        printf("gramine_Unseal failed\n");
	return -1;
    }

    if (sealed_size != unsealed_size) {
        printf("gramine seal/unseal size failed\n");
	return -1;
    }

    if (sealed_size != unsealed_size) {
        printf("gramine seal/unseal size failed\n");
	return -1;
    }

    ret = memcmp(buf, dec_buf, sizeof(enc_buf));
    if (ret) {
        printf("comparison of encrypted and decrypted buffers failed\n");
	return -1;
    }

#ifdef DEBUG
    printf("Testing seal interface - input buf:\n");
    print_bytes(BUF_SIZE, buf);
    printf("\n");
    printf("Testing seal interface - encrypted buf:\n");
    print_bytes(BUF_SIZE, enc_buf);
    printf("\n");
    printf("Testing seal interface - tag:\n");
    print_bytes(TAG_SIZE, tag);
    printf("\n");
#endif

    printf("gramine_Seal test successful\n");
#if 0
    /* A. Gramine Local Tests */
    printf("Test quote interface... %s\n",
            test_quote_interface() == SUCCESS ? "SUCCESS" : "FAIL");

    printf("Test seal/unseal interface... %s\n",
            test_seal_interface() == SUCCESS ? "SUCCESS" : "FAIL");

    /* B. Certifier integrated Attest/Verify */
    bool cert_result = false;

    printf("Invoking certifier...\n");

    cert_result = gramine_local_certify();
    if (!cert_result) {
        printf("gramine_local_certify failed: result = %d\n", cert_result);
        goto exit;
    }
    fflush(stdout);

    /* Certifier integrated Seal/Unseal */
    cert_result = gramine_seal();
    if (!cert_result) {
        printf("gramine_seal failed: result = %d\n", cert_result);
        goto exit;
    }
#endif
    printf("Done with certifier tests\n");
    fflush(stdout);

exit:

    if (ra_tls_attest_lib)
        dlclose(ra_tls_attest_lib);

    return ret;
}
