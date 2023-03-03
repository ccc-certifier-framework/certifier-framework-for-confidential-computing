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

#include <iostream>
#include <stdlib.h>

#include "support.h"
#include "certifier.h"
#include "simulated_enclave.h"
#include "application_enclave.h"
#include "cc_helpers.h"
#include "gramine_api.h"

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

#define MAX_ASSERTION_SIZE 5000

uint8_t g_quote[SGX_QUOTE_MAX_SIZE];

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
#if 0
bool gramine_Attest(int claims_size, byte* claims, int* size_out, byte* out) {
  byte assertion[MAX_ASSERTION_SIZE];
  memset(assertion, 0, MAX_ASSERTION_SIZE);
  int assertion_size = 0;
  bool result = false;

  printf("Invoking Gramine Attest %d\n", claims_size);

#ifdef DEBUG
  print_bytes(claims_size, claims);
  printf("\n");
#endif

  result = (*gramineFuncs.Attest)
           (claims_size, claims, &assertion_size, assertion);
  if (!result) {
    printf("Gramine attest failed\n");
    return false;
  }

  int total_size = assertion_size + claims_size + (sizeof(int) * 2);

  int i, j = 0;
  for (i = 0; i < sizeof(int); i++, j++) {
    out[j] = ((byte*)&assertion_size)[i];
  }

  for (i = 0; i < assertion_size; i++, j++) {
    out[j] = assertion[i];
  }

  for (i = 0; i < sizeof(int); i++, j++) {
    out[j] = ((byte*)&claims_size)[i];
  }

  for (i = 0; i < claims_size; i++, j++) {
    out[j] = claims[i];
  }

  *size_out = j;

  printf("Done Gramine Attest assertion size %d:\n", *size_out);
#ifdef DEBUG
  print_bytes(*size_out, out);
#endif

  return true;
}

bool gramine_Verify(int claims_size, byte* claims, int *user_data_out_size,
                  byte *user_data_out, int* size_out, byte* out) {
  byte assertion[MAX_ASSERTION_SIZE];
  memset(assertion, 0, MAX_ASSERTION_SIZE);
  int assertion_size = 0;
  bool result = false;

  printf("\nInput claims sent to gramine_Verify claims_size %d\n", claims_size);
#ifdef DEBUG
  print_bytes(claims_size, claims);
#endif

  int i, j = 0;
  for (i = 0; i < sizeof(int); i++, j++) {
    ((byte*)&assertion_size)[i] = claims[j];
  }

  for (i = 0; i < assertion_size; i++, j++) {
    assertion[i] = claims[j];
  }

#ifdef DEBUG
  printf("\nAssertion:\n");
  print_bytes(assertion_size, assertion);
#endif

  for (i = 0; i < sizeof(int); i++, j++) {
    ((byte*)user_data_out_size)[i] = claims[j];
  }

  for (i = 0; i < *user_data_out_size; i++, j++) {
    user_data_out[i] = claims[j];
  }

#ifdef DEBUG
  printf("\nuser_data_out:\n");
  print_bytes(*user_data_out_size, user_data_out);
#endif

  printf("Invoking Gramine Verify %d\n", claims_size);
  result = (*gramineFuncs.Verify)
           (*user_data_out_size, user_data_out, assertion_size,
             assertion, size_out, out);
  if (!result) {
    printf("Gramine verify failed\n");
    return false;
  }

  printf("Done Gramine Verification via API\n");

  return true;
}

bool gramine_Seal(int in_size, byte* in, int* size_out, byte* out) {
  bool result = false;
  printf("Invoking Gramine Seal %d\n", in_size);

  result = (*gramineFuncs.Seal)(in_size, in, size_out, out);
  if (!result) {
    printf("Gramine seal failed\n");
    return false;
  }

  printf("Done Gramine Seal %d\n", *size_out);
  return true;
}

bool gramine_Unseal(int in_size, byte* in, int* size_out, byte* out) {
  bool result = false;
  printf("Invoking Gramine Unseal %d\n", in_size);

  result = (*gramineFuncs.Unseal)(in_size, in, size_out, out);
  if (!result) {
    printf("Gramine unseal failed\n");
    return false;
  }

  printf("Done Gramine Unseal %d\n", *size_out);
  return true;
}
#endif
