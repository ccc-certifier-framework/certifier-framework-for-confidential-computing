//  Copyright (c) 2021-22, VMware Inc, and the Certifier Authors.  All rights
//  reserved.
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
#include <sys/types.h>
#include <sys/stat.h>
#include <stdint.h>

#include <unistd.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <string.h>

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

#ifndef _GRAMINE_API_H_
#  define _GRAMINE_API_H_

#  define MAX_ATTESTATION_SIZE 5000
#  define TAG_SIZE             16

//#define DEBUG

typedef unsigned char byte;

typedef struct GramineSgxAttributes {
  /* Quoting Enclave SVN */
  uint16_t qe_svn;
  /* Provisioning Certification Enclave SVN */
  uint16_t pce_svn;
  /* CPU SVN (16 bytes) */
  uint8_t cpu_svn[SGX_CPUSVN_SIZE];
  /* Debug enclave */
  bool debug;
  /* 64-bit enclave */
  bool mode64bit;
} GramineSgxAttributes;

#  ifdef GRAMINE_CERTIFIER
bool gramine_Init(const int cert_size, byte *cert);
bool gramine_Attest(const int what_to_say_size,
                    byte *    what_to_say,
                    int *     attestation_size_out,
                    byte *    attestation_out);
bool gramine_Verify(const int what_to_say_size,
                    byte *    what_to_say,
                    const int attestation_size,
                    byte *    attestation,
                    int *     measurement_out_size,
                    byte *    measurement_out);
bool gramine_Seal(int in_size, byte *in, int *size_out, byte *out);
bool gramine_Unseal(int in_size, byte *in, int *size_out, byte *out);
#  endif

inline void gramine_print_bytes(int n, byte *buf) {
  for (int i = 0; i < n; i++)
    printf("%02x", buf[i]);
}

typedef struct GramineFunctions {
  bool (*Attest)(const int what_to_say_size,
                 byte *    what_to_say,
                 int *     attestation_size_out,
                 byte *    attestation_out);
  bool (*Verify)(const int what_to_say_size,
                 byte *    what_to_say,
                 const int attestation_size,
                 byte *    attestation,
                 int *     measurement_out_size,
                 byte *    measurement_out);
  bool (*Seal)(int in_size, byte *in, int *size_out, byte *out);
  bool (*Unseal)(int in_size, byte *in, int *size_out, byte *out);
} GramineFunctions;

bool    gramine_Init(const int cert_size, byte *cert);
int     gramine_Getkey(byte *user_report_data, sgx_key_128bit_t *key);
int     gramine_Sgx_Getkey(byte *user_report_data, sgx_key_128bit_t *key);
int     gramine_file_size(const char *file_name);
ssize_t gramine_rw_file(const char *path,
                        uint8_t *   buf,
                        size_t      len,
                        bool        do_write);
void    gramine_setup_functions(GramineFunctions *gramineFuncs);
bool    gramine_get_attributes_from_quote(byte *                attestation,
                                          GramineSgxAttributes *atts);


#endif  // #ifdef _GRAMINE_API_H_
