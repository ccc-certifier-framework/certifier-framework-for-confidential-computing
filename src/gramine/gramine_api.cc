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

#include "gramine_api.h"
#include <string>

using std::string;

#define ATTESTATION_TYPE_SIZE 32

GramineFunctions gramineFuncs;
bool             gramine_platform_cert_initialized = false;
string           gramine_platform_cert;

int gramine_file_size(const char *file_name) {
  struct stat file_info;

  if (stat(file_name, &file_info) != 0)
    return false;
  if (!S_ISREG(file_info.st_mode))
    return false;
  return (int)file_info.st_size;
}

bool gramine_Init(const int cert_size, byte *cert) {
  char   attestation_type_str[ATTESTATION_TYPE_SIZE] = {0};
  size_t ret = 0;

  if (cert_size > 0) {
    gramine_platform_cert.assign((char *)cert, cert_size);
    gramine_platform_cert_initialized = true;
  }

  ret = gramine_rw_file("/dev/attestation/attestation_type",
                        (uint8_t *)attestation_type_str,
                        sizeof(attestation_type_str) - 1,
                        /*do_write=*/false);
  if (ret < 0 && ret != -ENOENT) {
    printf("User requested SGX attestation but cannot read SGX-specific file "
           "/dev/attestation/attestation_type\n");
    return false;
  }

#ifdef DEBUG
  printf("Attestation type: %s\n", attestation_type_str);
#endif

  if (strcmp(attestation_type_str, "dcap")) {
    printf("Unsupported remote attestation type: %s\n", attestation_type_str);
    return false;
  }

  /* Setup Gramine specific API calls */
  gramine_setup_functions(&gramineFuncs);

  return true;
}

bool gramine_Attest(const int what_to_say_size,
                    byte *    what_to_say,
                    int *     attestation_size_out,
                    byte *    attestation_out) {
  bool result = false;

#ifdef DEBUG
  printf("Invoking Gramine Attest %d\n", what_to_say_size);
  gramine_print_bytes(what_to_say_size, what_to_say);
  printf("\n");
#endif

  result = (*gramineFuncs.Attest)(what_to_say_size,
                                  what_to_say,
                                  attestation_size_out,
                                  attestation_out);
  if (!result) {
    printf("Gramine attest failed\n");
    return false;
  }

#ifdef DEBUG
  printf("Done Gramine Attest attestation size %d:\n", *attestation_size_out);
  gramine_print_bytes(*attestation_size_out, attestation_out);
#endif

  return true;
}

bool gramine_Verify(const int what_to_say_size,
                    byte *    what_to_say,
                    const int attestation_size,
                    byte *    attestation,
                    int *     measurement_out_size,
                    byte *    measurement_out) {
  bool result = false;

#ifdef DEBUG
  printf("\nInput data sent to gramine_Verify size: %d\n", what_to_say_size);
  gramine_print_bytes(what_to_say_size, what_to_say);
  printf("\nAttestation size: %d\n", attestation_size);
  gramine_print_bytes(attestation_size, attestation);
#endif

  result = (*gramineFuncs.Verify)(what_to_say_size,
                                  what_to_say,
                                  attestation_size,
                                  attestation,
                                  measurement_out_size,
                                  measurement_out);
  if (!result) {
    printf("Gramine verify failed\n");
    return false;
  }

#ifdef DEBUG
  printf("Done Gramine Verification via API\n");
#endif
  return true;
}

bool gramine_Seal(int in_size, byte *in, int *size_out, byte *out) {
  bool result = false;

#ifdef DEBUG
  printf("Invoking Gramine Seal size: %d\n", in_size);
#endif

  result = (*gramineFuncs.Seal)(in_size, in, size_out, out);
  if (!result) {
    printf("Gramine seal failed\n");
    return false;
  }

#ifdef DEBUG
  printf("Done Gramine Seal size: %d\n", *size_out);
#endif
  return true;
}

bool gramine_Unseal(int in_size, byte *in, int *size_out, byte *out) {
  bool result = false;

#ifdef DEBUG
  printf("Invoking Gramine Unseal size: %d\n", in_size);
#endif

  result = (*gramineFuncs.Unseal)(in_size, in, size_out, out);
  if (!result) {
    printf("Gramine unseal failed\n");
    return false;
  }

#ifdef DEBUG
  printf("Done Gramine Unseal size: %d\n", *size_out);
#endif

  return true;
}

int gramine_Getkey(byte *user_report_data, sgx_key_128bit_t *key) {
  return gramine_Sgx_Getkey(user_report_data, key);
}
