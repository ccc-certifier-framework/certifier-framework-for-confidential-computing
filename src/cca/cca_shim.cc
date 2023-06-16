//  Copyright (c) 2021-23, VMware Inc, and the Certifier Authors.  All rights reserved.
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

#include <islet.h>
#include "cca.h"
#include "certifier_framework.h"
#include "certifier_utilities.h"

using namespace certifier::utilities;

// Some reasonable size to allocate an attestation report on-stack buffers.
// Typical attestation report size is over 1K.
#define BUFFER_SIZE 2048

static const char CLAIM_TITLE_USER_DATA[] = "User data";
static const char CLAIM_TITLE_RIM[] = "Realm initial measurement";

bool cca_Init(const int cert_size, byte *cert) {
  return true;
}

bool cca_Attest(const int what_to_say_size, byte* what_to_say,
                int* attestation_size_out, byte* attestation_out) {

  int len = digest_output_byte_size("sha-256");
  byte cca_what_to_say[len];
  if (!digest_message("sha-256", what_to_say, what_to_say_size,
        cca_what_to_say, len)) {
    printf("cca_Attest: Can't digest what_to_say\n");
    return false;
  }

  islet_status_t rv = islet_attest(cca_what_to_say, len,
                                   attestation_out, attestation_size_out);
  printf("%s(): rv=%d\n", __func__, rv);
  return rv == ISLET_SUCCESS;
}

#if 0
static void print_buf(int sz, byte* buf) {
  for (int i = 0; i < sz; i++)
    printf("%02x", buf[i]);
  printf("\n");
}
#endif

bool cca_Verify(const int what_to_say_size, byte* what_to_say,
                const int attestation_size, byte* attestation,
                int* measurement_out_size, byte* measurement_out) {
  byte claims[BUFFER_SIZE];

  int claims_len = 0;

  memset(claims, 0, sizeof(claims));

  islet_status_t rv = islet_verify(attestation, attestation_size, claims, &claims_len);
  if (rv != ISLET_SUCCESS)
    return false;

  int len = digest_output_byte_size("sha-256");
  byte cca_what_to_say_expected[len];
  if (!digest_message("sha-256", what_to_say, what_to_say_size,
        cca_what_to_say_expected, len)) {
    printf("cca_Verify: Can't digest what_to_say\n");
    return false;
  }

  byte cca_what_to_say_returned[2*len];
  int user_data_len = len;
  rv = islet_parse(CLAIM_TITLE_USER_DATA, claims, claims_len, cca_what_to_say_returned, &user_data_len);
  if (rv != ISLET_SUCCESS)
    return false;

  if (memcmp(cca_what_to_say_returned, cca_what_to_say_expected, len) != 0)
    return false;

  rv = islet_parse(CLAIM_TITLE_RIM, claims, claims_len, measurement_out,
                   measurement_out_size);
  return rv == ISLET_SUCCESS;
}

bool cca_Seal(int in_size, byte* in, int* size_out, byte* out) {
  islet_status_t rv = islet_seal(in, in_size, out, size_out);
  return rv == ISLET_SUCCESS;
}

bool cca_Unseal(int in_size, byte* in, int* size_out, byte* out) {
  islet_status_t rv = islet_unseal(in, in_size, out, size_out);
  return rv == ISLET_SUCCESS;
}
