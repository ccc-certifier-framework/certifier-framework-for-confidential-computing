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

#include "cca.h"

#include <islet.h>

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
  islet_status_t rv = islet_attest(what_to_say, what_to_say_size, attestation_out, attestation_size_out);
  return rv == ISLET_SUCCESS;
}

bool cca_Verify(const int what_to_say_size, byte* what_to_say,
                const int attestation_size, byte* attestation, int* measurement_out_size,
                byte* measurement_out) {
  byte claims[BUFFER_SIZE];

  int claims_len = 0;
  int user_data_len = 0;

  memset(claims, 0, sizeof(claims));

  islet_status_t rv = islet_verify(attestation, attestation_size, claims, &claims_len);
  if (rv != ISLET_SUCCESS)
    return false;

  rv = islet_parse(CLAIM_TITLE_USER_DATA, claims, claims_len, what_to_say, &user_data_len);
  if (rv != ISLET_SUCCESS)
    return false;

  rv = islet_parse(CLAIM_TITLE_RIM, claims, claims_len, measurement_out, measurement_out_size);
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
