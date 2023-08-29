//  Copyright (c) 2023, VMware Inc, and the Certifier Authors.  All rights
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

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

#ifndef byte
typedef unsigned char byte;
#endif

#ifdef __cplusplus
extern "C" {
#endif

bool tee_Attest(const char *enclave_type,
                int         what_to_say_size,
                byte *      what_to_say,
                int *       size_out,
                byte *      out);

bool tee_Seal(const char *enclave_type,
              const char *enclave_id,
              int         in_size,
              byte *      in,
              int *       size_out,
              byte *      out);

bool tee_Unseal(const char *enclave_type,
                const char *enclave_id,
                int         in_size,
                byte *      in,
                int *       size_out,
                byte *      out);

bool tee_Simulated_Init(const char *asn1_policy_cert,
                        const char *attest_key_file,
                        const char *measurement_file,
                        const char *attest_key_signed_claim_file);

#ifdef __cplusplus
}
#endif
