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

#include "tee_primitives.h"
#include "certifier_framework.h"
#include "certifier_utilities.h"
#include "simulated_enclave.h"

using namespace certifier::framework;
using namespace certifier::utilities;
using namespace std;

bool tee_Attest(const char *enclave_type,
                int         what_to_say_size,
                byte *      what_to_say,
                int *       size_out,
                byte *      out) {
  string enc_type(enclave_type);
  return Attest(enc_type, what_to_say_size, what_to_say, size_out, out);
}

bool tee_Seal(const char *enclave_type,
              const char *enclave_id,
              int         in_size,
              byte *      in,
              int *       size_out,
              byte *      out) {
  string enc_type(enclave_type);
  string enc_id(enclave_id);
  return Seal(enc_type, enc_id, in_size, in, size_out, out);
}

bool tee_Unseal(const char *enclave_type,
                const char *enclave_id,
                int         in_size,
                byte *      in,
                int *       size_out,
                byte *      out) {
  string enc_type(enclave_type);
  string enc_id(enclave_id);
  return Unseal(enc_type, enc_id, in_size, in, size_out, out);
}

bool tee_Simulated_Init(const char *asn1_policy_cert,
                        const char *attest_key_file,
                        const char *measurement_file,
                        const char *attest_key_signed_claim_file) {

  const string attest_key_file_str(attest_key_file);
  const string measurement_file_str(measurement_file);
  const string attest_key_signed_claim_file_str(attest_key_signed_claim_file);

  string serialized_attest_key;
  if (!read_file_into_string(attest_key_file_str, &serialized_attest_key)) {
    printf("%s() error, line %d, Can't read attest file\n", __func__, __LINE__);
    return false;
  }

  string measurement;
  if (!read_file_into_string(measurement_file_str, &measurement)) {
    printf("%s() error, line %d, Can't read measurement file\n",
           __func__,
           __LINE__);
    return false;
  }

  string serialized_endorsement;
  if (!read_file_into_string(attest_key_signed_claim_file_str,
                             &serialized_endorsement)) {
    printf("%s() error, line %d, Can't read endorsement file\n",
           __func__,
           __LINE__);
    return false;
  }

  return simulated_Init(serialized_attest_key,
                        measurement,
                        serialized_endorsement);
}
