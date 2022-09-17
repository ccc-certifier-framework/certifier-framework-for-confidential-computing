#include "certifier.h"
#include "support.h"

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

#ifdef SEV_SNP

#include "attestation.h"

extern bool verify_sev_Attest(EVP_PKEY* key, int size_sev_attestation, byte* the_attestation,
      int* size_measurement, byte* measurement);
extern EVP_PKEY* get_simulated_vcek_key();
extern bool sev_verify_report(EVP_PKEY* key, struct attestation_report *report);

bool test_sev(bool print_all) {
  const int data_size = 64;
  string enclave_type("sev-enclave");
  string enclave_id("test-enclave");
  byte data[data_size];
  for (int i = 0; i < data_size; i++)
    data[i] = i;

  byte sealed[512];
  int sealed_size = 512;
  memset(sealed, 0, sealed_size);

  if (!Seal(enclave_type, enclave_id, data_size, data, &sealed_size, sealed)) {
    printf("test_sev, error 1\n");
    return false;
  }

  if (print_all) {
    printf("\n");
    printf("data   size : %d\n", data_size);
    print_bytes(data_size, data);
    printf("\n");
    printf("Sealed size : %d\n", sealed_size);
    print_bytes(sealed_size, sealed);
    printf("\n");
  }

  byte unsealed[512];
  int unsealed_size = 512;
  memset(unsealed, 0, unsealed_size);

  if (!Unseal(enclave_type, enclave_id, sealed_size, sealed, &unsealed_size, unsealed)) {
    printf("test_sev, error 2\n");
    return false;
  }

  if (print_all) {
    printf("\n");
    printf("unsealed size: %d\n", unsealed_size);
    print_bytes(unsealed_size, unsealed);
    printf("\n");
  }

  if (unsealed_size != data_size || memcmp(data, unsealed, data_size) != 0) {
    printf("test_sev, error 3\n");
    return false;
  }

  int size_measurement = 64;
  byte measurement[size_measurement];
  memset(measurement, 0, size_measurement);

  attestation_user_data ud;
  ud.set_enclave_type("sev-enclave");
  RSA* r = RSA_new();
  if (!generate_new_rsa_key(2048, r))
    return false;
  key_message private_auth_key;
  key_message public_auth_key;
  if (!RSA_to_key(r, &private_auth_key)) {
    return false;
  }
  private_auth_key.set_key_name("authKey");
  if (!private_key_to_public_key(private_auth_key, &public_auth_key)) {
      return false;
  }
  // time
  time_point t;
  time_now(&t);
  string str_now;
  time_to_string(t, &str_now);
  ud.set_time(str_now);
  ud.mutable_enclave_key()->CopyFrom(public_auth_key);

  int size_out = 2048;
  byte out[size_out];
  string serialized_user;
  if (!ud.SerializeToString(&serialized_user)) {
    return false;
  }
  if (!Attest(ud.enclave_type(), serialized_user.size(), (byte*)serialized_user.data(), &size_out, out)) {
    printf("Attest failed\n");
    return false;
  }

  extern EVP_PKEY* get_simulated_vcek_key();
  EVP_PKEY* verify_pkey = get_simulated_vcek_key();
  if (verify_pkey == nullptr)
    return false;
  bool success = verify_sev_Attest(verify_pkey, size_out, out, &size_measurement, measurement);
  EVP_PKEY_free(verify_pkey);
  verify_pkey = nullptr;

  if (!success) {
    printf("verify_sev_Attest failed\n");
    return false;
  }

  sev_attestation_message sev_att;
  string at_str;
  at_str.assign((char*)out, size_out);
  if (!sev_att.ParseFromString(at_str)) {
    printf("Can't parse attestation\n");
    return false;
  }

  attestation_user_data ud_new;
  string ud_str;
  ud_str.assign((char*)sev_att.what_was_said().data(), sev_att.what_was_said().size());
  if (!ud_new.ParseFromString(ud_str)) {
    printf("Can't parse user data\n");
    return false;
  }

  if (!same_key(ud_new.enclave_key(), ud.enclave_key())) {
    printf("not same key\n");
    return false;
  }

  if (print_all) {
    printf("\nMeasurement size: %d, measurement: ", size_measurement);
    print_bytes(size_measurement, measurement);
    printf("\n");
  }

  return true;
}

#endif // SEV_SNP
