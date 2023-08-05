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

#include "certifier.h"
#include "support.h"

using namespace certifier::utilities;

char hex_digit(byte v) {
  if (v >= 0 && v <= 9)
    return '0' + v;
  if (v >= 10 && v <= 15)
    return 'a' + v - 10;
  return ' ';
}

bool make_enclave_name(string enclave_type, string *enclave_name) {
  int    measurement_size = 32;
  byte   m[measurement_size];
  string enclave_id;

  if (enclave_type != "simulated-enclave")
    return false;
  for (int i = 0; i < measurement_size; i++)
    m[i] = i;
  char hex[65];
  int  pos = 0;
  hex[64] = 0;
  for (int i = 0; i < measurement_size; i++) {
    hex[2 * i] = hex_digit(m[i] >> 4);
    hex[2 * i + 1] = hex_digit(m[i] & 0xff);
  }
  enclave_name->append((const char *)hex);
  return true;
}


bool test_artifact(bool print_all) {
  X509 *      cert = X509_new();
  key_message signing_key;
  key_message subject_key;
  string      issuer_name_str("Policy-key");  // eventually serialized key
  string      issuer_description_str("Policy-key");
  string      enclave_type("simulated-enclave");

  string subject_name_str;
  if (!make_enclave_name(enclave_type, &subject_name_str))
    return false;
  if (print_all)
    printf("Subject (Enclave) name: %s\n", subject_name_str.c_str());
  string subject_description_str("writer");

  double   secs_duration = 60.0 * 60.0 * 24.0 * 365.0;
  uint64_t sn = 1;

  if (!make_certifier_rsa_key(2048, &signing_key))
    return false;
  if (!make_certifier_rsa_key(2048, &subject_key))
    return false;
  if (!produce_artifact(signing_key,
                        issuer_name_str,
                        issuer_description_str,
                        subject_key,
                        subject_name_str,
                        subject_description_str,
                        sn,
                        secs_duration,
                        cert,
                        true))
    return false;

  if (print_all)
    X509_print_fp(stdout, cert);

  uint64_t    recovered_sn;
  string      recovered_subject_name_str;
  string      recovered_issuer_name_str;
  string      recovered_subject_description_str;
  string      recovered_issuer_description_str;
  key_message recovered_subject_key;
  if (!verify_artifact(*cert,
                       signing_key,
                       &recovered_issuer_name_str,
                       &recovered_issuer_description_str,
                       &recovered_subject_key,
                       &recovered_subject_name_str,
                       &recovered_subject_description_str,
                       &recovered_sn))
    return false;
  if (print_all)
    printf("Recovered subject name: %s\n", recovered_subject_name_str.c_str());
  return true;
}
