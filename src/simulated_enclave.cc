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

#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/x509v3.h>

#include "support.h"
#include "simulated_enclave.h"
#include "certifier.pb.h"

#include <string>

using std::string;
using namespace certifier::framework;
using namespace certifier::utilities;

// simulated enclave data
bool                 my_data_initialized = false;
string               my_measurement;
const int            simulated_measurment_size = 32;
const int            sealing_key_size = 64;  // for aes&hmac
byte                 sealing_key[sealing_key_size];
key_message          my_attestation_key;
key_message          my_platform_key;
string               serialized_platform_claim;
signed_claim_message my_platform_claim;
string               serialized_attest_claim;
signed_claim_message my_attest_claim;
RSA *                rsa_attestation_key = nullptr;

bool simulated_GetAttestClaim(signed_claim_message *out) {
  if (!my_data_initialized) {
    printf("simulated_GetAttestClaim: data not initialized\n");
    return false;
  }
  out->CopyFrom(my_attest_claim);
  return true;
}

bool simulated_GetPlatformClaim(signed_claim_message *out) {
  if (!my_data_initialized) {
    printf("simulated_GetPlatformClaim: data not initialized\n");
    return false;
  }
  out->CopyFrom(my_platform_claim);
  return true;
}

bool simulated_Init(const string &serialized_attest_key,
                    const string &measurement,
                    const string &serialized_attest_key_signed_claim) {

  my_measurement.assign((char *)measurement.data(), measurement.size());

  // For reproducability, make this a fixed key
  for (int i = 0; i < sealing_key_size; i++)
    sealing_key[i] = (5 * i) % 16;

  // attest key
  if (!my_attestation_key.ParseFromString(serialized_attest_key)) {
    printf("simulated_Init: Can't parse attest key\n");
    printf("Key: %s\n", serialized_attest_key.c_str());
    return false;
  }

  my_attestation_key.set_key_name("attestKey");
  rsa_attestation_key = RSA_new();
  if (!key_to_RSA(my_attestation_key, rsa_attestation_key)) {
    printf("simulated_Init: Can't recover attestation key\n");
    return false;
  }

  // Claim
  if (!my_attest_claim.ParseFromString(serialized_attest_key_signed_claim)) {
    printf("simulated_Init: Can't parse attest claim\n");
    return false;
  }

  certifier_parent_enclave_type = "software";
  certifier_parent_enclave_type_intitalized = true;
  my_data_initialized = true;
  return true;
}

bool simulated_Getmeasurement(int *size_out, byte *out) {

  if (*size_out < simulated_measurment_size)
    return false;
  *size_out = simulated_measurment_size;
  memcpy(out, (byte *)my_measurement.data(), my_measurement.size());
  return true;
}

const int max_seal_pad = 256;

bool simulated_Seal(const string &enclave_type,
                    const string &enclave_id,
                    int           in_size,
                    byte *        in,
                    int *         size_out,
                    byte *        out) {

  const int iv_size = block_size;
  byte      iv[iv_size];

  int  input_size = in_size + my_measurement.size();
  byte input[input_size];

  int output_size = in_size + my_measurement.size() + iv_size + max_seal_pad;
  if (out == nullptr) {
    *size_out = output_size;
    return true;
  }
  byte output[output_size];

  memset(input, 0, input_size);
  memset(output, 0, output_size);
  if (!get_random(8 * block_size, iv)) {
    printf("simulated_Seal: getrandom FAILED\n");
    return false;
  }

  // input: concatinate measurment_size bytes of measurement and in
  // then encrypt it and give it back.
  memcpy(input, (byte *)my_measurement.data(), my_measurement.size());
  memcpy(input + my_measurement.size(), in, in_size);

  // output is iv, encrypted bytes
  int real_output_size = output_size;
  if (!authenticated_encrypt(Enc_method_aes_256_cbc_hmac_sha256,
                             input,
                             input_size,
                             sealing_key,
                             sealing_key_size,
                             iv,
                             16,
                             output,
                             &real_output_size)) {
    printf("simulated_Seal: authenticated encrypt failed\n");
    return false;
  }

  memcpy(out, output, real_output_size);
  *size_out = real_output_size;
  return true;
}

bool simulated_Unseal(const string &enclave_type,
                      const string &enclave_id,
                      int           in_size,
                      byte *        in,
                      int *         size_out,
                      byte *        out) {

  int  iv_size = block_size;
  byte iv[iv_size];
  int  output_size = in_size + max_seal_pad;
  byte output[output_size];
  if (out == nullptr) {
    *size_out = output_size;
    return true;
  }

  memset(output, 0, output_size);
  memcpy(iv, in, iv_size);

  int real_output_size = output_size;
  if (!authenticated_decrypt(Enc_method_aes_256_cbc_hmac_sha256,
                             in,
                             in_size,
                             (byte *)sealing_key,
                             sealing_key_size,
                             output,
                             &real_output_size)) {
    printf("simulated_Unseal: authenticated decrypt failed\n");
    return false;
  }

  if (memcmp((void *)output,
             (byte *)my_measurement.data(),
             (int)my_measurement.size())
      != 0) {
    printf("simulated_Unseal: measurement mismatch\n");
    return false;
  }
  real_output_size -= my_measurement.size();
  memcpy(out, (byte *)(output + my_measurement.size()), real_output_size);
  *size_out = real_output_size;
  return true;
}

// Attestation is a signed_claim_message
// with a vse_claim_message claim
bool simulated_Attest(const string &enclave_type,
                      int           what_to_say_size,
                      byte *        what_to_say,
                      int *         size_out,
                      byte *        out) {

  vse_attestation_report_info report_info;
  string                      serialized_report_info;
  report_info.set_enclave_type("simulated-enclave");

  // what_to_say is usually a serialized vse-attestation_report_info
  // simulated_Attest returns a serialized signed_report
  string     nb, na;
  time_point tn, tf;
  if (!time_now(&tn))
    return false;
  if (!add_interval_to_time_point(tn, 24.0 * 365.0, &tf))
    return false;
  if (!time_to_string(tn, &nb))
    return false;
  if (!time_to_string(tf, &na))
    return false;

  report_info.set_not_before(nb);
  report_info.set_not_after(na);
  report_info.set_user_data((byte *)what_to_say, what_to_say_size);
  report_info.set_verified_measurement((byte *)my_measurement.data(),
                                       my_measurement.size());
  if (!report_info.SerializeToString(&serialized_report_info)) {
    return false;
  }

  const string type("vse-attestation-report");
  string       signing_alg(Enc_method_rsa_2048_sha256_pkcs_sign);
  string       serialized_signed_report;

  if (!sign_report(type,
                   serialized_report_info,
                   signing_alg,
                   my_attestation_key,
                   &serialized_signed_report)) {
    printf("simulated_Attest: Can't sign report\n");
    return false;
  }

  if (out == nullptr) {
    *size_out = (int)serialized_signed_report.size();
    return true;
  }
  if (*size_out < (int)serialized_signed_report.size()) {
    printf("simulated_Attest: size out in simulated Attest is too small\n");
    return false;
  }
  memset(out, 0, *size_out);
  *size_out = (int)serialized_signed_report.size();
  memcpy(out, serialized_signed_report.data(), *size_out);
  return true;
}

bool simulated_Verify(string &serialized_signed_report) {
  string type("vse-attestation-report");

  if (!verify_report(type, serialized_signed_report, my_attestation_key)) {
    printf("simulated_Verify: verify_report failed\n");
    return false;
  }

  signed_report sr;
  if (!sr.ParseFromString(serialized_signed_report)) {
    printf("simulated_Verify: Can't parse serialized_signed_report\n");
    return false;
  }
  if (!sr.has_report_format()
      || sr.report_format() != "vse-attestation-report") {
    printf("simulated_Verify: signed report malformed\n");
    return false;
  }
  vse_attestation_report_info info;
  if (!info.ParseFromString(sr.report())) {
    printf("simulated_Verify: Can't parse report\n");
    return false;
  }
  if (info.verified_measurement() != my_measurement) {
    printf("verified measurement: ");
    print_bytes(info.verified_measurement().size(),
                (byte *)info.verified_measurement().data());
    printf("\n");
    printf("my       measurement: ");
    print_bytes(my_measurement.size(), (byte *)my_measurement.data());
    printf("\n");
    printf("simulated_Verify: simulated_Verify 3 failed\n");
    return false;
  }
  return check_date_range(info.not_before(), info.not_after());
}

bool simulated_GetParentEvidence(string *out) {
  return false;
}

// Delete this eventually.  It is only used in certifier_tests.
bool simulator_init() {
  // makeup attestation key and measurement and sealing key
  byte m[simulated_measurment_size];
  for (int i = 0; i < simulated_measurment_size; i++)
    m[i] = (byte)i;
  my_measurement.assign((char *)m, simulated_measurment_size);
  for (int i = 0; i < sealing_key_size; i++)
    sealing_key[i] = (5 * i) % 16;

  rsa_attestation_key = RSA_new();
  if (!generate_new_rsa_key(2048, rsa_attestation_key)) {
    printf("simulator_init: Can't generate RSA key\n");
    return false;
  }
  if (!RSA_to_key(rsa_attestation_key, &my_attestation_key)) {
    printf("simulator_init: Can't convert RSA key to internal\n");
    return false;
  }
  my_attestation_key.set_key_type(Enc_method_rsa_2048_private);
  my_attestation_key.set_key_name("attestKey");

  return true;
}
