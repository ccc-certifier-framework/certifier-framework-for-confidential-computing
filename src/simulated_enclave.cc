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


// simulated enclave data
bool my_data_initialized = false;
string my_measurement;
const int simulated_measurment_size = 32;
const int sealing_key_size = 64;  // for aes&hmac
byte sealing_key[sealing_key_size];
key_message my_attestation_key;
key_message my_platform_key;
string serialized_platform_claim;
signed_claim_message my_platform_claim;
string serialized_attest_claim;
signed_claim_message my_attest_claim;
RSA* rsa_attestation_key = nullptr;

bool simulated_GetAttestClaim(signed_claim_message* out) {
  if (!my_data_initialized) {
    return false;
  }
  out->CopyFrom(my_attest_claim);
  return true;
}

bool simulated_GetPlatformClaim(signed_claim_message* out) {
  if (!my_data_initialized) {
    return false;
  }
  out->CopyFrom(my_platform_claim);
  return true;
}

bool simulated_Init(const string& asn1_policy_cert, const string& attest_key_file,
      const string& measurement_file, const string& attest_key_signed_claim_file) {

  int m_size = file_size(measurement_file);
  if (m_size < 0) {
    printf("simulated_Init, error 1\n");
    return false;
  }
  byte m[m_size];
  if (!read_file(measurement_file, &m_size, m)) {
    printf("simulated_Init, error 2\n");
    return false;
  }
  my_measurement.assign((char*)m, m_size);

  // For reproducability, make this a fixed key
  for (int i = 0; i < sealing_key_size; i++)
    sealing_key[i]= (5*i)%16;

  // get attest key
  int at_size = file_size(attest_key_file);
  byte at[at_size];
  if (!read_file(attest_key_file, &at_size, at)) {
    return false;
  }
  string serialized_attest_key;
  serialized_attest_key.assign((char*)at, at_size);
  if (!my_attestation_key.ParseFromString(serialized_attest_key)) {
    return false;
  }

  my_attestation_key.set_key_name("attestKey");
  rsa_attestation_key = RSA_new();
  if (!key_to_RSA(my_attestation_key, rsa_attestation_key)) {
    printf("Can't recover attestation key\n");
    return false;
  }

  int a_size = file_size(attest_key_signed_claim_file);
  byte a_buf[a_size];
  if (!read_file(attest_key_signed_claim_file, &a_size, a_buf)) {
    printf("Can't read attest claim\n");
    return false;
  }
  serialized_attest_claim.assign((char*)a_buf, a_size);
  if (!my_attest_claim.ParseFromString(serialized_attest_claim)) {
    printf("Can't parse attest claim\n");
    return false;
  }

  certifier_parent_enclave_type = "software";
  certifier_parent_enclave_type_intitalized = true;
  my_data_initialized = true;
  return true;
}

bool simulated_Getmeasurement(int* size_out, byte* out) {

  if (*size_out < simulated_measurment_size)
    return false;
  *size_out = simulated_measurment_size;
  memcpy(out, (byte*)my_measurement.data(), my_measurement.size());
  return true;
}

bool simulated_Seal(const string& enclave_type, const string& enclave_id,
    int in_size, byte* in, int* size_out, byte* out) {

  const int iv_size = block_size;
  byte iv[iv_size];

  int input_size = in_size + my_measurement.size();
  byte input[input_size];

  int output_size = in_size + my_measurement.size() + iv_size + 512;
  byte output[output_size];

  memset(input, 0, input_size);
  memset(output, 0, output_size);
  if (!get_random(8 * block_size, iv)) {
    printf("getrandom FAILED\n");
    return false;
  }

  // input: concatinate measurment_size bytes of measurement and in
  // then encrypt it and give it back.
  memcpy(input, (byte*)my_measurement.data(), my_measurement.size());
  memcpy(input + my_measurement.size(), in, in_size);

  // output is iv, encrypted bytes
  int real_output_size = output_size;
  if (!authenticated_encrypt(input, input_size, sealing_key, iv, output, &real_output_size))
    return false;
 
  memcpy(out, output, real_output_size);
  *size_out = real_output_size;
  return true;
}

bool simulated_Unseal(const string& enclave_type, const string& enclave_id,
      int in_size, byte* in, int* size_out, byte* out) {

  int iv_size = block_size;
  byte iv[iv_size];
  int output_size = in_size + 128;
  byte output[output_size];

  memset(output, 0, output_size);
  memcpy(iv, in, iv_size);

  int real_output_size = output_size;
  if (!authenticated_decrypt(in, in_size, (byte*)sealing_key,
          output, &real_output_size))
    return false;

  if (memcmp((void*)output, (byte*)my_measurement.data(), (int)my_measurement.size()) != 0) {
    return false;
  }
  real_output_size -= my_measurement.size();
  memcpy(out, (byte*)(output + my_measurement.size()), real_output_size);
  *size_out = real_output_size;
  return true;
}

// Attestation is a signed_claim_message
// with a vse_claim_message claim
bool simulated_Attest(const string& enclave_type,
  int what_to_say_size, byte* what_to_say,
  int* size_out, byte* out) {

  if (rsa_attestation_key == nullptr)
    return false;

  vse_attestation_report_info report_info;
  string serialized_report_info;
  report_info.set_enclave_type("simulated-enclave");

  // what_to_say is usually a serialized vse-attestation_report_info
  // simulated_Attest returns a serialized signed_report
  string nb, na;
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
  report_info.set_user_data((byte*)what_to_say, what_to_say_size);
  report_info.set_verified_measurement(my_measurement);

  const string type("vse-attestation-report");
  string signing_alg("rsa-2048-sha256-pkcs-sign");

  signed_report report; 
  string serialized_signed_report;

  if (!sign_report(type, serialized_report_info,
      signing_alg, my_attestation_key, &serialized_signed_report)) {
    printf("Can't sign report\n");
    return false;
  }
  if (*size_out < (int)serialized_signed_report.size())
    return false;
  memset(out, 0, *size_out);
  *size_out = (int)serialized_signed_report.size();
  memcpy(out, serialized_signed_report.data(), *size_out);
  return true;
}

bool simulated_Verify(string& serialized_signed_report) {
  string type("vse-attestation-report");

  if (!verify_report(type, serialized_signed_report, my_attestation_key)) {
    printf("verify_report failed\n");
    return false;
  }

  signed_report sr;
  if (!sr.ParseFromString(serialized_signed_report)) {
    return false;
  }
  if (!sr.has_report_format() || sr.report_format() != "vse-attestation-report") {
    return false;
  }
  vse_attestation_report_info info;
  if (!info.ParseFromString(sr.report()))
    return false;
  if (info.verified_measurement() != my_measurement)
    return false;
  //  time ok?  not_after, not_after
  return true;
}

bool simulated_GetParentEvidence(string* out) {
  return false;
}


// Delete this eventually.  It is only used in certifier_tests.
bool simulator_init() {
  // makeup attestation key and measurement and sealing key
  byte m[simulated_measurment_size];
  for (int i = 0; i < simulated_measurment_size; i++)
    m[i] = (byte)i;
  my_measurement.assign((char*)m, simulated_measurment_size);
  for (int i = 0; i < sealing_key_size; i++)
    sealing_key[i]= (5*i)%16;
  
  rsa_attestation_key = RSA_new();
  if (!generate_new_rsa_key(2048, rsa_attestation_key))
    return false;
  if (!RSA_to_key(rsa_attestation_key, &my_attestation_key))
    return false;
  my_attestation_key.set_key_type("rsa-2048-private");
  my_attestation_key.set_key_name("attestKey");

  return true;
}

