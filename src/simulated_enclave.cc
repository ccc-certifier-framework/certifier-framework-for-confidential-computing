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



const int simulated_measurment_size = 32;
string my_measurement;

const int sealing_key_size = 4 * block_size;
byte sealing_key[sealing_key_size];
key_message my_attestation_key;
RSA* rsa_attestation_key = nullptr;

bool simulator_init(const char* key_file, const char* m_file) {
  // makeup attestation key and measurement and sealing key
  byte m[simulated_measurment_size];

  if (m_file == nullptr) {
    for (int i = 0; i < simulated_measurment_size; i++)
      m[i] = (byte)i;
  } else {
    string m_str(m_file);
    int m_size = simulated_measurment_size;
    if (!read_file(m_str, &m_size, m)) {
      return false;
    }
  }
  my_measurement.assign((char*)m, simulated_measurment_size);

  for (int i = 0; i < sealing_key_size; i++)
    sealing_key[i]= (5*i)%16;

  if (key_file == nullptr) {
    rsa_attestation_key = RSA_new();
    if (!generate_new_rsa_key(2048, rsa_attestation_key))
      return false;
    if (!RSA_to_key(rsa_attestation_key, &my_attestation_key))
      return false;
    my_attestation_key.set_key_type("rsa-2048-private");
    my_attestation_key.set_key_name("attestKey");
  } else {
    string file_name(key_file);
    int at_size =  file_size(file_name)+1;
    byte at[at_size];
    if (!read_file(file_name, &at_size, at)) {
      return false;
    }
    string serialized_key;
    serialized_key.assign((char*)at, at_size);
    if (!my_attestation_key.ParseFromString(serialized_key)) {
      return false;
    }
    // my_attestation_key.set_key_name("local-attestation-key");
    my_attestation_key.set_key_name("attestKey");
    rsa_attestation_key = RSA_new();
    if (!key_to_RSA( my_attestation_key, rsa_attestation_key)) {
      printf("Can't recover attestation key\n");
      return false;
    }
  }

  return true;
}

bool simulated_Getmeasurement(int* size_out, byte* out) {

  if (*size_out < simulated_measurment_size)
    return false;
  *size_out = simulated_measurment_size;
  memcpy(out, (byte*)my_measurement.data(),simulated_measurment_size);
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
  int m_size = my_measurement.size();
  byte m[m_size];
  if (!simulated_Getmeasurement(&m_size, m))
    return false;

  memcpy(input, m, my_measurement.size());
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

  // input: concatinate measurment_size bytes of measurement and in
  // then encrypt it and give it back.
  int m_size = my_measurement.size();
  byte m[m_size];
  if (!simulated_Getmeasurement(&m_size, m))
    return false;

  int real_output_size = output_size;
  if (!authenticated_decrypt(in, in_size, (byte*)sealing_key,
          output, &real_output_size))
    return false;

  if (memcmp((void*)output, (void*)m, (int)m_size) != 0)
    return false;
  real_output_size -= m_size;
  memcpy(out, (byte*)(output + m_size), real_output_size);
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
  // what_to_say is a serialized vse-attestation
  claim_message cm;
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
  string cf("vse-attestation");
  string desc("");
  if (!make_claim(what_to_say_size, what_to_say, cf, desc,
        nb, na, &cm))
    return false;
  string ser_cm;
  if (!cm.SerializeToString(&ser_cm))
    return false;

  signed_claim_message scm;
  if (!make_signed_claim(cm, my_attestation_key, &scm))
    return false;
  string ser_scm;
  if (!scm.SerializeToString(&ser_scm))
    return false;
  if (*size_out < ser_scm.size())
    return false;
  memset(out, 0, *size_out);
  *size_out = ser_scm.size();
  memcpy(out, ser_scm.data(), *size_out);
  return true;
}
