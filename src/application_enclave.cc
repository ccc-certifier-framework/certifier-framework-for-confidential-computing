#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/x509v3.h>

#include "support.h" 
#include "simulated_enclave.h" 
#include "application_enclave.h" 
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

bool application_GetCerts(int* size_out, byte* out) {
  return false;
}

bool application_Seal(int in_size, byte* in, int* size_out, byte* out) {

#if 0
  const int iv_size = block_size;
  byte iv[iv_size];
  string my_measurement;

  int input_size = in_size + my_measurement.size();
  byte input[input_size];

  int output_size = in_size + my_measurement.size() + iv_size + 512;
  byte output[output_size];

  memset(input, 0, input_size);
  memset(output, 0, output_size);
  if (!get_random(8 * block_size, iv)) {
    return false;
  }

  // input: concatinate measurment_size bytes of measurement and in
  // then encrypt it and give it back.
  int m_size = my_measurement.size();
  byte m[m_size];
  if (!application_Getmeasurement(enclave_type, enclave_id, &m_size, m))
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
#else
  return false;
#endif
}

bool application_Unseal(int in_size, byte* in, int* size_out, byte* out) {

#if 0
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
  if (!application_Getmeasurement(enclave_type, enclave_id, &m_size, m))
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
#else
  return false;
#endif
}

// Attestation is a signed_claim_message
// with a vse_claim_message claim
bool application_Attest(int what_to_say_size, byte* what_to_say,
  int* size_out, byte* out) {

#if 0
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
#else
  return false;
#endif
}
