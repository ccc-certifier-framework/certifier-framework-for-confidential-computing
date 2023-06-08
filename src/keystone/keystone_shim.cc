#include "keystone_api.h"
#include "certifier_framework.h"
#include "certifier_utilities.h"
#include <string.h>

using std::string;
using namespace certifier::utilities;


//  Copyright (c) 2021-22, VMware Inc, and the Regents of the University of California.
//    All rights reserved.
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


bool keystone_getSealingKey(byte* key) {
  for (int i = 0; i < 64; i++)
    key[i] = i ^ 0x33;
  return true;
}

bool keystone_get_fake_measurement(int* size, byte* measurement) {
  for (int i = 0; i < 32; i++)
    measurement[i] = i;
  *size = 32;
  return true;
}

bool keystone_ecc_sign(const char* alg, EC_KEY* key, int size, byte* msg, int* size_out, byte* out) {
  unsigned int len = (unsigned int)digest_output_byte_size(alg);
  byte digest[len];

  int blk_len = ECDSA_size(key);
  if (*size_out < 2 * blk_len) {
    printf("keystone_ecc_sign: size_out too small %d %d\n", *size_out, blk_len);
    return false;
  }

  if (!digest_message(alg, msg, size, digest, len)) {
    printf("keystone_ecc_sign: digest fails\n");
    return false;
  }
  unsigned int sz = (unsigned int) *size_out;
  if (ECDSA_sign(0, digest, len, out, &sz, key) != 1) {
    printf("keystone_ecc_sign: ECDSA_sign fails\n");
    return false;
  }
  *size_out = (int) sz;
  return true;
}

bool keystone_ecc_verify(const char* alg, EC_KEY* key, int size, byte* msg, int size_sig, byte* sig) {
  unsigned int len = (unsigned int)digest_output_byte_size(alg);
  byte digest[len];

  if (!digest_message(alg, msg, size, digest, len)) {
    printf("ecc_verify: %s digest failed %d\n", alg, len);
    return false;
  }
  int res = ECDSA_verify(0, digest, len, sig, size_sig, key);
  if (res != 1) {
    printf("ecc_verify: ECDSA_failed %d %d\n", len, size_sig);
    return false;
  }
  return true;
}

bool keystone_Init(const int cert_size, byte *cert) {
  // Later certificates go here
  // EC_KEY* generate_new_ecc_key(int num_bits);
  return true;
}


bool keystone_Attest(const int what_to_say_size, byte* what_to_say, int* attestation_size_out, byte* attestation_out) {

  // what to say should be hashed as in other interfaces
  
  assert(what_to_say_size <= ATTEST_DATA_MAXLEN);
  *attestation_size_out = sizeof(struct report_t);
  // unique-ify un-faked fields to avoid accidentally passing tests
  for (unsigned int i = 0; i < sizeof(struct report_t); i++) {
    attestation_out[i] = i ^ 17;
  }
  struct report_t &report = *reinterpret_cast<struct report_t*>(attestation_out);

  // this should be a hash
  report.enclave.data_len = what_to_say_size;
  memcpy(report.enclave.data, what_to_say, what_to_say_size);
  // TODO: input default measurement
  return true;
}

// true = different
bool nonhash_report_cmp(struct report_t& a, struct report_t& b) {
  return (a.enclave.data_len != b.enclave.data_len)
    || memcmp(a.enclave.data, b.enclave.data, ATTEST_DATA_MAXLEN)
    || memcmp(a.enclave.signature, b.enclave.signature, SIGNATURE_SIZE)
    || memcmp(a.sm.public_key, b.sm.public_key, PUBLIC_KEY_SIZE)
    || memcmp(a.sm.signature, b.sm.signature, SIGNATURE_SIZE)
    || memcmp(a.dev_public_key, b.dev_public_key, PUBLIC_KEY_SIZE);
}

bool keystone_Verify(const int what_to_say_size, byte* what_to_say, const int attestation_size,
      byte* attestation, int* measurement_out_size, byte* measurement_out) {
  assert(attestation_size == sizeof(struct report_t));
  struct report_t &report = *reinterpret_cast<struct report_t*>(attestation);

  int gold_attestation_size = 0;
  struct report_t gold_report;
  keystone_Attest(what_to_say_size, what_to_say, &gold_attestation_size, (byte*) &gold_report);

/*
  if (nonhash_report_cmp(gold_report, report) != 0) {
    return false;
  }
 */

  if (!keystone_get_fake_measurement(measurement_out_size, measurement_out)) {
    return false;
  }

  return true;
}

bool keystone_Seal(int in_size, byte* in, int* size_out, byte* out) {
  byte iv[16];
  byte key[64];

  memset(iv, 0, 16);
  if (!keystone_getSealingKey(key)) {
    return false;
  }

  if (!authenticated_encrypt("aes-256-cbc-hmac-sha256", in, in_size, key,
                iv, out, size_out)) {
    return false;
  }
  return true;
}

bool keystone_Unseal(int in_size, byte* in, int* size_out, byte* out) {
  byte iv[16];
  byte key[64];

  if (!keystone_getSealingKey(key)) {
    return false;
  }

  if (!authenticated_decrypt("aes-256-cbc-hmac-sha256", in, in_size, key,
                out, size_out)) {
    return false;
  }
  return true;
}
