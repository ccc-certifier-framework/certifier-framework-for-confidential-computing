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

#if 0
  int res = ECDSA_verify(0, digest, len, sig, size_sig, key);
  if (res != 1) {
    printf("ecc_verify: ECDSA_failed %d %d\n", len, size_sig);
    return false;
  }
#endif 
  return true;
}

EC_KEY* fake_attest_key = nullptr;
key_message attest_private_key;
key_message attest_public_key;

bool keystone_Init(const int cert_size, byte *cert) {
  // later, we should read in the key and cert chain
  fake_attest_key = generate_new_ecc_key(256);
  if (fake_attest_key == nullptr) {
    printf("keystone_Init: can't init Ecc key\n");
    return false;
  }

  if (!ECC_to_key(fake_attest_key, &attest_private_key)) {
    printf("keystone_Init: can't init attest private key\n");
    return false;
  }
  attest_private_key.set_key_name("keystone-simulated-attest-key");
  if (!private_key_to_public_key(attest_private_key, &attest_public_key)) {
    printf("keystone_Init: can't convert attest private key\n");
    return false;
  }
  return true;
}


bool keystone_Attest(const int what_to_say_size, byte* what_to_say, int* attestation_size_out, byte* attestation_out) {

  int sz= (int)(sizeof(struct enclave_report_t) + sizeof(struct sm_report_t) + PUBLIC_KEY_SIZE);
  *attestation_size_out = sz;

  assert(what_to_say_size <= ATTEST_DATA_MAXLEN);

  memset(attestation_out, 0, sizeof(report_t));
  struct report_t &report = *reinterpret_cast<struct report_t*>(attestation_out);

  // report.enclave.data gets the hash of what_to_say
  int len = digest_output_byte_size("sha-256");
  if (!digest_message("sha-256", what_to_say, what_to_say_size,
        report.enclave.data, len)) {
    printf("keystone_Attest: Can't digest what_to_say\n");
    return false;
  }

  // this should be a hash
  report.enclave.data_len = what_to_say_size;
  memcpy(report.enclave.data, what_to_say, what_to_say_size);
  report.enclave.data_len = 32;

  // report.enclave.hash is measurement or its hash
  int measurement_size = MDSIZE;
  if (!keystone_get_fake_measurement(&measurement_size, report.enclave.hash)) {
    printf("keystone_Attest: Can't get measurement\n");
    return false;
  }

  // Put the signing public key in report.sm.public_key, leave signature 0'd
  // for now.
  // Put the signing public key in report.enclave.dev_public_key.
  //
  // Hash report.enclave.hash, report.enclave.datalen and report.enclave.data
  // and sign that hash.
  len = digest_output_byte_size("sha-256");
  byte signed_hash[len];
  if (!digest_message("sha-256", (byte*)report.enclave.hash,
        MDSIZE + sizeof(uint64_t)+report.enclave.data_len,
        signed_hash, len)) {
    printf("keystone_Attest: Can't hash final signature\n");
    return false;
  }

  int size_out = SIGNATURE_SIZE;
  if (!keystone_ecc_sign("sha-256", fake_attest_key, len, signed_hash,
        &size_out, report.enclave.signature)) {
    printf("keystone_Attest: Can't sign\n");
    return false;
  }
  
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

  int len = digest_output_byte_size("sha-256");
  byte signed_hash[len];
  if (!digest_message("sha-256", (byte*)report.enclave.hash,
        MDSIZE + sizeof(uint64_t)+report.enclave.data_len,
        signed_hash, len)) {
    printf("keystone_Verify: Can't hash final signature\n");
    return false;
  }

  int size_out = SIGNATURE_SIZE;
  if (!keystone_ecc_verify("sha-256", fake_attest_key, len, signed_hash,
        size_out, report.enclave.signature)) {
    printf("keystone_Verify: Can't verify\n");
    return false;
  }

  *measurement_out_size = 32;
  memcpy(measurement_out, report.enclave.hash, *measurement_out_size);

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
