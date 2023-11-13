//  Copyright (c) 2021-22, VMware Inc, and the Regents of the University of
//  California.
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

#include <string.h>
#include "keystone_api.h"
#include "certifier_framework.h"
#include "certifier_utilities.h"

using std::string;
using namespace certifier::utilities;

bool keystone_getSealingKey(byte *key) {
  for (int i = 0; i < 64; i++)
    key[i] = i ^ 0x33;
  return true;
}

bool      g_m_initialized = false;
const int g_m_size = 32;
byte      g_measurement[g_m_size];

// Keep name consistent with what is being used by other apps.
// This simplifies the logic in driver run_example.sh script.
string g_measurement_file_name("./provisioning/example_app.measurement");

bool keystone_get_fake_measurement(int *size, byte *measurement) {

  if (!g_m_initialized) {
    int    n = file_size(g_measurement_file_name);
    string str_measurement;
    if (n > 0
        && read_file_into_string(g_measurement_file_name, &str_measurement)) {
      byte *p = (byte *)str_measurement.data();
      for (int i = 0; i < g_m_size; i++)
        g_measurement[i] = p[i];
    } else {
      for (int i = 0; i < g_m_size; i++)
        g_measurement[i] = i;
    }
    g_m_initialized = true;
  }

  for (int i = 0; i < g_m_size; i++)
    measurement[i] = g_measurement[i];
  *size = g_m_size;

  return true;
}

bool keystone_ecc_sign(const char *alg,
                       EC_KEY *    key,
                       int         size,
                       byte *      msg,
                       int *       size_out,
                       byte *      out) {
  unsigned int len = (unsigned int)digest_output_byte_size(alg);
  byte         digest[len];

  int blk_len = ECDSA_size(key);
  if (*size_out < 2 * blk_len) {
    printf("keystone_ecc_sign: size_out too small %d %d\n", *size_out, blk_len);
    return false;
  }

  if (!digest_message(alg, msg, size, digest, len)) {
    printf("keystone_ecc_sign: digest fails\n");
    return false;
  }

#if 1
  printf("Hash to sign: ");
  print_bytes(len, digest);
  printf("\n");
#endif

  unsigned int sz = (unsigned int)*size_out;
  if (ECDSA_sign(0, digest, len, out, &sz, key) != 1) {
    printf("keystone_ecc_sign: ECDSA_sign fails\n");
    return false;
  }
  *size_out = (int)sz;
  return true;
}

bool keystone_ecc_verify(const char *alg,
                         EC_KEY *    key,
                         int         size,
                         byte *      msg,
                         int         size_sig,
                         byte *      sig) {
  unsigned int len = (unsigned int)digest_output_byte_size(alg);
  byte         digest[len];

  if (!digest_message(alg, msg, size, digest, len)) {
    printf("ecc_verify: %s digest failed %d\n", alg, len);
    return false;
  }

#if 1
  printf("Hash to verify: ");
  print_bytes(len, digest);
  printf("\n");
#endif

  int res = ECDSA_verify(0, digest, len, sig, size_sig, key);
  if (res != 1) {
    printf("ecc_verify: ECDSA_failed %d %d\n", len, size_sig);
    return false;
  }

  return true;
}

string      key_file("emulated_keystone_key.bin");
string      cert_file("emulated_keystone_key_cert.bin");
EC_KEY *    fake_attest_private_key = nullptr;
EC_KEY *    fake_attest_public_key = nullptr;
key_message attest_private_key;
key_message attest_public_key;

bool keystone_Init(const int cert_size, byte *cert) {
  // later, we should read in the key and cert chain
  int size_key = file_size(key_file);
  int size_cert = file_size(cert_file);

  if (size_key <= 0 || size_cert <= 0) {
    fake_attest_private_key = generate_new_ecc_key(256);
    if (fake_attest_private_key == nullptr) {
      printf("keystone_Init: can't init Ecc key\n");
      return false;
    }

    if (!ECC_to_key(fake_attest_private_key, &attest_private_key)) {
      printf("keystone_Init: can't init attest private key\n");
      return false;
    }
    attest_private_key.set_key_name("keystone-simulated-attest-key");
    if (!private_key_to_public_key(attest_private_key, &attest_public_key)) {
      printf("keystone_Init: can't convert attest private key\n");
      return false;
    }
    fake_attest_public_key = key_to_ECC(attest_public_key);
    if (fake_attest_public_key == nullptr) {
      printf("keystone_Init: can't init attest public key\n");
      return false;
    }

    string key_str;
    if (!attest_private_key.SerializeToString(&key_str)) {
      return false;
    }
    if (!write_file(key_file, key_str.size(), (byte *)key_str.data())) {
      return false;
    }

    // generate self signed cert
    string name("KeystoneAuthority");
    string desc("Authority");
    X509 * crt = X509_new();
    if (!produce_artifact(attest_private_key,
                          name,
                          desc,
                          attest_public_key,
                          name,
                          desc,
                          94720,
                          86400 * 365.26,
                          crt,
                          true)) {
      X509_free(crt);
      return false;
    }

    string cert_str;
    if (!x509_to_asn1(crt, &cert_str)) {
      printf("keystone_Init: Cant save key\n");
      X509_free(crt);
      return false;
    }
    X509_free(crt);
    if (!write_file(cert_file, cert_str.size(), (byte *)cert_str.data())) {
      printf("keystone_Init: Cant save cert\n");
      return false;
    }

  } else {
    string key_str;
    string cert_str;
    if (!read_file_into_string(key_file, &key_str)) {
      printf("keystone_Init: Cant read key\n");
      return false;
    }
    if (!read_file_into_string(cert_file, &cert_str)) {
      printf("keystone_Init: Cant read cert\n");
      return false;
    }

    if (!attest_private_key.ParseFromString(key_str)) {
      printf("keystone_Init: Cant deserialize cert\n");
      return false;
    }
    if (!private_key_to_public_key(attest_private_key, &attest_public_key)) {
      printf("keystone_Init: Cant make public attest key\n");
      return false;
    }
    fake_attest_private_key = key_to_ECC(attest_private_key);
    fake_attest_public_key = key_to_ECC(attest_public_key);
    if (fake_attest_private_key == nullptr
        || fake_attest_public_key == nullptr) {
      printf("keystone_Init: Cant convert attest key\n");
      return false;
    }
  }

  return true;
}

bool keystone_Verify(const int what_to_say_size,
                     byte *    what_to_say,
                     const int attestation_size,
                     byte *    attestation,
                     int *     measurement_out_size,
                     byte *    measurement_out) {
  assert(attestation_size == sizeof(struct report_t));
  struct report_t &report = *reinterpret_cast<struct report_t *>(attestation);

#if 1
  printf("verifying: ");
  print_bytes(MDSIZE + sizeof(uint64_t) + report.enclave.data_len,
              (byte *)report.enclave.hash);
  printf("\n");
  printf("signature: ");
  print_bytes(report.enclave.size_sig, report.enclave.signature);
  printf("\n");
#endif

  // report.enclave.data should be hash of what_to_say
  int  len = digest_output_byte_size(Digest_method_sha_256);
  byte expected_data[len];
  if (!digest_message(Digest_method_sha_256,
                      what_to_say,
                      what_to_say_size,
                      expected_data,
                      len)) {
    printf("keystone_Verify: Can't digest what_to_say\n");
    return false;
  }
  if ((int)report.enclave.data_len != len
      || memcmp(expected_data, report.enclave.data, len) != 0) {
    printf("keystone_Verify: reported data is not hash of what_to_say\n");
    return false;
  }

  if (!keystone_ecc_verify(Digest_method_sha_256,
                           fake_attest_public_key,
                           MDSIZE + sizeof(uint64_t) + report.enclave.data_len,
                           (byte *)report.enclave.hash,
                           report.enclave.size_sig,
                           report.enclave.signature)) {
    printf("keystone_Verify: Can't verify\n");
    return false;
  }

  *measurement_out_size = 32;
  memcpy(measurement_out, report.enclave.hash, *measurement_out_size);

  return true;
}

bool keystone_Attest(const int what_to_say_size,
                     byte *    what_to_say,
                     int *     attestation_size_out,
                     byte *    attestation_out) {

  int sz = (int)(sizeof(struct enclave_report_t) + sizeof(struct sm_report_t)
                 + PUBLIC_KEY_SIZE);
  *attestation_size_out = sz;

  memset(attestation_out, 0, sizeof(report_t));
  struct report_t &report =
      *reinterpret_cast<struct report_t *>(attestation_out);

  // report.enclave.data gets the hash of what_to_say
  int len = digest_output_byte_size(Digest_method_sha_256);
  if (!digest_message(Digest_method_sha_256,
                      what_to_say,
                      what_to_say_size,
                      report.enclave.data,
                      len)) {
    printf("keystone_Attest: Can't digest what_to_say\n");
    return false;
  }
  report.enclave.data_len = len;

  // report.enclave.hash is measurement or its hash
  int measurement_size = MDSIZE;
  if (!keystone_get_fake_measurement(&measurement_size, report.enclave.hash)) {
    printf("keystone_Attest: Can't get measurement\n");
    return false;
  }

  // Put the signing public key in report.sm.public_key eventually, leave
  // signature 0'd for now. Put the signing public key in
  // report.enclave.dev_public_key, eventually.

  // Hash report.enclave.hash, report.enclave.datalen and report.enclave.data
  // and sign that hash.
  //

  int size_out = SIGNATURE_SIZE;
  if (!keystone_ecc_sign(Digest_method_sha_256,
                         fake_attest_private_key,
                         MDSIZE + sizeof(uint64_t) + report.enclave.data_len,
                         (byte *)report.enclave.hash,
                         &size_out,
                         report.enclave.signature)) {
    printf("keystone_Attest: Can't sign\n");
    return false;
  }
  report.enclave.size_sig = size_out;

#if 1
  printf("signing: ");
  print_bytes(MDSIZE, (byte *)report.enclave.hash);
  printf("\n");
  printf("signature: ");
  print_bytes(report.enclave.size_sig, report.enclave.signature);
  printf("\n");
#endif

#if 0
  // Cross check
  int size_measurement_test = 64;
  byte measurement_test[size_measurement_test];
  
  if (keystone_Verify(what_to_say_size, what_to_say, *attestation_size_out,
      attestation_out, &size_measurement_test, measurement_test)) {
    printf("keystone_Attest: attest verifies\n");
  } else {
    printf("keystone_Attest: attest does not verify\n");
  }
#endif
  return true;
}

bool keystone_Seal(int in_size, byte *in, int *size_out, byte *out) {
  byte iv[16];
  byte key[64];

  memset(iv, 0, 16);
  if (!get_random(128, iv)) {
    return false;
  }
  if (!keystone_getSealingKey(key)) {
    return false;
  }

  if (!authenticated_encrypt(Enc_method_aes_256_cbc_hmac_sha256,
                             in,
                             in_size,
                             key,
                             64,
                             iv,
                             16,
                             out,
                             size_out)) {
    return false;
  }
  return true;
}

bool keystone_Unseal(int in_size, byte *in, int *size_out, byte *out) {
  byte iv[16];
  byte key[64];

  if (!keystone_getSealingKey(key)) {
    return false;
  }

  if (!authenticated_decrypt(Enc_method_aes_256_cbc_hmac_sha256,
                             in,
                             in_size,
                             key,
                             64,
                             out,
                             size_out)) {
    return false;
  }
  return true;
}
