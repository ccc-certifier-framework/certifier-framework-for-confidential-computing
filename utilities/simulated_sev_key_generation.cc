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

#include <gflags/gflags.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include "certifier.h"
#include "support.h"
#include "attestation.h"

using namespace certifier::utilities;

DEFINE_bool(print_all, false, "verbose");
DEFINE_string(ark_der, "sev_ark_cert.der", "ark cert file");
DEFINE_string(ask_der, "sev_ask_cert.der", "ask cert file");
DEFINE_string(vcek_der, "sev_vcek_cert.der", "vcek cert file");
DEFINE_string(vcek_key_file, "ec-secp384r1-pub-key.pem", "vcek key file");

int read_vcek_file(const char *filename, EVP_PKEY **key, bool priv) {
  int       rc = -EXIT_FAILURE;
  EVP_PKEY *pkey;
  FILE *    file = NULL;

  pkey = EVP_PKEY_new();
  file = fopen(filename, "r");
  if (!file) {
    rc = EIO;
    goto out;
  }

  if (priv) {
    if (PEM_read_PrivateKey(file, &pkey, NULL, NULL) == NULL) {
      rc = EIO;
      goto out_close;
    }
  } else {
    if (PEM_read_PUBKEY(file, &pkey, NULL, NULL) == NULL) {
      rc = EIO;
      goto out_close;
    }
  }
  *key = pkey;

  rc = EXIT_SUCCESS;

out_close:
  fclose(file);
out:
  return rc;
}


// This generates an sev attestation signed by the key in key_file
int main(int an, char **av) {
  gflags::ParseCommandLineFlags(&an, &av, true);

  printf("sample_sev_key_generation.exe --ark_der=sev_ark_cert.der "
         "--ask_cert=sev_ask_cert.der --vcek_der=sev_vcek_cert.der "
         "--vcek_key_file=ec-secp384r1-pub-key.pem\n");

  // Generate keys and certs
  string rsa_type(Enc_method_rsa_4096_private);
  string ecc_type(Enc_method_ecc_384_private);
  string ark_name("ARKKey");
  string ask_name("ASKKey");
  string vcek_name("VCEKKey");
  string ark_desc_str("AMD-ark-key");
  string ask_desc_str("AMD-ask-key");
  string vcek_desc_str("AMD-vcek-key");

  // ARK
  key_message ark_vse_key;
  key_message pub_ark_vse_key;
  RSA *       r1 = RSA_new();
  if (!generate_new_rsa_key(4096, r1)) {
    printf("Generate RSA ark key failed\n");
    return 1;
  }
  if (!RSA_to_key(r1, &ark_vse_key)) {
    printf("Generate vse ark key failed\n");
    return 1;
  }
  ark_vse_key.set_key_name(ark_name);
  if (!private_key_to_public_key(ark_vse_key, &pub_ark_vse_key)) {
    printf("private to public ark key failed\n");
    return 1;
  }

  X509 *ark_509 = X509_new();
  if (!produce_artifact(ark_vse_key,
                        ark_name,
                        ark_desc_str,
                        pub_ark_vse_key,
                        ark_name,
                        ark_desc_str,
                        1ULL,
                        86400 * 365.25,
                        ark_509,
                        true)) {
    printf("Generate ark cert failed\n");
    return 1;
  }
  printf("\nARK Cert\n");
  X509_print_fp(stdout, ark_509);
  string ark_der;
  if (!x509_to_asn1(ark_509, &ark_der)) {
    printf("Can't convert ARK to der\n");
    return 1;
  }
  if (!write_file(FLAGS_ark_der, ark_der.size(), (byte *)ark_der.data())) {
    printf("Can't write %s\n", FLAGS_ark_der.c_str());
    return 1;
  }
  RSA_free(r1);

  // ASK
  key_message ask_vse_key;
  key_message pub_ask_vse_key;
  RSA *       r2 = RSA_new();
  if (!generate_new_rsa_key(4096, r2)) {
    printf("Generate RSA ark key failed\n");
    return 1;
  }
  if (!RSA_to_key(r2, &ask_vse_key)) {
    printf("Generate vse ask key failed\n");
    return 1;
  }
  ask_vse_key.set_key_name(ask_name);
  if (!private_key_to_public_key(ask_vse_key, &pub_ask_vse_key)) {
    printf("private to public ask key failed\n");
    return 1;
  }

  X509 *ask_509 = X509_new();
  if (!produce_artifact(ark_vse_key,
                        ark_name,
                        ark_desc_str,
                        pub_ask_vse_key,
                        ask_name,
                        ask_desc_str,
                        1ULL,
                        86400 * 365.25,
                        ask_509,
                        false)) {
    printf("Generate ark cert failed\n");
    return 1;
  }
  printf("\nASK Cert\n");
  X509_print_fp(stdout, ask_509);
  string ask_der;
  if (!x509_to_asn1(ask_509, &ask_der)) {
    printf("Can't convert ASK to der\n");
    return 1;
  }
  if (!write_file(FLAGS_ask_der, ask_der.size(), (byte *)ask_der.data())) {
    printf("Can't write %s\n", FLAGS_ask_der.c_str());
    return 1;
  }
  RSA_free(r2);

  // VCEK
  key_message pub_vcek_vse_key;

  EVP_PKEY *key = NULL;
  int       rc = read_vcek_file(FLAGS_vcek_key_file.c_str(), &key, false);
  if (rc != EXIT_SUCCESS) {
    printf("Can't read vcek public key\n");
    return 1;
  }

  // simulated_sev_key_generation
  EC_KEY *ec = EVP_PKEY_get1_EC_KEY(key);
  if (ec == nullptr) {
    printf("Can't get ecc key\n");
    return 1;
  }
  if (!ECC_to_key(ec, &pub_vcek_vse_key)) {
    printf("Generate vse vcek key failed\n");
    return 1;
  }
  pub_vcek_vse_key.set_key_name(vcek_name);

  X509 *vcek_509 = X509_new();
  if (!produce_artifact(ask_vse_key,
                        ask_name,
                        ask_desc_str,
                        pub_vcek_vse_key,
                        vcek_name,
                        vcek_desc_str,
                        1ULL,
                        86400 * 365.25,
                        vcek_509,
                        false,
                        true)) {
    printf("Generate ark cert failed\n");
    return 1;
  }
  printf("\nVCEK Cert\n");
  X509_print_fp(stdout, vcek_509);
  string vcek_der;
  if (!x509_to_asn1(vcek_509, &vcek_der)) {
    printf("Can't convert ASK to der\n");
    return 1;
  }
  if (!write_file(FLAGS_vcek_der, vcek_der.size(), (byte *)vcek_der.data())) {
    printf("Can't write %s\n", FLAGS_vcek_der.c_str());
    return 1;
  }

  return 0;
}
