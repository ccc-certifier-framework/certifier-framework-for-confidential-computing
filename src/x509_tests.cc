#include "certifier.h"
#include "support.h"
#include "simulated_enclave.h"
#include "application_enclave.h"

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


bool test_x_509_chain(bool print_all) {

  cert_keys_seen_list list(20);

  // Make up three level cert chain
  key_message k1;
  if (!make_certifier_rsa_key(4096,  &k1)) {
    return false;
  }
  k1.set_key_name("ark-key");
  k1.set_key_format("vse-key");
  key_message pub_k1;
  if (!private_key_to_public_key(k1, &pub_k1)) {
    return false;
  }
  key_message k2;
  if (!make_certifier_rsa_key(4096,  &k2)) {
    return false;
  }
  k2.set_key_name("ask-key");
  k2.set_key_format("vse-key");
  key_message pub_k2;
  if (!private_key_to_public_key(k2, &pub_k2)) {
    return false;
  }
  key_message k3;
  if (!make_certifier_rsa_key(4096,  &k3)) {
    return false;
  }
  k3.set_key_name("vcek-key");
  k3.set_key_format("vse-key");
  key_message pub_k3;
  if (!private_key_to_public_key(k3, &pub_k3)) {
    return false;
  }

  if (print_all) {
    printf("\nark-key\n");
    print_key(k1);
    printf("\n");
    printf("\nask-key\n");
    print_key(k2);
    printf("\n");
    printf("\nvcek-key\n");
    print_key(k3);
    printf("\n");
  }

  string ark_str("ark-key");
  string ark_desc_str("AMD-ark-key");
  string ask_str("ask-key");
  string ask_desc_str("AMD-ask-key");
  string vcek_str("vcek-key");
  string vcek_desc_str("AMD-vcek-key");

  X509* cert1 =X509_new();
  if (!produce_artifact(k1, ark_str, ark_desc_str, pub_k1,
            ark_str, ark_desc_str, 1L, 150000.0, cert1, true)) {
    return false;
  }
  if (print_all) {
    printf("\nFirst cert:\n");
    X509_print_fp(stdout, cert1);
    printf("\n");
  }

  X509* cert2 =X509_new();
  if (!produce_artifact(k1, ark_str, ark_desc_str, pub_k2,
            ask_str, ask_desc_str, 1L, 150000.0, cert2, false)) {
    return false;
  }
  if (print_all) {
    printf("\nSecond cert:\n");
    X509_print_fp(stdout, cert2);
    printf("\n");
  }

  X509* cert3 =X509_new();
  if (!produce_artifact(k2, ask_str, ask_desc_str, pub_k3,
            vcek_str, vcek_desc_str, 1L, 150000.0, cert3, false)) {
    return false;
  }
  if (print_all) {
    printf("\nThird cert:\n");
    X509_print_fp(stdout, cert3);
    printf("\n");
  }

  // pub key from first cert
  key_message* pub_subject_key1 = new key_message;
  if (!x509_to_public_key(cert1, pub_subject_key1)) {
    printf("Can't get public key from cert 1\n");
    return false;
  }

  // issuer name from first cert
  string issuer1(pub_k1.key_name());
  if (!list.add_key_seen(pub_subject_key1)) {
    return false;
  }
  const key_message* issuer1_key = get_issuer_key(cert1, list);
  if (issuer1_key == nullptr) {
    printf("Can't get issuer_key 1\n");
    return false;
  }
  if (print_all) {
    printf("Cert 1 issuer name: %s\n", issuer1_key->key_name().c_str());
  }
  EVP_PKEY* signing_pkey1 = pkey_from_key(*issuer1_key);
  if (signing_pkey1 == nullptr) {
    printf("\nsigning_pkey1 is NULL\n");
    return false;
  }

  // pub key from second cert
  key_message* pub_subject_key2 = new key_message;
  if (!x509_to_public_key(cert2, pub_subject_key2)) {
    printf("Can't get public key from cert 2\n");
    return false;
  }
  // issuer name from second cert
  string issuer2(pub_k1.key_name());
  if (!list.add_key_seen(pub_subject_key2)) {
    return false;
  }
  const key_message* issuer2_key = get_issuer_key(cert2, list);
  if (issuer2_key == nullptr) {
    printf("Can't get issuer_key 2\n");
    return false;
  }
  if (print_all) {
    printf("Cert 2 issuer name: %s\n", issuer2_key->key_name().c_str());
  }
  EVP_PKEY* signing_pkey2 = pkey_from_key(*issuer2_key);
  if (signing_pkey2 == nullptr) {
    printf("\nsigning_pkey2 is NULL\n");
    return false;
  }

  // pub key from third cert
  key_message* pub_subject_key3 = new key_message;
  if (!x509_to_public_key(cert3, pub_subject_key3)) {
    printf("Can't get public key from cert 3\n");
    return false;
  }
  // issuer name from third cert
  string issuer3(pub_k2.key_name());
  if (!list.add_key_seen(pub_subject_key3)) {
    return false;
  }
  const key_message* issuer3_key = get_issuer_key(cert3, list);
  if (issuer3_key == nullptr) {
    printf("Can't get issuer_key 3\n");
    return false;
  }
  if (print_all) {
    printf("Cert 3 issuer name: %s\n", issuer3_key->key_name().c_str());
  }
  if (print_all) {
    printf("\nSigning key:\n");
    print_key(*issuer3_key);
    printf("\n");
  }

  EVP_PKEY* signing_pkey3 = pkey_from_key(*issuer3_key);
  if (signing_pkey3 == nullptr) {
    printf("signing_pkey3 is NULL\n");
    return false;
  }
  int ret = X509_verify(cert3, signing_pkey3);
  bool success = (ret == 1);
  if (print_all) {
    if (success) {
      printf("X509 verifies\n");
    } else {
      printf("X509 does not verify (%d)\n", ret);
    }
  }

  vse_clause cl;
  if (!construct_vse_attestation_from_cert(*pub_subject_key3, *issuer3_key, &cl)) {
      printf("Can't construct vse attestation from cert\n");
      return false;
   }

  if (print_all) {
    printf("Statement: \n");
    print_vse_clause(cl);
    printf("\n");
  }

  X509_free(cert1);
  X509_free(cert2);
  X509_free(cert3);
  return success;
}

bool test_x_509_sign(bool print_all) {

  string issuer_common_name("Tester-cert");
  string issuer_desc("JLM");
  key_message k1;
  if (!make_certifier_rsa_key(4096,  &k1)) {
    return false;
  }
  k1.set_key_name(issuer_common_name);
  k1.set_key_format("vse-key");
  key_message pub_k1;
  if (!private_key_to_public_key(k1, &pub_k1)) {
    return false;
  }

  X509* cert1 =X509_new();
  if (!produce_artifact(k1, issuer_common_name, issuer_desc, pub_k1,
         issuer_common_name, issuer_desc, 1L, 150000.0, cert1, true)) {
    return false;
  }
  if (print_all) {
    printf("\nFirst cert:\n");
    X509_print_fp(stdout, cert1);
    printf("\n");
  }

  if (print_all) {
    printf("\nCert:\n");
    X509_print_fp(stdout, cert1);
    printf("\n");
  }
  EVP_PKEY* pkey = pkey_from_key(pub_k1);
  int ret = X509_verify(cert1, pkey);
  bool success = (ret == 1);
  if (print_all) {
    if (success) {
      printf("X509 (2) verifies\n");
    } else {
      printf("X509 (2) does not verify (%d)\n", ret);
    }
  }
  X509_free(cert1);
  return success;
}

bool test_sev_certs(bool print_all) {
  string ark_file_str("./test_data/milan_ark_cert.der");
  string ask_file_str("./test_data/milan_ask_cert.der");

  string ark_der_str;
  string ask_der_str;
  if (!read_file_into_string(ark_file_str, &ark_der_str)) {
    printf("Can't read ark file\n");
    return false;
  }
  if (!read_file_into_string(ask_file_str, &ask_der_str)) {
    printf("Can't read ask file\n");
    return false;
  }

  X509* cert1 =X509_new();
  if (!asn1_to_x509(ark_der_str, cert1)) {
    return false;
  }
  if (print_all) {
    printf("\nARK cert:\n");
    X509_print_fp(stdout, cert1);
    printf("\n");
  }

  EVP_PKEY* ark_pkey = X509_get_pubkey(cert1);
  int ret = X509_verify(cert1, ark_pkey);
  bool success = (ret == 1);
  if (print_all) {
    if (success) {
      printf("ark cert verifies\n");
    } else {
      printf("ark cert does not verify (%d)\n", ret);
    }
  }
  if (!success)
    return false;

  X509* cert2 =X509_new();
  if (!asn1_to_x509(ask_der_str, cert2)) {
    return false;
  }
  if (print_all) {
    printf("\nASK cert:\n");
    X509_print_fp(stdout, cert2);
    printf("\n");
  }

  ret = X509_verify(cert2, ark_pkey);
  success = (ret == 1);
  if (print_all) {
    if (success) {
      printf("ask cert verifies\n");
    } else {
      printf("ask cert does not verify (%d)\n", ret);
    }
  }
  if (!success)
    return false;

  key_message ark_key;
  if (!x509_to_public_key(cert1, &ark_key)) {
    printf("Can't convert ark to key\n");
    return false;
  }

  key_message ask_key;
  if (!x509_to_public_key(cert2, &ask_key)) {
    printf("Can't convert ark to key\n");
    return false;
  }

  vse_clause cl;
  if (!construct_vse_attestation_from_cert(ask_key, ark_key, &cl)) {
    printf("construct_vse_attestation_from_cert failed\n");
    return false;
  }

  printf("\n");
  if (print_all) {
    print_vse_clause(cl);
    printf("\n");
  }

  X509_free(cert1);
  X509_free(cert2);

  return true;
}
