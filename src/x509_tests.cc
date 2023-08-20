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
#include "simulated_enclave.h"
#include "application_enclave.h"

using namespace certifier::framework;
using namespace certifier::utilities;

bool test_x_509_chain(bool print_all) {

  cert_keys_seen_list list(20);

  // Make up three level cert chain
  key_message k1;
  if (!make_certifier_rsa_key(4096, &k1)) {
    return false;
  }
  k1.set_key_name("ark-key");
  k1.set_key_format("vse-key");
  key_message pub_k1;
  if (!private_key_to_public_key(k1, &pub_k1)) {
    return false;
  }
  key_message k2;
  if (!make_certifier_rsa_key(4096, &k2)) {
    return false;
  }
  k2.set_key_name("ask-key");
  k2.set_key_format("vse-key");
  key_message pub_k2;
  if (!private_key_to_public_key(k2, &pub_k2)) {
    return false;
  }
  key_message k3;
  if (!make_certifier_rsa_key(4096, &k3)) {
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

  X509 *cert1 = X509_new();
  if (!produce_artifact(k1,
                        ark_str,
                        ark_desc_str,
                        pub_k1,
                        ark_str,
                        ark_desc_str,
                        1L,
                        150000.0,
                        cert1,
                        true)) {
    return false;
  }
  if (print_all) {
    printf("\nFirst cert:\n");
    X509_print_fp(stdout, cert1);
    printf("\n");
  }

  X509 *cert2 = X509_new();
  if (!produce_artifact(k1,
                        ark_str,
                        ark_desc_str,
                        pub_k2,
                        ask_str,
                        ask_desc_str,
                        1L,
                        150000.0,
                        cert2,
                        false)) {
    return false;
  }
  if (print_all) {
    printf("\nSecond cert:\n");
    X509_print_fp(stdout, cert2);
    printf("\n");
  }

  X509 *cert3 = X509_new();
  if (!produce_artifact(k2,
                        ask_str,
                        ask_desc_str,
                        pub_k3,
                        vcek_str,
                        vcek_desc_str,
                        1L,
                        150000.0,
                        cert3,
                        false)) {
    return false;
  }
  if (print_all) {
    printf("\nThird cert:\n");
    X509_print_fp(stdout, cert3);
    printf("\n");
  }

  // pub key from first cert
  key_message *pub_subject_key1 = new key_message;
  if (!x509_to_public_key(cert1, pub_subject_key1)) {
    printf("Can't get public key from cert 1\n");
    return false;
  }

  // issuer name from first cert
  string issuer1(pub_k1.key_name());
  if (!list.add_key_seen(pub_subject_key1)) {
    return false;
  }
  const key_message *issuer1_key = get_issuer_key(cert1, list);
  if (issuer1_key == nullptr) {
    printf("Can't get issuer_key 1\n");
    return false;
  }
  if (print_all) {
    printf("Cert 1 issuer name: %s\n", issuer1_key->key_name().c_str());
  }
  EVP_PKEY *signing_pkey1 = pkey_from_key(*issuer1_key);
  if (signing_pkey1 == nullptr) {
    printf("\nsigning_pkey1 is NULL\n");
    return false;
  }

  time_point t1_before, t1_after;
  // asn1_time_to_tm_time(const ASN1_TIME* s, struct tm *tm_time);
  if (!get_not_before_from_cert(cert1, &t1_before)) {
    printf("get_not_before_from_cert failed\n");
    return false;
  }
  if (!get_not_after_from_cert(cert1, &t1_after)) {
    printf("get_not_after_from_cert failed\n");
    return false;
  }

  if (print_all) {
    printf("Time before: ");
    print_time_point(t1_before);
    printf("\n");
    printf("Time after : ");
    print_time_point(t1_after);
    printf("\n");
  }

  // pub key from second cert
  key_message *pub_subject_key2 = new key_message;
  if (!x509_to_public_key(cert2, pub_subject_key2)) {
    printf("Can't get public key from cert 2\n");
    return false;
  }
  // issuer name from second cert
  string issuer2(pub_k1.key_name());
  if (!list.add_key_seen(pub_subject_key2)) {
    return false;
  }
  const key_message *issuer2_key = get_issuer_key(cert2, list);
  if (issuer2_key == nullptr) {
    printf("Can't get issuer_key 2\n");
    return false;
  }
  if (print_all) {
    printf("Cert 2 issuer name: %s\n", issuer2_key->key_name().c_str());
  }
  EVP_PKEY *signing_pkey2 = pkey_from_key(*issuer2_key);
  if (signing_pkey2 == nullptr) {
    printf("\nsigning_pkey2 is NULL\n");
    return false;
  }

  // pub key from third cert
  key_message *pub_subject_key3 = new key_message;
  if (!x509_to_public_key(cert3, pub_subject_key3)) {
    printf("Can't get public key from cert 3\n");
    return false;
  }
  // issuer name from third cert
  string issuer3(pub_k2.key_name());
  if (!list.add_key_seen(pub_subject_key3)) {
    return false;
  }
  const key_message *issuer3_key = get_issuer_key(cert3, list);
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

  EVP_PKEY *signing_pkey3 = pkey_from_key(*issuer3_key);
  if (signing_pkey3 == nullptr) {
    printf("signing_pkey3 is NULL\n");
    return false;
  }
  int  ret = X509_verify(cert3, signing_pkey3);
  bool success = (ret == 1);
  if (print_all) {
    if (success) {
      printf("X509 verifies\n");
    } else {
      printf("X509 does not verify (%d)\n", ret);
    }
  }

  vse_clause cl;
  if (!construct_vse_attestation_from_cert(*pub_subject_key3,
                                           *issuer3_key,
                                           &cl)) {
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

  string      issuer_common_name("Tester-cert");
  string      issuer_desc("JLM");
  key_message k1;
  if (!make_certifier_rsa_key(4096, &k1)) {
    return false;
  }
  k1.set_key_name(issuer_common_name);
  k1.set_key_format("vse-key");
  key_message pub_k1;
  if (!private_key_to_public_key(k1, &pub_k1)) {
    return false;
  }

  X509 *cert1 = X509_new();
  if (!produce_artifact(k1,
                        issuer_common_name,
                        issuer_desc,
                        pub_k1,
                        issuer_common_name,
                        issuer_desc,
                        1L,
                        150000.0,
                        cert1,
                        true)) {
    return false;
  }
  if (print_all) {
    printf("\nFirst cert:\n");
    X509_print_fp(stdout, cert1);
    printf("\n");
  }

  EVP_PKEY *pkey = pkey_from_key(pub_k1);
  int       ret = X509_verify(cert1, pkey);
  bool      success = (ret == 1);
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

  X509 *cert1 = X509_new();
  if (!asn1_to_x509(ark_der_str, cert1)) {
    return false;
  }

  EVP_PKEY *ark_pkey = X509_get_pubkey(cert1);
  int       ret = X509_verify(cert1, ark_pkey);
  bool      success = (ret == 1);
  if (print_all) {
    if (success) {
      printf("ark cert verifies\n");
    } else {
      printf("ark cert does not verify (%d)\n", ret);
    }
  }
  if (!success)
    return false;

  X509 *cert2 = X509_new();
  if (!asn1_to_x509(ask_der_str, cert2)) {
    return false;
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

bool test_real_sev_certs(bool print_all) {
  string ark_file_str("./test_data/ark.der");
  string ask_file_str("./test_data/ask.der");
  string vcek_file_str("./test_data/vcek.der");

  string ark_der_str;
  string ask_der_str;
  string vcek_der_str;
  if (!read_file_into_string(ark_file_str, &ark_der_str)) {
    printf("Can't read ark file\n");
    return false;
  }
  if (!read_file_into_string(ask_file_str, &ask_der_str)) {
    printf("Can't read ask file\n");
    return false;
  }
  if (!read_file_into_string(vcek_file_str, &vcek_der_str)) {
    printf("Can't read vcek file\n");
    return false;
  }

  X509 *cert1 = X509_new();
  if (!asn1_to_x509(ark_der_str, cert1)) {
    return false;
  }
  if (print_all) {
    printf("\nARK cert:\n");
    X509_print_fp(stdout, cert1);
    printf("\n");
  }

  EVP_PKEY *ark_pkey = X509_get_pubkey(cert1);
  int       ret = X509_verify(cert1, ark_pkey);
  bool      success = (ret == 1);
  if (print_all) {
    if (success) {
      printf("ark cert verifies\n");
    } else {
      printf("ark cert does not verify (%d)\n", ret);
    }
  }
  if (!success)
    return false;

  X509 *cert2 = X509_new();
  if (!asn1_to_x509(ask_der_str, cert2)) {
    return false;
  }
  if (print_all) {
    printf("\nASK cert:\n");
    X509_print_fp(stdout, cert2);
    printf("\n");
  }

  EVP_PKEY *ask_pkey = X509_get_pubkey(cert2);
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

  X509 *cert3 = X509_new();
  if (!asn1_to_x509(vcek_der_str, cert3)) {
    return false;
  }
  if (print_all) {
    printf("\nVCEK cert:\n");
    X509_print_fp(stdout, cert3);
    printf("\n");
  }

  ret = X509_verify(cert3, ask_pkey);
  success = (ret == 1);
  if (print_all) {
    if (success) {
      printf("vcek cert verifies\n");
    } else {
      printf("vcek cert does not verify (%d)\n", ret);
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

  key_message vcek_key;
  if (!x509_to_public_key(cert3, &vcek_key)) {
    printf("Can't convert vcek to key\n");
    return false;
  }

  vse_clause cl;
  if (!construct_vse_attestation_from_cert(vcek_key, ask_key, &cl)) {
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
  X509_free(cert3);

  return true;
}

// Should only run is SEV_SNP is defined
bool test_sev_request(bool print_all) {

  if (print_all) {
    printf("\n\ntest_sev_request\n\n");
  }
  string ark_file_str("./test_data/ark.der");
  string ask_file_str("./test_data/ask.der");
  string vcek_file_str("./test_data/vcek.der");

  string ark_der_str;
  string ask_der_str;
  string vcek_der_str;
  if (!read_file_into_string(ark_file_str, &ark_der_str)) {
    printf("Can't read ark file\n");
    return false;
  }
  if (!read_file_into_string(ask_file_str, &ask_der_str)) {
    printf("Can't read ask file\n");
    return false;
  }
  if (!read_file_into_string(vcek_file_str, &vcek_der_str)) {
    printf("Can't read vcek file\n");
    return false;
  }

  X509 *cert1 = X509_new();
  if (!asn1_to_x509(ark_der_str, cert1)) {
    return false;
  }

  EVP_PKEY *ark_pkey = X509_get_pubkey(cert1);
  int       ret = X509_verify(cert1, ark_pkey);
  bool      success = (ret == 1);
  if (print_all) {
    if (success) {
      printf("ark cert verifies\n");
    } else {
      printf("ark cert does not verify (%d)\n", ret);
    }
  }
  if (!success)
    return false;

  X509 *cert2 = X509_new();
  if (!asn1_to_x509(ask_der_str, cert2)) {
    return false;
  }

  EVP_PKEY *ask_pkey = X509_get_pubkey(cert2);
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

  X509 *cert3 = X509_new();
  if (!asn1_to_x509(vcek_der_str, cert3)) {
    return false;
  }

  ret = X509_verify(cert3, ask_pkey);
  success = (ret == 1);
  if (print_all) {
    if (success) {
      printf("vcek cert verifies\n");
    } else {
      printf("vcek cert does not verify (%d)\n", ret);
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

  key_message vcek_key;
  if (!x509_to_public_key(cert3, &vcek_key)) {
    printf("Can't convert vcek to key\n");
    return false;
  }

  vse_clause cl;
  if (!construct_vse_attestation_from_cert(vcek_key, ask_key, &cl)) {
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
  X509_free(cert3);

  string      policy_key_file_str("./test_data/policy_key_file.bin");
  string      serialized_policy_key;
  key_message policy_private_key;
  key_message policy_public_key;
  if (!read_file_into_string(policy_key_file_str, &serialized_policy_key)) {
    printf("Can't read policy file\n");
    return false;
  }

  if (!policy_private_key.ParseFromString(serialized_policy_key)) {
    printf("Can't parse policy key\n");
    return false;
  }

  if (!private_key_to_public_key(policy_private_key, &policy_public_key)) {
    printf("Can't get public policy key\n");
    return false;
  }

  key_message auth_private_key;
  key_message auth_public_key;

  // Cheat
  auth_private_key.CopyFrom(policy_private_key);
  auth_private_key.set_key_name("authKey");
  auth_public_key.CopyFrom(policy_public_key);
  auth_public_key.set_key_name("authKey");

  string evidence_descriptor("sev-evidence");
  string enclave_type("sev-enclave");

  // Build evidence_package:
  //	serialized ark cert
  //	serialized ask cert
  //	serialized vcek cert
  //	"vcek says authKey speaks-for measurement

  evidence_package      evp;
  signed_claim_sequence trusted_measurements;
  signed_claim_sequence trusted_platforms;
  attestation_user_data ud;
  string                serialized_ud;

  evp.set_prover_type("vse-verifier");

  evidence *ev = evp.add_fact_assertion();
  ev->set_evidence_type("cert");
  ev->set_serialized_evidence(ark_der_str);
  ev = evp.add_fact_assertion();
  ev->set_evidence_type("cert");
  ev->set_serialized_evidence(ask_der_str);
  ev = evp.add_fact_assertion();
  ev->set_evidence_type("cert");
  ev->set_serialized_evidence(vcek_der_str);

  if (!make_attestation_user_data(enclave_type, auth_public_key, &ud)) {
    printf("Can't make user data (1)\n");
    return false;
  }
  if (!ud.SerializeToString(&serialized_ud)) {
    printf("Can't serialize user data\n");
    return false;
  }

  int  size_out = 8192;
  byte out[size_out];
  if (!Attest(enclave_type,
              serialized_ud.size(),
              (byte *)serialized_ud.data(),
              &size_out,
              out)) {
    printf("Attest failed\n");
    return false;
  }
  string at_str;
  at_str.assign((char *)out, size_out);
  ev = evp.add_fact_assertion();
  ev->set_evidence_type("sev-attestation");
  ev->set_serialized_evidence(at_str);

  byte m[48];
  for (int i = 0; i < 48; i++)
    m[i] = (i % 8) + 1;
  string measurement_str;
  measurement_str.assign((char *)m, 48);

  // init trusted_measurements
  //	policyKey says measurement is-trusted
  entity_message meas_ent;
  if (!make_measurement_entity(measurement_str, &meas_ent)) {
    printf("make_measurement_entity failed\n");
    return false;
  }
  entity_message policy_ent;
  if (!make_key_entity(policy_public_key, &policy_ent)) {
    printf("make_key_entity failed (1)\n");
    return false;
  }

  entity_message auth_ent;
  if (!make_key_entity(auth_public_key, &auth_ent)) {
    printf("make_key_entity failed (2)\n");
    return false;
  }

  string is_trusted_verb("is-trusted");
  string is_trusted_for_att_verb("is-trusted-for-attestation");
  string says_verb("says");

  // measurement is-trusted
  vse_clause c1;
  if (!make_unary_vse_clause(meas_ent, is_trusted_verb, &c1)) {
    printf("clause 1 failed (2)\n");
    return false;
  }
  // policyKey says measurement is-trusted
  vse_clause c2;
  if (!make_indirect_vse_clause(policy_ent, says_verb, c1, &c2)) {
    printf("clause 2 failed (3)\n");
    return false;
  }

  string     s_nb;
  string     s_na;
  time_point t_nb;
  time_point t_na;
  double     hours_to_add = 365.0 * 24.0;

  if (!time_now(&t_nb))
    return false;
  if (!time_to_string(t_nb, &s_nb))
    return false;
  if (!add_interval_to_time_point(t_nb, hours_to_add, &t_na))
    return false;

  if (!time_to_string(t_nb, &s_nb))
    return false;
  if (!time_to_string(t_na, &s_na))
    return false;

  string tm1_ser_vse;
  if (!c2.SerializeToString(&tm1_ser_vse)) {
    printf("serialize claim failed (1)\n");
    return false;
  }

  string        format("vse-clause");
  string        descriptor;
  claim_message cm1;
  if (!make_claim(tm1_ser_vse.size(),
                  (byte *)tm1_ser_vse.data(),
                  format,
                  descriptor,
                  s_nb,
                  s_na,
                  &cm1)) {
    printf("serialize claim failed (1)\n");
    return false;
  }

  signed_claim_message *scm1 = trusted_measurements.add_claims();
  if (!make_signed_claim(Enc_method_rsa_2048_sha256_pkcs_sign,
                         cm1,
                         policy_private_key,
                         scm1)) {
    printf("sign claim failed (3)\n");
    return false;
  }

  // init trusted_platforms
  //  arkKey is-trusted-for-attestation
  vse_clause     c3;
  entity_message ark_ent;
  if (!make_key_entity(ark_key, &ark_ent)) {
    printf("make_key_entity failed (2)\n");
    return false;
  }
  if (!make_unary_vse_clause(ark_ent, is_trusted_for_att_verb, &c3)) {
    printf("clause 3 failed (3)\n");
    return false;
  }
  //	policyKey says arkKey is-trusted-for-attestation
  vse_clause c4;
  if (!make_indirect_vse_clause(policy_ent, says_verb, c3, &c4)) {
    printf("clause 4 failed (4)\n");
    return false;
  }

  string tm2_ser_vse;
  if (!c4.SerializeToString(&tm2_ser_vse)) {
    printf("serialize claim failed (2)\n");
    return false;
  }
  claim_message cm2;
  if (!make_claim(tm2_ser_vse.size(),
                  (byte *)tm2_ser_vse.data(),
                  format,
                  descriptor,
                  s_nb,
                  s_na,
                  &cm2)) {
    printf("serialize claim failed (3)\n");
    return false;
  }

  signed_claim_message *scm2 = trusted_platforms.add_claims();
  if (!make_signed_claim(Enc_method_rsa_2048_sha256_pkcs_sign,
                         cm2,
                         policy_private_key,
                         scm2)) {
    printf("sign claim failed (4)\n");
    return false;
  }

  if (print_all) {
    printf("\nTrusted measurements\n");
    print_vse_clause(c2);
    printf("\n");
    printf("Trusted platforms\n");
    print_vse_clause(c4);
    printf("\n");
    printf("\nEvidence package\n");
    print_evidence_package(evp);
    printf("\n");
  }

  return true;

  string purpose("authentication");
  if (!validate_evidence(evidence_descriptor,
                         trusted_platforms,
                         trusted_measurements,
                         purpose,
                         evp,
                         policy_public_key)) {
    printf("validate_evidence\n");
    return false;
  }

  return true;
}
