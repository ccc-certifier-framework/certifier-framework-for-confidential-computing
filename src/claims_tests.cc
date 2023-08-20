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

using namespace certifier::framework;
using namespace certifier::utilities;

bool test_claims_1(bool print_all) {
  key_message k;
  if (!make_certifier_rsa_key(1024, &k))
    return false;
  key_message k1;
  if (!private_key_to_public_key(k, &k1))
    return false;
  entity_message e1;
  entity_message e2;
  if (!make_key_entity(k1, &e1))
    return false;
  extern string my_measurement;
  if (!make_measurement_entity(my_measurement, &e2))
    return false;
  vse_clause clause1;
  string     s1("is-trusted");
  string     s2("says");
  string     s3("speaks-for");
  if (!make_unary_vse_clause((const entity_message)e1, s1, &clause1))
    return false;
  vse_clause clause2;
  if (!make_indirect_vse_clause((const entity_message)e1,
                                s2,
                                clause1,
                                &clause2))
    return false;
  vse_clause clause3;
  if (!make_simple_vse_clause((const entity_message)e1,
                              s3,
                              (const entity_message)e2,
                              &clause3))
    return false;

  if (print_all) {
    print_vse_clause(clause1);
    printf("\n");
    print_vse_clause(clause2);
    printf("\n");
    print_vse_clause(clause3);
    printf("\n");
  }

  claim_message full_claim;
  string        serialized_claim;
  clause3.SerializeToString(&serialized_claim);
  string f1("vse-clause");
  string d1("basic speaks-for-claim");
  string nb("2021-08-01T05:09:50.000000Z");
  string na("2026-08-01T05:09:50.000000Z");
  if (!make_claim(serialized_claim.size(),
                  (byte *)serialized_claim.data(),
                  f1,
                  d1,
                  nb,
                  na,
                  &full_claim))
    return false;

  if (print_all) {
    printf("\nFull claim:\n");
    print_claim(full_claim);
  }

  claims_sequence seq;
  seq.add_claims();
  if (print_all) {
    printf("Num claims: %d\n", seq.claims_size());
  }
  claim_message *cm = seq.mutable_claims(0);
  cm->CopyFrom(full_claim);
  const claim_message &dm = seq.claims(0);
  if (print_all) {
    printf("\nsequence:\n");
    print_claim(dm);
  }
  return true;
}

bool test_signed_claims(bool print_all) {
  // make up rsa private keys and measurement
  string my_measurement;
  byte   m[32];
  for (int i = 0; i < 32; i++)
    m[i] = i;
  my_measurement.assign((char *)m, 32);

  key_message my_rsa_key;
  if (!make_certifier_rsa_key(2048, &my_rsa_key)) {
    printf("test_signed_claims: make_certifier_rsa_key failed (1)\n");
    return false;
  }
  my_rsa_key.set_key_name("my-rsa-key");
  my_rsa_key.set_key_type(Enc_method_rsa_2048_private);
  my_rsa_key.set_key_format("vse-key");

  key_message my_public_rsa_key;
  if (!private_key_to_public_key(my_rsa_key, &my_public_rsa_key)) {
    printf("test_signed_claims: private_key_to_public_key failed (1)\n");
    return false;
  }
  entity_message e1;
  entity_message e2;
  if (!make_key_entity(my_public_rsa_key, &e1))
    return false;

  if (!make_measurement_entity(my_measurement, &e2))
    return false;
  string     s1("says");
  string     s2("speaks-for");
  string     vse_clause_format("vse-clause");
  vse_clause clause1;
  vse_clause clause2;
  if (!make_simple_vse_clause((const entity_message)e1,
                              s2,
                              (const entity_message)e2,
                              &clause1))
    return false;
  if (!make_indirect_vse_clause((const entity_message)e1,
                                s1,
                                clause1,
                                &clause2))
    return false;

  string serialized_vse1;
  clause2.SerializeToString(&serialized_vse1);

  claim_message claim1;
  time_point    t_nb;
  time_point    t_na;
  time_now(&t_nb);
  add_interval_to_time_point(t_nb, 24.0 * 365.0, &t_na);
  string nb;
  string na;
  time_to_string(t_nb, &nb);
  time_to_string(t_na, &na);
  string n1("description");
  if (!make_claim(serialized_vse1.size(),
                  (byte *)serialized_vse1.data(),
                  vse_clause_format,
                  n1,
                  nb,
                  na,
                  &claim1))
    return false;
  if (print_all) {
    printf("\nClaims for signing:\n");
    print_claim(claim1);
    printf("\n");
  }
  signed_claim_message signed_claim1;
  if (!make_signed_claim(Enc_method_rsa_2048_sha256_pkcs_sign,
                         claim1,
                         my_rsa_key,
                         &signed_claim1))
    return false;
  if (!verify_signed_claim(signed_claim1, my_public_rsa_key)) {
    printf("my_rsa_key verified failed\n");
    return false;
  }

  // RSA-3072
  key_message my_medium_rsa_key;
  if (!make_certifier_rsa_key(3072, &my_medium_rsa_key)) {
    printf("test_signed_claims: make_certifier_rsa_key failed (3072)\n");
    return false;
  }
  my_medium_rsa_key.set_key_name("my-medium-rsa-key");
  my_medium_rsa_key.set_key_type(Enc_method_rsa_3072_private);
  my_medium_rsa_key.set_key_format("vse-key");

  if (print_all) {
    printf("RSA-3072 key: \n");
    print_key(my_medium_rsa_key);
    printf("\n");
  }

  key_message my_medium_public_rsa_key;
  if (!private_key_to_public_key(my_medium_rsa_key,
                                 &my_medium_public_rsa_key)) {
    printf("test_signed_claims: private_key_to_public_key failed (2)\n");
    return false;
  }
  entity_message e13;
  if (!make_key_entity(my_medium_public_rsa_key, &e13)) {
    printf("test_signed_claims: make_entity 13 failed\n");
    return false;
  }
  vse_clause clause13;
  vse_clause clause14;
  if (!make_simple_vse_clause((const entity_message)e13,
                              s2,
                              (const entity_message)e2,
                              &clause13)) {
    return false;
  }
  if (!make_indirect_vse_clause((const entity_message)e13,
                                s1,
                                clause13,
                                &clause14)) {
    printf("test_signed_claims: make clause 13 failed\n");
    return false;
  }

  claim_message        claim12;
  signed_claim_message signed_claim12;
  string               serialized_vse12;
  clause14.SerializeToString(&serialized_vse12);
  if (!make_claim(serialized_vse12.size(),
                  (byte *)serialized_vse12.data(),
                  vse_clause_format,
                  n1,
                  nb,
                  na,
                  &claim12)) {
    printf("test_signed_claims: make clause 12 failed\n");
    return false;
  }
  if (print_all) {
    printf("\nClaims for signing:\n");
    print_claim(claim12);
    printf("\n");
  }
  if (!make_signed_claim(Enc_method_rsa_3072_sha384_pkcs_sign,
                         claim12,
                         my_medium_rsa_key,
                         &signed_claim12)) {
    printf("test_signed_claims: make_signed_claim failed (3072)\n");
    return false;
  }
  if (!verify_signed_claim(signed_claim12, my_medium_public_rsa_key)) {
    printf("my_medium_rsa_key verified failed\n");
    return false;
  }

  // RSA-4096
  key_message my_big_rsa_key;
  if (!make_certifier_rsa_key(4096, &my_big_rsa_key)) {
    printf("test_signed_claims: make_certifier_rsa_key failed (1)\n");
    return false;
  }
  my_big_rsa_key.set_key_name("my-big-rsa-key");
  my_big_rsa_key.set_key_type(Enc_method_rsa_4096_private);
  my_big_rsa_key.set_key_format("vse-key");

  if (print_all) {
    printf("RSA-4096 key: \n");
    print_key(my_big_rsa_key);
    printf("\n");
  }

  key_message my_big_public_rsa_key;
  if (!private_key_to_public_key(my_big_rsa_key, &my_big_public_rsa_key)) {
    printf("test_signed_claims: private_key_to_public_key failed (2)\n");
    return false;
  }
  entity_message e3;
  if (!make_key_entity(my_big_public_rsa_key, &e3))
    return false;
  vse_clause clause3;
  vse_clause clause4;
  if (!make_simple_vse_clause((const entity_message)e3,
                              s2,
                              (const entity_message)e2,
                              &clause3))
    return false;
  if (!make_indirect_vse_clause((const entity_message)e3,
                                s1,
                                clause3,
                                &clause4))
    return false;

  claim_message        claim2;
  signed_claim_message signed_claim2;
  string               serialized_vse2;
  clause4.SerializeToString(&serialized_vse2);
  if (!make_claim(serialized_vse2.size(),
                  (byte *)serialized_vse2.data(),
                  vse_clause_format,
                  n1,
                  nb,
                  na,
                  &claim2))
    return false;
  if (print_all) {
    printf("\nClaims for signing:\n");
    print_claim(claim2);
    printf("\n");
  }
  if (!make_signed_claim(Enc_method_rsa_4096_sha384_pkcs_sign,
                         claim2,
                         my_big_rsa_key,
                         &signed_claim2)) {
    printf("test_signed_claims: make_signed_claim failed (2)\n");
    return false;
  }
  if (!verify_signed_claim(signed_claim2, my_big_public_rsa_key)) {
    printf("my_big_rsa_key verified failed\n");
    return false;
  }

  // ECC-384
  key_message my_ecc_key;
  key_message my_ecc_public_key;
  if (!make_certifier_ecc_key(384, &my_ecc_key)) {
    printf("test_signed_claims: make_certifier_ecc_key failed (1)\n");
    return false;
  }
  my_ecc_key.set_key_name("my-ecc-key");
  my_ecc_key.set_key_type(Enc_method_ecc_384_private);
  my_ecc_key.set_key_format("vse-key");

  if (print_all) {
    printf("ECC-384 key: \n");
    print_key(my_ecc_key);
    printf("\n");
  }
  if (!private_key_to_public_key(my_ecc_key, &my_ecc_public_key)) {
    printf("test_signed_claims: private_key_to_public_key failed (2)\n");
    return false;
  }
  entity_message e5;
  if (!make_key_entity(my_ecc_public_key, &e5))
    return false;
  vse_clause clause5;
  vse_clause clause6;
  if (!make_simple_vse_clause((const entity_message)e5,
                              s2,
                              (const entity_message)e2,
                              &clause5))
    return false;
  if (!make_indirect_vse_clause((const entity_message)e5,
                                s1,
                                clause5,
                                &clause6))
    return false;

  claim_message claim3;
  string        serialized_vse3;
  clause6.SerializeToString(&serialized_vse3);
  if (!make_claim(serialized_vse3.size(),
                  (byte *)serialized_vse3.data(),
                  vse_clause_format,
                  n1,
                  nb,
                  na,
                  &claim3))
    return false;
  if (print_all) {
    printf("\nClaims for signing:\n");
    print_claim(claim3);
    printf("\n");
  }

  signed_claim_message signed_claim3;
  if (!make_signed_claim(Enc_method_ecc_384_sha384_pkcs_sign,
                         claim3,
                         my_ecc_key,
                         &signed_claim3)) {
    printf("test_signed_claims: make_signed_claim failed (3)\n");
    return false;
  }
  if (!verify_signed_claim(signed_claim3, my_ecc_public_key)) {
    printf("my_ecc_key verified failed\n");
    return false;
  }

  return true;
}

//  Proofs and certification -----------------------------

// test_support.cc has test code that can be used in an enclave
//    without gtest
#include "test_support.cc"

bool test_certify_steps(bool print_all) {
  return true;
}

bool test_full_certification(bool print_all) {
  return true;
}

// policy-key says intel-key is-trusted-for-attestation
// intel-key says attestation-key is-trusted-for-attestation
// attestation-key says authentication-key speaks-for measurement
// policy-key says measurement is-trusted-for-authentication
// authentication-key is-trusted-for-authentication

const int   num_is_trusted_kids = 2;
const char *kids[2] = {
    "is-trusted-for-attestation",
    "is-trusted-for-authentication",
};

bool init_top_level_is_trusted(predicate_dominance &root) {
  root.predicate_.assign("is-trusted");

  string descendant;
  for (int i = 0; i < num_is_trusted_kids; i++) {
    descendant.assign(kids[i]);
    if (!root.insert(root.predicate_, descendant))
      return false;
  }
  return true;
}

bool test_predicate_dominance(bool print_all) {
  predicate_dominance root;

  if (!init_top_level_is_trusted(root)) {
    return false;
  }

  if (print_all) {
    root.print_tree(0);
  }

  string it("is-trusted");
  string it1("is-trusted-for-attestation");
  string it2("is-trusted-for-authentication");
  string it3("is-trusted-for-crap");

  if (!dominates(root, it, it1))
    return false;
  if (!dominates(root, it, it2))
    return false;
  if (dominates(root, it, it3))
    return false;

  return true;
}
