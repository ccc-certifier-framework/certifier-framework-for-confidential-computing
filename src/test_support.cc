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
#ifdef SEV_SNP
#  include "sev-snp/attestation.h"
#endif

using namespace certifier::framework;
using namespace certifier::utilities;

bool debug_print = false;

bool read_trusted_binary_measurements_and_sign(string &     file_name,
                                               key_message &policy_key,
                                               signed_claim_sequence *list) {

  int size = file_size(file_name);
  if (size < 0) {
    return false;
  }
  byte file_contents[size];

  if (!read_file(file_name, &size, file_contents)) {
    printf("Can't read %s\n", file_name.c_str());
    return false;
  }

  key_message policy_pk;
  if (!private_key_to_public_key(policy_key, &policy_pk))
    return false;
  entity_message policy_key_entity;
  if (!make_key_entity(policy_pk, &policy_key_entity)) {
    return false;
  }

  time_point t_nb;
  time_point t_na;
  time_now(&t_nb);
  add_interval_to_time_point(t_nb, 24.0 * 365.0, &t_na);
  string nb;
  string na;
  time_to_string(t_nb, &nb);
  time_to_string(t_na, &na);

  string says_verb("says");
  string it_verb("is-trusted");

  const int measurement_size = 32;
  int       current = 0;
  int       left = size;
  while (left >= measurement_size) {
    string measurement;
    measurement.assign((char *)&file_contents[current], measurement_size);
    entity_message measurement_entity;
    if (!make_measurement_entity(measurement, &measurement_entity)) {
      return false;
    }

    vse_clause c1;
    vse_clause c2;

    if (!make_unary_vse_clause(measurement_entity, it_verb, &c1))
      return false;

    if (!make_indirect_vse_clause(policy_key_entity, says_verb, c1, &c2))
      return false;

    string serialized_vse;
    if (!c2.SerializeToString(&serialized_vse))
      return false;

    // policy_key says measurement is-trusted
    claim_message claim;
    string        n1("description");
    string        vse_clause_format("vse-clause");
    if (!make_claim(serialized_vse.size(),
                    (byte *)serialized_vse.data(),
                    vse_clause_format,
                    n1,
                    nb,
                    na,
                    &claim))
      return false;
    signed_claim_message sc;
    if (!make_signed_claim(Enc_method_rsa_2048_sha256_pkcs_sign,
                           claim,
                           policy_key,
                           &sc))
      return false;

    signed_claim_message *scm = list->add_claims();
    scm->CopyFrom(sc);

    left -= measurement_size;
    current += measurement_size;
  }

  return true;
}

bool construct_keys(string       key_name,
                    string       format,
                    key_message *public_key,
                    key_message *private_key) {

  if (!make_certifier_rsa_key(2048, private_key))
    return false;
  private_key->set_key_name(key_name);
  private_key->set_key_format(format);

  if (!private_key_to_public_key(*private_key, public_key))
    return false;
  return true;
}

bool construct_standard_evidence_package(
    string &               enclave_type,
    bool                   init_measurements,
    string &               file_name,
    string &               evidence_descriptor,
    signed_claim_sequence *trusted_platforms,
    signed_claim_sequence *trusted_measurements,
    key_message *          policy_key,
    key_message *          policy_pk,
    evidence_package *     evp) {

  string policy_key_name("policy-key");
  string key_format("vse-key");
  if (!construct_keys(policy_key_name, key_format, policy_pk, policy_key))
    return false;

  string enclave_id("test-enclave");

  if (debug_print) {
    printf("\nPolicy key: ");
    print_key(*policy_key);
    printf("\n");
  }

  // Construct measurement
  string meas;
  if (init_measurements) {
    if (!read_trusted_binary_measurements_and_sign(file_name,
                                                   *policy_key,
                                                   trusted_measurements))
      return false;

    if (debug_print) {
      printf("\nMeasurements read\n");
      for (int i = 0; i < trusted_measurements->claims_size(); i++) {
        print_signed_claim(trusted_measurements->claims(i));
        printf("\n");
      }
    }
    // measurement should be the only measurement in trusted measurements
    vse_clause c;
    if (!get_vse_clause_from_signed_claim(trusted_measurements->claims(0), &c))
      return false;
    meas.assign((char *)c.clause().subject().measurement().data(),
                c.clause().subject().measurement().size());
  } else {
    byte m[32];
    for (int i = 0; i < 32; i++)
      m[i] = i;
    meas.assign((char *)m, 32);
  }

  // Construct intel-key
  key_message intel_key;
  key_message intel_pk;
  string      intel_key_name("intel-key");
  if (!construct_keys(intel_key_name, key_format, &intel_pk, &intel_key))
    return false;
  if (debug_print) {
    printf("\nIntel key: ");
    print_key(intel_key);
    printf("\n");
  }

  // attest key
  key_message        attest_pk;
  extern key_message my_attestation_key;
  if (!private_key_to_public_key(my_attestation_key, &attest_pk))
    return false;
  if (debug_print) {
    printf("\nAttest key: ");
    print_key(attest_pk);
    printf("\n");
  }

  // Construct enclave-authentication-key
  string      enclave_key_name("enclave-key");
  key_message enclave_key;
  key_message enclave_pk;
  if (!construct_keys(enclave_key_name, key_format, &enclave_pk, &enclave_key))
    return false;
  if (debug_print) {
    printf("\nEnclave key: ");
    print_key(enclave_key);
    printf("\n");
  }

  // measurement entity
  entity_message measurement_entity;
  if (!make_measurement_entity(meas, &measurement_entity))
    return false;
  if (debug_print) {
    printf("Measurement: ");
    print_entity(measurement_entity);
    printf("\n");
  }

  // constructed vse clauses
  string is_trusted("is-trusted");
  string says("says");
  string speaks_for("speaks-for");

  //  c1: enclave-measurement is-trusted
  vse_clause c1;
  if (!make_unary_vse_clause(measurement_entity, is_trusted, &c1))
    return false;

  // c2: intel-key is-trusted
  vse_clause     c2;
  entity_message intel_key_entity;
  if (!make_key_entity(intel_pk, &intel_key_entity))
    return false;
  if (!make_unary_vse_clause(intel_key_entity, is_trusted, &c2))
    return false;

  // c3: attestation-key is-trusted
  vse_clause     c3;
  entity_message attest_key_entity;
  if (!make_key_entity(attest_pk, &attest_key_entity))
    return false;
  if (!make_unary_vse_clause(attest_key_entity, is_trusted, &c3))
    return false;

  // c4: enclave-authentication-key is-trusted
  vse_clause     c4;
  entity_message enclave_key_entity;
  if (!make_key_entity(enclave_pk, &enclave_key_entity))
    return false;
  if (!make_unary_vse_clause(enclave_key_entity, is_trusted, &c4))
    return false;

  // c5: policy-key says measurement is-trusted
  vse_clause     c5;
  entity_message policy_key_entity;
  if (!make_key_entity(*policy_pk, &policy_key_entity))
    return false;
  if (!make_indirect_vse_clause(policy_key_entity, says, c1, &c5))
    return false;

  // c6: policy-key says intel-key is-trusted
  vse_clause c6;
  if (!make_indirect_vse_clause(policy_key_entity, says, c2, &c6))
    return false;

  // c7: intel-key says attestation-key is-trusted
  vse_clause c7;
  if (!make_indirect_vse_clause(intel_key_entity, says, c3, &c7))
    return false;

  // c8: enclave-authentication-key speaks-for enclave-measurement
  vse_clause c8;
  if (!make_simple_vse_clause(enclave_key_entity,
                              speaks_for,
                              measurement_entity,
                              &c8))
    return false;

  // c9: attestation-key says enclave-authentication-key speaks-for
  // enclave-measurement
  vse_clause c9;
  if (!make_indirect_vse_clause(attest_key_entity, says, c8, &c9))
    return false;

  // Construct signed statements
  //    C1: policy-key says enclave-measurement is-trusted (signed c5)
  //    C2: policy-key says intel-key is-trusted (signed c6)
  //    C3: intel-key says attestation-key is-trusted (signed c7)
  //    C4: attestation-key says enclave-authentication-key speaks-for
  //    enclave-measurement (signed c9)
  time_point t_nb;
  time_point t_na;
  string     s_nb;
  string     s_na;
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

  string vse_clause_format("vse-clause");
  string d1("policy-key says enclave-measurement is-trusted");
  string d2("policy-key says intel-key is-trusted");
  string d3("intel-key says attestation-key is-trusted");
  string d4("attestation-key says enclave-authentication-key speaks-for "
            "enclave-measurement");
  string serialized_cl1;
  string serialized_cl2;
  string serialized_cl3;
  string serialized_cl4;
  c5.SerializeToString(&serialized_cl1);
  c6.SerializeToString(&serialized_cl2);
  c7.SerializeToString(&serialized_cl3);
  c9.SerializeToString(&serialized_cl4);

  claim_message cl1;
  if (!make_claim(serialized_cl1.size(),
                  (byte *)serialized_cl1.data(),
                  vse_clause_format,
                  d1,
                  s_nb,
                  s_na,
                  &cl1))
    return false;

  signed_claim_message sc1;
  if (!make_signed_claim(Enc_method_rsa_2048_sha256_pkcs_sign,
                         cl1,
                         *policy_key,
                         &sc1))
    return false;

  claim_message cl2;
  if (!make_claim(serialized_cl2.size(),
                  (byte *)serialized_cl2.data(),
                  vse_clause_format,
                  d2,
                  s_nb,
                  s_na,
                  &cl2))
    return false;

  signed_claim_message sc2;
  if (!make_signed_claim(Enc_method_rsa_2048_sha256_pkcs_sign,
                         cl2,
                         *policy_key,
                         &sc2))
    return false;

  claim_message cl3;
  if (!make_claim(serialized_cl3.size(),
                  (byte *)serialized_cl3.data(),
                  vse_clause_format,
                  d3,
                  s_nb,
                  s_na,
                  &cl3))
    return false;

  signed_claim_message sc3;
  if (!make_signed_claim(Enc_method_rsa_2048_sha256_pkcs_sign,
                         cl3,
                         intel_key,
                         &sc3))
    return false;

  string serialized_what_to_say;
  if (!construct_what_to_say(enclave_type,
                             enclave_pk,
                             &serialized_what_to_say)) {
    return false;
  }

  int  size_out = 8192;
  byte attest_out[size_out];

  if (!Attest(enclave_type,
              serialized_what_to_say.size(),
              (byte *)serialized_what_to_say.data(),
              &size_out,
              attest_out))
    return false;
  string final_serialized_attest;
  final_serialized_attest.assign((char *)attest_out, size_out);

  evp->set_prover_type("vse-verifier");

  // sc1: "policyKey says measurement is-trusted"
  // sc2: "policyKey says platformKey is-trusted"
  // sc3: "platformKey says attestKey is-trusted
  // sc4: "attestKey says enclaveKey speaks-for measurement

  if (evidence_descriptor == "full-vse-support") {
    // Evidence should be
    //    sc3: "platformKey says attestKey is-trusted
    //    sc4: "attestKey says enclaveKey speaks-for measurement (attest)
    //    sc1: "policyKey says measurement is-trusted"
    //    sc2: "policyKey says platformKey is-trusted"

    evidence *ev1 = evp->add_fact_assertion();
    evidence *ev2 = evp->add_fact_assertion();
    evidence *ev3 = evp->add_fact_assertion();
    evidence *ev4 = evp->add_fact_assertion();

    string t_str;
    if (!sc3.SerializeToString(&t_str))
      return false;
    ev1->set_evidence_type("signed-claim");
    ev1->set_serialized_evidence((byte *)t_str.data(), t_str.size());
    t_str.clear();

    ev2->set_evidence_type("signed-vse-attestation-report");
    ev2->set_serialized_evidence((byte *)final_serialized_attest.data(),
                                 final_serialized_attest.size());

    if (!sc1.SerializeToString(&t_str))
      return false;
    ev3->set_evidence_type("signed-claim");
    ev3->set_serialized_evidence((byte *)t_str.data(), t_str.size());
    t_str.clear();

    if (!sc2.SerializeToString(&t_str))
      return false;
    ev4->set_evidence_type("signed-claim");
    ev4->set_serialized_evidence((byte *)t_str.data(), t_str.size());
  } else if (evidence_descriptor == "platform-attestation-only") {
    // Todo: Change this type to "vse-attestation-package"
    // Evidence should be
    //    sc3: "platformKey says attestKey is-trusted
    //    sc4: "attestKey says enclaveKey speaks-for measurement (attest)
    //    sc1 --> trusted_measurements
    //    sc2 --> trusted platforms

    evidence *ev1 = evp->add_fact_assertion();
    evidence *ev2 = evp->add_fact_assertion();

    string t_str;
    if (!sc3.SerializeToString(&t_str))
      return false;
    ev1->set_evidence_type("signed-claim");
    ev1->set_serialized_evidence((byte *)t_str.data(), t_str.size());
    t_str.clear();

    ev2->set_evidence_type("signed-vse-attestation-report");
    ev2->set_serialized_evidence((byte *)final_serialized_attest.data(),
                                 final_serialized_attest.size());

    if (!init_measurements) {
      signed_claim_message *nsc1 = trusted_measurements->add_claims();
      nsc1->CopyFrom(sc1);
    }
    signed_claim_message *nsc2 = trusted_platforms->add_claims();
    nsc2->CopyFrom(sc2);
  } else if (evidence_descriptor == "oe-evidence") {
    // Evidence should be
    //    sc3: "platformKey says attestationKey is-trusted
    //    attest output (attest)
    //    sc1 --> trusted_measurements
    //    sc2 --> trusted platforms

    evidence *ev1 = evp->add_fact_assertion();
    evidence *ev2 = evp->add_fact_assertion();

    string t_str;
    if (!sc3.SerializeToString(&t_str))
      return false;
    ev1->set_evidence_type("signed-claim");
    ev1->set_serialized_evidence((byte *)t_str.data(), t_str.size());
    t_str.clear();

    ev2->set_evidence_type("oe-attestation-report");
    ev2->set_serialized_evidence((byte *)final_serialized_attest.data(),
                                 final_serialized_attest.size());

    if (!init_measurements) {
      signed_claim_message *nsc1 = trusted_measurements->add_claims();
      nsc1->CopyFrom(sc1);
    }
    signed_claim_message *nsc2 = trusted_platforms->add_claims();
    nsc2->CopyFrom(sc2);
  } else if (evidence_descriptor == "asylo-evidence") {
    // Evidence should be
    //    sc3: "platformKey says attestationKey is-trusted
    //    attest output (attest)
    //    sc1 --> trusted_measurements
    //    sc2 --> trusted platforms

    evidence *ev1 = evp->add_fact_assertion();
    evidence *ev2 = evp->add_fact_assertion();

    string t_str;
    if (!sc3.SerializeToString(&t_str))
      return false;
    ev1->set_evidence_type("signed-claim");
    ev1->set_serialized_evidence((byte *)t_str.data(), t_str.size());
    t_str.clear();

    ev2->set_evidence_type("asylo-evidence");
    ev2->set_serialized_evidence((byte *)final_serialized_attest.data(),
                                 final_serialized_attest.size());

    if (!init_measurements) {
      signed_claim_message *nsc1 = trusted_measurements->add_claims();
      nsc1->CopyFrom(sc1);
    }
    signed_claim_message *nsc2 = trusted_platforms->add_claims();
    nsc2->CopyFrom(sc2);
  } else if (evidence_descriptor == "gramine-evidence") {
    // Evidence should be
    //    sc3: "platformKey says attestationKey is-trusted
    //    attest output (attest)
    //    sc1 --> trusted_measurements
    //    sc2 --> trusted platforms

    evidence *ev1 = evp->add_fact_assertion();
    evidence *ev2 = evp->add_fact_assertion();

    string t_str;
    if (!sc3.SerializeToString(&t_str))
      return false;
    ev1->set_evidence_type("signed-claim");
    ev1->set_serialized_evidence((byte *)t_str.data(), t_str.size());
    t_str.clear();

    ev2->set_evidence_type("gramine-evidence");
    ev2->set_serialized_evidence((byte *)final_serialized_attest.data(),
                                 final_serialized_attest.size());

    if (!init_measurements) {
      signed_claim_message *nsc1 = trusted_measurements->add_claims();
      nsc1->CopyFrom(sc1);
    }

    signed_claim_message *nsc2 = trusted_platforms->add_claims();
    nsc2->CopyFrom(sc2);
  } else {
    printf("Bad evidence descriptor\n");
    return false;
  }

  return true;
}

bool test__local_certify(string &enclave_type,
                         bool    init_from_file,
                         string &file_name,
                         string &evidence_descriptor) {
  string enclave_id("test-enclave");

  evidence_package evp;
  evp.set_prover_type("vse-verifier");

  certifier_rules rules;
  if (!init_certifier_rules(rules))
    return false;

  signed_claim_sequence trusted_measurements;
  signed_claim_sequence trusted_platforms;

  key_message policy_key;
  key_message policy_pk;
  if (!construct_standard_evidence_package(enclave_type,
                                           init_from_file,
                                           file_name,
                                           evidence_descriptor,
                                           &trusted_platforms,
                                           &trusted_measurements,
                                           &policy_key,
                                           &policy_pk,
                                           &evp))
    return false;
  if (debug_print) {
    printf("test_local_certify, evidence descriptor: %s, enclave type: %s, "
           "evidence:\n",
           evidence_descriptor.c_str(),
           enclave_type.c_str());
    for (int i = 0; i < evp.fact_assertion_size(); i++) {
      print_evidence(evp.fact_assertion(i));
      printf("\n");
    }
    printf("trusted measurements (%d):\n", trusted_measurements.claims_size());
    for (int i = 0; i < trusted_measurements.claims_size(); i++) {
      print_signed_claim(trusted_measurements.claims(i));
      printf("\n");
    }
    printf("trusted platforms(%d):\n", trusted_platforms.claims_size());
    for (int i = 0; i < trusted_platforms.claims_size(); i++) {
      print_signed_claim(trusted_platforms.claims(i));
      printf("\n");
    }
  }

  string purpose("authentication");
  if (!validate_evidence(evidence_descriptor,
                         trusted_platforms,
                         trusted_measurements,
                         purpose,
                         evp,
                         policy_pk)) {
    printf("validate_evidence failed\n");
    return false;
  }

  return true;
}

// test_local_certify(), test_partial_local_certify()
// Exist so that we can exercise these tests from the Python bindings to
// certifier_tests.so, for the default behaviour of these test cases.
bool test_local_certify(bool print_all) {
  string enclave_type("simulated-enclave");
  string evidence_descriptor("full-vse-support");
  string unused("Unused-file-name");

  if (print_all) {
    printf("%s(): enclave_type='%s', evidence_descriptor='%s'\n",
           __func__,
           enclave_type.c_str(),
           evidence_descriptor.c_str());
  }
  return test__local_certify(enclave_type, false, unused, evidence_descriptor);
}

bool test_partial_local_certify(bool print_all) {
  string enclave_type("simulated-enclave");
  string evidence_descriptor("platform-attestation-only");
  string unused("Unused-file-name");

  if (print_all) {
    printf("%s(): enclave_type='%s', evidence_descriptor='%s'\n",
           __func__,
           enclave_type.c_str(),
           evidence_descriptor.c_str());
  }
  return test__local_certify(enclave_type, false, unused, evidence_descriptor);
}

// constrained delegation test

bool construct_standard_constrained_evidence_package(
    string &               enclave_type,
    bool                   init_measurements,
    string &               file_name,
    string &               evidence_descriptor,
    signed_claim_sequence *trusted_platforms,
    signed_claim_sequence *trusted_measurements,
    key_message *          policy_key,
    key_message *          policy_pk,
    evidence_package *     evp) {

  string policy_key_name("policy-key");
  string key_format("vse-key");
  if (!construct_keys(policy_key_name, key_format, policy_pk, policy_key))
    return false;

  string enclave_id("test-enclave");

  if (debug_print) {
    printf("\nPolicy key: ");
    print_key(*policy_key);
    printf("\n");
  }

  // Construct measurement
  string meas;

  if (init_measurements) {
    if (!read_trusted_binary_measurements_and_sign(file_name,
                                                   *policy_key,
                                                   trusted_measurements))
      return false;

    if (debug_print) {
      printf("\nMeasurements read\n");
      for (int i = 0; i < trusted_measurements->claims_size(); i++) {
        print_signed_claim(trusted_measurements->claims(i));
        printf("\n");
      }
    }
    // measurement should be the only measurement in trusted measurements
    vse_clause c;
    if (!get_vse_clause_from_signed_claim(trusted_measurements->claims(0), &c))
      return false;
    meas.assign((char *)c.clause().subject().measurement().data(),
                c.clause().subject().measurement().size());
  } else {
    byte m[32];
    for (int i = 0; i < 32; i++)
      m[i] = i;
    meas.assign((char *)m, 32);
  }

  // Construct intel-key
  key_message intel_key;
  key_message intel_pk;
  string      intel_key_name("intel-key");
  if (!construct_keys(intel_key_name, key_format, &intel_pk, &intel_key))
    return false;
  if (debug_print) {
    printf("\nIntel key: ");
    print_key(intel_key);
    printf("\n");
  }

  // attest key
  key_message        attest_pk;
  extern key_message my_attestation_key;
  if (!private_key_to_public_key(my_attestation_key, &attest_pk))
    return false;
  if (debug_print) {
    printf("\nAttest key: ");
    print_key(attest_pk);
    printf("\n");
  }

  // Construct enclave-authentication-key
  string      enclave_key_name("enclave-key");
  key_message enclave_key;
  key_message enclave_pk;
  if (!construct_keys(enclave_key_name, key_format, &enclave_pk, &enclave_key))
    return false;
  if (debug_print) {
    printf("\nEnclave key: ");
    print_key(enclave_key);
    printf("\n");
  }

  // measurement entity
  entity_message measurement_entity;
  if (!make_measurement_entity(meas, &measurement_entity))
    return false;
  if (debug_print) {
    printf("Measurement: ");
    print_entity(measurement_entity);
    printf("\n");
  }

  // constructed vse clauses
  string is_trusted_for_attestation("is-trusted-for-attestation");
  string is_trusted_for_authentication("is-trusted-for-authentication");
  string is_trusted("is-trusted");
  string says("says");
  string speaks_for("speaks-for");

  //  c1: enclave-measurement is-trusted
  vse_clause c1;
  if (!make_unary_vse_clause(measurement_entity, is_trusted, &c1))
    return false;

  // c2: intel-key is-trusted-for-attestation
  vse_clause     c2;
  entity_message intel_key_entity;
  if (!make_key_entity(intel_pk, &intel_key_entity))
    return false;
  if (!make_unary_vse_clause(intel_key_entity, is_trusted_for_attestation, &c2))
    return false;

  // c3: attestation-key is-trusted-for-attestation
  vse_clause     c3;
  entity_message attest_key_entity;
  if (!make_key_entity(attest_pk, &attest_key_entity))
    return false;
  if (!make_unary_vse_clause(attest_key_entity,
                             is_trusted_for_attestation,
                             &c3))
    return false;

  // c4: enclave-authentication-key is-trusted-for-authentication
  vse_clause     c4;
  entity_message enclave_key_entity;
  if (!make_key_entity(enclave_pk, &enclave_key_entity))
    return false;
  if (!make_unary_vse_clause(enclave_key_entity,
                             is_trusted_for_authentication,
                             &c4))
    return false;

  // c5: policy-key says measurement is-trusted
  vse_clause     c5;
  entity_message policy_key_entity;
  if (!make_key_entity(*policy_pk, &policy_key_entity))
    return false;
  if (!make_indirect_vse_clause(policy_key_entity, says, c1, &c5))
    return false;

  // c6: policy-key says intel-key is-trusted-for-attestation
  vse_clause c6;
  if (!make_indirect_vse_clause(policy_key_entity, says, c2, &c6))
    return false;

  // c7: intel-key says attestation-key is-trusted-for-attestation
  vse_clause c7;
  if (!make_indirect_vse_clause(intel_key_entity, says, c3, &c7))
    return false;

  // c8: enclave-authentication-key speaks-for enclave-measurement
  vse_clause c8;
  if (!make_simple_vse_clause(enclave_key_entity,
                              speaks_for,
                              measurement_entity,
                              &c8))
    return false;

  // c9: attestation-key says enclave-authentication-key speaks-for
  // enclave-measurement
  vse_clause c9;
  if (!make_indirect_vse_clause(attest_key_entity, says, c8, &c9))
    return false;

  // Construct signed statements
  //    C1: policy-key says enclave-measurement is-trusted (signed c5)
  //    C2: policy-key says intel-key is-trusted-for-attestation (signed c6)
  //    C3: intel-key says attestation-key is-trusted-for-attestation (signed
  //    c7) C4: attestation-key says enclave-authentication-key speaks-for
  //    enclave-measurement (signed c9)
  time_point t_nb;
  time_point t_na;
  string     s_nb;
  string     s_na;
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

  string vse_clause_format("vse-clause");
  string d1("policy-key says enclave-measurement is-trusted");
  string d2("policy-key says intel-key is-trusted-for-attestation");
  string d3("intel-key says attestation-key is-trusted-for-attestation");
  string d4("attestation-key says enclave-authentication-key speaks-for "
            "enclave-measurement");
  string serialized_cl1;
  string serialized_cl2;
  string serialized_cl3;
  string serialized_cl4;
  c5.SerializeToString(&serialized_cl1);
  c6.SerializeToString(&serialized_cl2);
  c7.SerializeToString(&serialized_cl3);
  c9.SerializeToString(&serialized_cl4);

  claim_message cl1;
  if (!make_claim(serialized_cl1.size(),
                  (byte *)serialized_cl1.data(),
                  vse_clause_format,
                  d1,
                  s_nb,
                  s_na,
                  &cl1))
    return false;

  signed_claim_message sc1;
  if (!make_signed_claim(Enc_method_rsa_2048_sha256_pkcs_sign,
                         cl1,
                         *policy_key,
                         &sc1))
    return false;

  claim_message cl2;
  if (!make_claim(serialized_cl2.size(),
                  (byte *)serialized_cl2.data(),
                  vse_clause_format,
                  d2,
                  s_nb,
                  s_na,
                  &cl2))
    return false;

  signed_claim_message sc2;
  if (!make_signed_claim(Enc_method_rsa_2048_sha256_pkcs_sign,
                         cl2,
                         *policy_key,
                         &sc2))
    return false;

  claim_message cl3;
  if (!make_claim(serialized_cl3.size(),
                  (byte *)serialized_cl3.data(),
                  vse_clause_format,
                  d3,
                  s_nb,
                  s_na,
                  &cl3))
    return false;

  signed_claim_message sc3;
  if (!make_signed_claim(Enc_method_rsa_2048_sha256_pkcs_sign,
                         cl3,
                         intel_key,
                         &sc3))
    return false;

  string serialized_what_to_say;
  if (!construct_what_to_say(enclave_type,
                             enclave_pk,
                             &serialized_what_to_say)) {
    return false;
  }

  int  size_out = 8192;
  byte attest_out[size_out];
  if (!Attest(enclave_type,
              serialized_what_to_say.size(),
              (byte *)serialized_what_to_say.data(),
              &size_out,
              attest_out))
    return false;
  string final_serialized_attest;
  final_serialized_attest.assign((char *)attest_out, size_out);

  evp->set_prover_type("vse-verifier");

  // sc1: "policyKey says measurement is-trusted"
  // sc2: "policyKey says platformKey is-trusted"
  // sc3: "platformKey says attestKey is-trusted
  // sc4: "attestKey says enclaveKey speaks-for measurement

  if (evidence_descriptor == "full-vse-support") {
    // Evidence should be
    //    sc3: "platformKey says attestKey is-trusted-for-attestation
    //    sc4: "attestKey says enclaveKey speaks-for measurement (attest)
    //    sc1: "policyKey says measurement is-trusted"
    //    sc2: "policyKey says platformKey is-trusted-for-attestation"

    evidence *ev1 = evp->add_fact_assertion();
    evidence *ev2 = evp->add_fact_assertion();
    evidence *ev3 = evp->add_fact_assertion();
    evidence *ev4 = evp->add_fact_assertion();

    string t_str;
    if (!sc3.SerializeToString(&t_str))
      return false;
    ev1->set_evidence_type("signed-claim");
    ev1->set_serialized_evidence((byte *)t_str.data(), t_str.size());
    t_str.clear();

    ev2->set_evidence_type("signed-vse-attestation-report");
    ev2->set_serialized_evidence((byte *)final_serialized_attest.data(),
                                 final_serialized_attest.size());

    if (!sc1.SerializeToString(&t_str))
      return false;
    ev3->set_evidence_type("signed-claim");
    ev3->set_serialized_evidence((byte *)t_str.data(), t_str.size());
    t_str.clear();

    if (!sc2.SerializeToString(&t_str))
      return false;
    ev4->set_evidence_type("signed-claim");
    ev4->set_serialized_evidence((byte *)t_str.data(), t_str.size());
  } else if (evidence_descriptor == "platform-attestation-only") {
    // Todo: Change this type to "vse-attestation-package"
    // Evidence should be
    //    sc3: "platformKey says attestKey is-trusted-for-attestation
    //    sc4: "attestKey says enclaveKey speaks-for measurement (attest)
    //    sc1 --> trusted_measurements
    //    sc2 --> trusted platforms

    evidence *ev1 = evp->add_fact_assertion();
    evidence *ev2 = evp->add_fact_assertion();

    string t_str;
    if (!sc3.SerializeToString(&t_str))
      return false;
    ev1->set_evidence_type("signed-claim");
    ev1->set_serialized_evidence((byte *)t_str.data(), t_str.size());
    t_str.clear();

    ev2->set_evidence_type("signed-vse-attestation-report");
    ev2->set_serialized_evidence((byte *)final_serialized_attest.data(),
                                 final_serialized_attest.size());

    if (!init_measurements) {
      signed_claim_message *nsc1 = trusted_measurements->add_claims();
      nsc1->CopyFrom(sc1);
    }
    signed_claim_message *nsc2 = trusted_platforms->add_claims();
    nsc2->CopyFrom(sc2);

  } else if (evidence_descriptor == "oe-evidence") {
    // Evidence should be
    //    sc3: "platformKey says attestationKey is-trusted
    //    attest output (attest)
    //    sc1 --> trusted_measurements
    //    sc2 --> trusted platforms

    evidence *ev1 = evp->add_fact_assertion();
    evidence *ev2 = evp->add_fact_assertion();

    string t_str;
    if (!sc3.SerializeToString(&t_str))
      return false;
    ev1->set_evidence_type("signed-claim");
    ev1->set_serialized_evidence((byte *)t_str.data(), t_str.size());
    t_str.clear();

    ev2->set_evidence_type("oe-attestation-report");
    ev2->set_serialized_evidence((byte *)final_serialized_attest.data(),
                                 final_serialized_attest.size());

    if (!init_measurements) {
      signed_claim_message *nsc1 = trusted_measurements->add_claims();
      nsc1->CopyFrom(sc1);
    }
    signed_claim_message *nsc2 = trusted_platforms->add_claims();
    nsc2->CopyFrom(sc2);
  } else if (evidence_descriptor == "asylo-evidence") {
    // Evidence should be
    //    sc3: "platformKey says attestationKey is-trusted
    //    attest output (attest)
    //    sc1 --> trusted_measurements
    //    sc2 --> trusted platforms

    evidence *ev1 = evp->add_fact_assertion();
    evidence *ev2 = evp->add_fact_assertion();

    string t_str;
    if (!sc3.SerializeToString(&t_str)) {
      printf("\n Error in adding asylo evidence\n");
      return false;
    }
    ev1->set_evidence_type("signed-claim");
    ev1->set_serialized_evidence((byte *)t_str.data(), t_str.size());
    t_str.clear();

    ev2->set_evidence_type("asylo-evidence");
    ev2->set_serialized_evidence((byte *)final_serialized_attest.data(),
                                 final_serialized_attest.size());

    printf("\n Asylo evidence\n");
    print_bytes(final_serialized_attest.size(),
                (byte *)final_serialized_attest.c_str());
    if (!init_measurements) {
      signed_claim_message *nsc1 = trusted_measurements->add_claims();
      nsc1->CopyFrom(sc1);
    }
    signed_claim_message *nsc2 = trusted_platforms->add_claims();
    printf("\n Successfully added asylo evidence\n");
  } else if (evidence_descriptor == "gramine-evidence") {
    // Evidence should be
    //    sc3: "platformKey says attestationKey is-trusted
    //    attest output (attest)
    //    sc1 --> trusted_measurements
    //    sc2 --> trusted platforms

    evidence *ev1 = evp->add_fact_assertion();
    evidence *ev2 = evp->add_fact_assertion();

    string t_str;
    if (!sc3.SerializeToString(&t_str)) {
      printf("\n Error in adding gramine evidence\n");
      return false;
    }
    ev1->set_evidence_type("signed-claim");
    ev1->set_serialized_evidence((byte *)t_str.data(), t_str.size());
    t_str.clear();

    ev2->set_evidence_type("gramine-evidence");
    ev2->set_serialized_evidence((byte *)final_serialized_attest.data(),
                                 final_serialized_attest.size());

    printf("\n Gramine evidence\n");
    print_bytes(final_serialized_attest.size(),
                (byte *)final_serialized_attest.c_str());
    if (!init_measurements) {
      signed_claim_message *nsc1 = trusted_measurements->add_claims();
      nsc1->CopyFrom(sc1);
    }
    signed_claim_message *nsc2 = trusted_platforms->add_claims();
    printf("\n Successfully added gramine evidence\n");
  } else {
    printf("Bad evidence descriptor\n");
    return false;
  }

  return true;
}

bool test__new_local_certify(string &enclave_type,
                             bool    init_from_file,
                             string &file_name,
                             string &evidence_descriptor) {
  string enclave_id("test-enclave");

  evidence_package evp;
  evp.set_prover_type("vse-verifier");

  certifier_rules rules;
  if (!init_certifier_rules(rules))
    return false;

  signed_claim_sequence trusted_measurements;
  signed_claim_sequence trusted_platforms;

  key_message policy_key;
  key_message policy_pk;
  if (!construct_standard_constrained_evidence_package(enclave_type,
                                                       init_from_file,
                                                       file_name,
                                                       evidence_descriptor,
                                                       &trusted_platforms,
                                                       &trusted_measurements,
                                                       &policy_key,
                                                       &policy_pk,
                                                       &evp))
    return false;

  if (debug_print) {
    printf("test_local_certify, evidence descriptor: %s, enclave type: %s, "
           "evidence:\n",
           evidence_descriptor.c_str(),
           enclave_type.c_str());
    for (int i = 0; i < evp.fact_assertion_size(); i++) {
      print_evidence(evp.fact_assertion(i));
      printf("\n");
    }
    printf("trusted measurements (%d):\n", trusted_measurements.claims_size());
    for (int i = 0; i < trusted_measurements.claims_size(); i++) {
      print_signed_claim(trusted_measurements.claims(i));
      printf("\n");
    }
    printf("trusted platforms(%d):\n", trusted_platforms.claims_size());
    for (int i = 0; i < trusted_platforms.claims_size(); i++) {
      print_signed_claim(trusted_platforms.claims(i));
      printf("\n");
    }
  }

  // adding predicate hierarchy
  string purpose("authentication");
  if (!validate_evidence(evidence_descriptor,
                         trusted_platforms,
                         trusted_measurements,
                         purpose,
                         evp,
                         policy_pk)) {
    printf("validate_evidence failed\n");
    return false;
  }
  return true;
}

// Exists so that we can exercise this test from the Python bindings to
// certifier_tests.so, for the default behaviour of this test cases.
bool test_new_local_certify(bool print_all) {
  string enclave_type("simulated-enclave");
  string evidence_descriptor("full-vse-support");
  string unused("Unused-file-name");

  if (print_all) {
    printf("%s(): enclave_type='%s', evidence_descriptor='%s'\n",
           __func__,
           enclave_type.c_str(),
           evidence_descriptor.c_str());
  }
  return test__new_local_certify(enclave_type,
                                 false,
                                 unused,
                                 evidence_descriptor);
}

// -----------------------------------------------------------------------------
