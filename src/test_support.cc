#include "certifier.h"
#include "support.h"
#include "sev-snp/attestation.h"

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

bool debug_print = false;

bool read_trusted_binary_measurements_and_sign(string& file_name, key_message& policy_key,
        signed_claim_sequence* list) {

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
  int current = 0;
  int left = size;
  while (left >= measurement_size) {
    string measurement;
    measurement.assign((char*)&file_contents[current], measurement_size);
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
    string n1("description");
    string vse_clause_format("vse-clause");
    if (!make_claim(serialized_vse.size(), (byte*)serialized_vse.data(), vse_clause_format, n1,
            nb, na, &claim))
        return false;
    signed_claim_message sc;
    if(!make_signed_claim("rsa-2048-sha256-pkcs-sign", claim, policy_key, &sc))
        return false;

    signed_claim_message* scm = list->add_claims();
    scm->CopyFrom(sc);

    left -= measurement_size;
    current += measurement_size;
  }

  return true;
}

bool construct_keys(string key_name, string format, key_message* public_key, key_message* private_key) {

  if (!make_certifier_rsa_key(2048, private_key))
    return false;
  private_key->set_key_name(key_name);
  private_key->set_key_format(format);

  if (!private_key_to_public_key(*private_key, public_key))
    return false;
  return true;
}

bool construct_standard_evidence_package(string& enclave_type, bool init_measurements,
        string& file_name, string& evidence_descriptor,
        signed_claim_sequence* trusted_platforms,
        signed_claim_sequence* trusted_measurements,
        key_message* policy_key, key_message* policy_pk, evidence_package* evp) {

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
    if (!read_trusted_binary_measurements_and_sign(file_name, *policy_key, trusted_measurements))
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
    meas.assign((char*)c.clause().subject().measurement().data(),
      c.clause().subject().measurement().size());
  } else {
    byte m[32];
    for (int i = 0; i < 32; i++)
      m[i] = i;
    meas.assign((char*)m, 32);
  }

  // Construct intel-key
  key_message intel_key;
  key_message intel_pk;
  string intel_key_name("intel-key");
  if (!construct_keys(intel_key_name, key_format, &intel_pk, &intel_key))
    return false;
  if (debug_print) {
    printf("\nIntel key: ");
    print_key(intel_key);
    printf("\n");
  }

  // attest key
  key_message attest_pk;
  extern key_message my_attestation_key;
  if (!private_key_to_public_key(my_attestation_key, &attest_pk))
    return false;
  if (debug_print) {
    printf("\nAttest key: ");
    print_key(attest_pk);
    printf("\n");
  }

  // Construct enclave-authentication-key
  string enclave_key_name("enclave-key");
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
  vse_clause c2;
  entity_message intel_key_entity;
  if (!make_key_entity(intel_pk, &intel_key_entity))
    return false;
  if (!make_unary_vse_clause(intel_key_entity, is_trusted, &c2))
    return false;

  // c3: attestation-key is-trusted
  vse_clause c3;
  entity_message attest_key_entity;
  if (!make_key_entity(attest_pk, &attest_key_entity))
    return false;
  if (!make_unary_vse_clause(attest_key_entity, is_trusted, &c3))
    return false;

  // c4: enclave-authentication-key is-trusted
  vse_clause c4;
  entity_message enclave_key_entity;
  if (!make_key_entity(enclave_pk, &enclave_key_entity))
    return false;
  if (!make_unary_vse_clause(enclave_key_entity, is_trusted, &c4))
    return false;

  // c5: policy-key says measurement is-trusted
  vse_clause c5;
  entity_message policy_key_entity;
  if (!make_key_entity(*policy_pk, &policy_key_entity))
    return false;
  if (!make_indirect_vse_clause(policy_key_entity, says, c1 , &c5))
    return false;

  // c6: policy-key says intel-key is-trusted
  vse_clause c6;
  if (!make_indirect_vse_clause(policy_key_entity, says, c2 , &c6))
    return false;

  // c7: intel-key says attestation-key is-trusted
  vse_clause c7;
  if (!make_indirect_vse_clause(intel_key_entity, says, c3 , &c7))
    return false;

  // c8: enclave-authentication-key speaks-for enclave-measurement
  vse_clause c8;
  if (!make_simple_vse_clause(enclave_key_entity, speaks_for,
          measurement_entity, &c8))
    return false;

  // c9: attestation-key says enclave-authentication-key speaks-for enclave-measurement
  vse_clause c9;
  if (!make_indirect_vse_clause(attest_key_entity, says, c8 , &c9))
    return false;

  // Construct signed statements
  //    C1: policy-key says enclave-measurement is-trusted (signed c5)
  //    C2: policy-key says intel-key is-trusted (signed c6)
  //    C3: intel-key says attestation-key is-trusted (signed c7)
  //    C4: attestation-key says enclave-authentication-key speaks-for enclave-measurement (signed c9)
  time_point t_nb;
  time_point t_na;
  string s_nb;
  string s_na;
  double hours_to_add = 365.0 * 24.0;

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
  string d4("attestation-key says enclave-authentication-key speaks-for enclave-measurement");
  string serialized_cl1;
  string serialized_cl2;
  string serialized_cl3;
  string serialized_cl4;
  c5.SerializeToString(&serialized_cl1);
  c6.SerializeToString(&serialized_cl2);
  c7.SerializeToString(&serialized_cl3);
  c9.SerializeToString(&serialized_cl4);

  claim_message cl1;
  if (!make_claim(serialized_cl1.size(), (byte*)serialized_cl1.data(), vse_clause_format, d1,
        s_nb, s_na, &cl1))
    return false;

  signed_claim_message sc1;
  if (!make_signed_claim("rsa-2048-sha256-pkcs-sign", cl1, *policy_key, &sc1))
    return false;

  claim_message cl2;
  if (!make_claim(serialized_cl2.size(), (byte*)serialized_cl2.data(), vse_clause_format, d2,
        s_nb, s_na, &cl2))
    return false;

  signed_claim_message sc2;
  if (!make_signed_claim("rsa-2048-sha256-pkcs-sign", cl2, *policy_key, &sc2))
    return false;

  claim_message cl3;
  if (!make_claim(serialized_cl3.size(), (byte*)serialized_cl3.data(), vse_clause_format, d3,
        s_nb, s_na, &cl3))
    return false;

  signed_claim_message sc3;
  if (!make_signed_claim("rsa-2048-sha256-pkcs-sign", cl3, intel_key, &sc3))
    return false;

  string serialized_what_to_say;
  if (!construct_what_to_say(enclave_type, enclave_pk,
          &serialized_what_to_say)) {
    return false;
  }

  int size_out = 8192;
  byte attest_out[size_out];

  if (!Attest(enclave_type, serialized_what_to_say.size(),
              (byte*)serialized_what_to_say.data(),
              &size_out, attest_out))
    return false;
  string final_serialized_attest;
  final_serialized_attest.assign((char*) attest_out, size_out);

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

    evidence* ev1 = evp->add_fact_assertion();
    evidence* ev2 = evp->add_fact_assertion();
    evidence* ev3 = evp->add_fact_assertion();
    evidence* ev4 = evp->add_fact_assertion();

    string t_str;
    if (!sc3.SerializeToString(&t_str))
      return false;
    ev1->set_evidence_type("signed-claim");
    ev1->set_serialized_evidence((byte*) t_str.data(), t_str.size());
    t_str.clear();

    ev2->set_evidence_type("signed-vse-attestation-report");
    ev2->set_serialized_evidence((byte*) final_serialized_attest.data(), final_serialized_attest.size());

    if (!sc1.SerializeToString(&t_str))
      return false;
    ev3->set_evidence_type("signed-claim");
    ev3->set_serialized_evidence((byte*) t_str.data(), t_str.size());
    t_str.clear();

    if (!sc2.SerializeToString(&t_str))
      return false;
    ev4->set_evidence_type("signed-claim");
    ev4->set_serialized_evidence((byte*) t_str.data(), t_str.size());
  } else if (evidence_descriptor == "platform-attestation-only") {
    // Evidence should be
    //    sc3: "platformKey says attestKey is-trusted
    //    sc4: "attestKey says enclaveKey speaks-for measurement (attest)
    //    sc1 --> trusted_measurements
    //    sc2 --> trusted platforms

    evidence* ev1 = evp->add_fact_assertion();
    evidence* ev2 = evp->add_fact_assertion();

    string t_str;
    if (!sc3.SerializeToString(&t_str))
      return false;
    ev1->set_evidence_type("signed-claim");
    ev1->set_serialized_evidence((byte*) t_str.data(), t_str.size());
    t_str.clear();

    ev2->set_evidence_type("signed-vse-attestation-report");
    ev2->set_serialized_evidence((byte*) final_serialized_attest.data(), final_serialized_attest.size());

    if (!init_measurements) {
      signed_claim_message* nsc1 = trusted_measurements->add_claims();
      nsc1->CopyFrom(sc1);
    }
    signed_claim_message* nsc2 = trusted_platforms->add_claims();
    nsc2->CopyFrom(sc2);
  } else if (evidence_descriptor == "oe-evidence") {
    // Evidence should be
    //    sc3: "platformKey says attestationKey is-trusted
    //    attest output (attest)
    //    sc1 --> trusted_measurements
    //    sc2 --> trusted platforms

    evidence* ev1 = evp->add_fact_assertion();
    evidence* ev2 = evp->add_fact_assertion();

    string t_str;
    if (!sc3.SerializeToString(&t_str))
      return false;
    ev1->set_evidence_type("signed-claim");
    ev1->set_serialized_evidence((byte*) t_str.data(), t_str.size());
    t_str.clear();

    ev2->set_evidence_type("oe-attestation-report");
    ev2->set_serialized_evidence((byte*) final_serialized_attest.data(), final_serialized_attest.size());

    if (!init_measurements) {
      signed_claim_message* nsc1 = trusted_measurements->add_claims();
      nsc1->CopyFrom(sc1);
    }
    signed_claim_message* nsc2 = trusted_platforms->add_claims();
    nsc2->CopyFrom(sc2);
  } else if (evidence_descriptor == "asylo-evidence") {
    // Evidence should be
    //    sc3: "platformKey says attestationKey is-trusted
    //    attest output (attest)
    //    sc1 --> trusted_measurements
    //    sc2 --> trusted platforms

    evidence* ev1 = evp->add_fact_assertion();
    evidence* ev2 = evp->add_fact_assertion();

    string t_str;
    if (!sc3.SerializeToString(&t_str))
      return false;
    ev1->set_evidence_type("signed-claim");
    ev1->set_serialized_evidence((byte*) t_str.data(), t_str.size());
    t_str.clear();

    ev2->set_evidence_type("asylo-evidence");
    ev2->set_serialized_evidence((byte*) final_serialized_attest.data(), final_serialized_attest.size());

    if (!init_measurements) {
      signed_claim_message* nsc1 = trusted_measurements->add_claims();
      nsc1->CopyFrom(sc1);
    }
    signed_claim_message* nsc2 = trusted_platforms->add_claims();
    nsc2->CopyFrom(sc2);
  } else if (evidence_descriptor == "gramine-evidence") {
    // Evidence should be
    //    sc3: "platformKey says attestationKey is-trusted
    //    attest output (attest)
    //    sc1 --> trusted_measurements
    //    sc2 --> trusted platforms

    evidence* ev1 = evp->add_fact_assertion();
    evidence* ev2 = evp->add_fact_assertion();

    string t_str;
    if (!sc3.SerializeToString(&t_str))
      return false;
    ev1->set_evidence_type("signed-claim");
    ev1->set_serialized_evidence((byte*) t_str.data(), t_str.size());
    t_str.clear();

    ev2->set_evidence_type("gramine-evidence");
    ev2->set_serialized_evidence((byte*) final_serialized_attest.data(), final_serialized_attest.size());

    if (!init_measurements) {
      signed_claim_message* nsc1 = trusted_measurements->add_claims();
      nsc1->CopyFrom(sc1);
    }

    signed_claim_message* nsc2 = trusted_platforms->add_claims();
    nsc2->CopyFrom(sc2);
  } else {
    printf("Bad evidence descriptor\n");
    return false;
  }

  return true;
}

bool test_local_certify(string& enclave_type,
          bool init_from_file, string& file_name,
          string& evidence_descriptor) {
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
          init_from_file, file_name, evidence_descriptor,
          &trusted_platforms, &trusted_measurements,
          &policy_key, &policy_pk, &evp))
    return false;
  if (debug_print) {
    printf("test_local_certify, evidence descriptor: %s, enclave type: %s, evidence:\n",
        evidence_descriptor.c_str(), enclave_type.c_str());
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
  if (!validate_evidence(evidence_descriptor, trusted_platforms,
          trusted_measurements, purpose, evp, policy_pk)) {
    printf("validate_evidence failed\n");
    return false;
  }

  return true;
}

// constrained delegation test

bool construct_standard_constrained_evidence_package(string& enclave_type,
      bool init_measurements, string& file_name, string& evidence_descriptor,
      signed_claim_sequence* trusted_platforms, signed_claim_sequence* trusted_measurements,
      key_message* policy_key, key_message* policy_pk, evidence_package* evp) {

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
    if (!read_trusted_binary_measurements_and_sign(file_name, *policy_key, trusted_measurements))
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
    meas.assign((char*)c.clause().subject().measurement().data(),
      c.clause().subject().measurement().size());
    } else {
      byte m[32];
      for (int i = 0; i < 32; i++)
        m[i] = i;
      meas.assign((char*)m, 32);
    }

  // Construct intel-key
  key_message intel_key;
  key_message intel_pk;
  string intel_key_name("intel-key");
  if (!construct_keys(intel_key_name, key_format, &intel_pk, &intel_key))
    return false;
  if (debug_print) {
    printf("\nIntel key: ");
    print_key(intel_key);
    printf("\n");
  }

  // attest key
  key_message attest_pk;
  extern key_message my_attestation_key;
  if (!private_key_to_public_key(my_attestation_key, &attest_pk))
    return false;
  if (debug_print) {
    printf("\nAttest key: ");
    print_key(attest_pk);
    printf("\n");
  }

  // Construct enclave-authentication-key
  string enclave_key_name("enclave-key");
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
  vse_clause c2;
  entity_message intel_key_entity;
  if (!make_key_entity(intel_pk, &intel_key_entity))
    return false;
  if (!make_unary_vse_clause(intel_key_entity, is_trusted_for_attestation, &c2))
    return false;

  // c3: attestation-key is-trusted-for-attestation
  vse_clause c3;
  entity_message attest_key_entity;
  if (!make_key_entity(attest_pk, &attest_key_entity))
    return false;
  if (!make_unary_vse_clause(attest_key_entity, is_trusted_for_attestation, &c3))
    return false;

  // c4: enclave-authentication-key is-trusted-for-authentication
  vse_clause c4;
  entity_message enclave_key_entity;
  if (!make_key_entity(enclave_pk, &enclave_key_entity))
    return false;
  if (!make_unary_vse_clause(enclave_key_entity, is_trusted_for_authentication, &c4))
    return false;

  // c5: policy-key says measurement is-trusted
  vse_clause c5;
  entity_message policy_key_entity;
  if (!make_key_entity(*policy_pk, &policy_key_entity))
    return false;
  if (!make_indirect_vse_clause(policy_key_entity, says, c1 , &c5))
    return false;

  // c6: policy-key says intel-key is-trusted-for-attestation
  vse_clause c6;
  if (!make_indirect_vse_clause(policy_key_entity, says, c2 , &c6))
    return false;

  // c7: intel-key says attestation-key is-trusted-for-attestation
  vse_clause c7;
  if (!make_indirect_vse_clause(intel_key_entity, says, c3 , &c7))
    return false;

  // c8: enclave-authentication-key speaks-for enclave-measurement
  vse_clause c8;
  if (!make_simple_vse_clause(enclave_key_entity, speaks_for,
          measurement_entity, &c8))
    return false;

  // c9: attestation-key says enclave-authentication-key speaks-for enclave-measurement
  vse_clause c9;
  if (!make_indirect_vse_clause(attest_key_entity, says, c8 , &c9))
    return false;

  // Construct signed statements
  //    C1: policy-key says enclave-measurement is-trusted (signed c5)
  //    C2: policy-key says intel-key is-trusted-for-attestation (signed c6)
  //    C3: intel-key says attestation-key is-trusted-for-attestation (signed c7)
  //    C4: attestation-key says enclave-authentication-key speaks-for enclave-measurement (signed c9)
  time_point t_nb;
  time_point t_na;
  string s_nb;
  string s_na;
  double hours_to_add = 365.0 * 24.0;

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
  string d4("attestation-key says enclave-authentication-key speaks-for enclave-measurement");
  string serialized_cl1;
  string serialized_cl2;
  string serialized_cl3;
  string serialized_cl4;
  c5.SerializeToString(&serialized_cl1);
  c6.SerializeToString(&serialized_cl2);
  c7.SerializeToString(&serialized_cl3);
  c9.SerializeToString(&serialized_cl4);

  claim_message cl1;
  if (!make_claim(serialized_cl1.size(), (byte*)serialized_cl1.data(), vse_clause_format, d1,
        s_nb, s_na, &cl1))
    return false;

  signed_claim_message sc1;
  if (!make_signed_claim("rsa-2048-sha256-pkcs-sign", cl1, *policy_key, &sc1))
    return false;

  claim_message cl2;
  if (!make_claim(serialized_cl2.size(), (byte*)serialized_cl2.data(), vse_clause_format, d2,
        s_nb, s_na, &cl2))
    return false;

  signed_claim_message sc2;
  if (!make_signed_claim("rsa-2048-sha256-pkcs-sign", cl2, *policy_key, &sc2))
    return false;

  claim_message cl3;
  if (!make_claim(serialized_cl3.size(), (byte*)serialized_cl3.data(), vse_clause_format, d3,
        s_nb, s_na, &cl3))
    return false;

  signed_claim_message sc3;
  if (!make_signed_claim("rsa-2048-sha256-pkcs-sign", cl3, intel_key, &sc3))
    return false;

  string serialized_what_to_say;
  if (!construct_what_to_say(enclave_type, enclave_pk,
          &serialized_what_to_say)) {
    return false;
  }

  int size_out = 8192;
  byte attest_out[size_out];
  if (!Attest(enclave_type, serialized_what_to_say.size(),
              (byte*)serialized_what_to_say.data(),
              &size_out, attest_out))
    return false;
  string final_serialized_attest;
  final_serialized_attest.assign((char*) attest_out, size_out);

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

    evidence* ev1 = evp->add_fact_assertion();
    evidence* ev2 = evp->add_fact_assertion();
    evidence* ev3 = evp->add_fact_assertion();
    evidence* ev4 = evp->add_fact_assertion();

    string t_str;
    if (!sc3.SerializeToString(&t_str))
      return false;
    ev1->set_evidence_type("signed-claim");
    ev1->set_serialized_evidence((byte*) t_str.data(), t_str.size());
    t_str.clear();

    ev2->set_evidence_type("signed-vse-attestation-report");
    ev2->set_serialized_evidence((byte*) final_serialized_attest.data(), final_serialized_attest.size());

    if (!sc1.SerializeToString(&t_str))
      return false;
    ev3->set_evidence_type("signed-claim");
    ev3->set_serialized_evidence((byte*) t_str.data(), t_str.size());
    t_str.clear();

    if (!sc2.SerializeToString(&t_str))
      return false;
    ev4->set_evidence_type("signed-claim");
    ev4->set_serialized_evidence((byte*) t_str.data(), t_str.size());
  } else if (evidence_descriptor == "platform-attestation-only") {
    // Evidence should be
    //    sc3: "platformKey says attestKey is-trusted-for-attestation
    //    sc4: "attestKey says enclaveKey speaks-for measurement (attest)
    //    sc1 --> trusted_measurements
    //    sc2 --> trusted platforms

    evidence* ev1 = evp->add_fact_assertion();
    evidence* ev2 = evp->add_fact_assertion();

    string t_str;
    if (!sc3.SerializeToString(&t_str))
      return false;
    ev1->set_evidence_type("signed-claim");
    ev1->set_serialized_evidence((byte*) t_str.data(), t_str.size());
    t_str.clear();

    ev2->set_evidence_type("signed-vse-attestation-report");
    ev2->set_serialized_evidence((byte*) final_serialized_attest.data(), final_serialized_attest.size());

    if (!init_measurements) {
      signed_claim_message* nsc1 = trusted_measurements->add_claims();
      nsc1->CopyFrom(sc1);
    }
    signed_claim_message* nsc2 = trusted_platforms->add_claims();
    nsc2->CopyFrom(sc2);

  } else if (evidence_descriptor == "oe-evidence") {
    // Evidence should be
    //    sc3: "platformKey says attestationKey is-trusted
    //    attest output (attest)
    //    sc1 --> trusted_measurements
    //    sc2 --> trusted platforms

    evidence* ev1 = evp->add_fact_assertion();
    evidence* ev2 = evp->add_fact_assertion();

    string t_str;
    if (!sc3.SerializeToString(&t_str))
      return false;
    ev1->set_evidence_type("signed-claim");
    ev1->set_serialized_evidence((byte*) t_str.data(), t_str.size());
    t_str.clear();

    ev2->set_evidence_type("oe-attestation-report");
    ev2->set_serialized_evidence((byte*) final_serialized_attest.data(), final_serialized_attest.size());

    if (!init_measurements) {
      signed_claim_message* nsc1 = trusted_measurements->add_claims();
      nsc1->CopyFrom(sc1);
    }
    signed_claim_message* nsc2 = trusted_platforms->add_claims();
    nsc2->CopyFrom(sc2);
  } else if (evidence_descriptor == "asylo-evidence") {
    // Evidence should be
    //    sc3: "platformKey says attestationKey is-trusted
    //    attest output (attest)
    //    sc1 --> trusted_measurements
    //    sc2 --> trusted platforms

    evidence* ev1 = evp->add_fact_assertion();
    evidence* ev2 = evp->add_fact_assertion();

    string t_str;
    if (!sc3.SerializeToString(&t_str)) {
      printf("\n Error in adding asylo evidence\n");
      return false;
    }
    ev1->set_evidence_type("signed-claim");
    ev1->set_serialized_evidence((byte*) t_str.data(), t_str.size());
    t_str.clear();

    ev2->set_evidence_type("asylo-evidence");
    ev2->set_serialized_evidence((byte*) final_serialized_attest.data(), final_serialized_attest.size());

    printf("\n Asylo evidence\n");
    print_bytes(final_serialized_attest.size(), (byte*)final_serialized_attest.c_str());
    if (!init_measurements) {
      signed_claim_message* nsc1 = trusted_measurements->add_claims();
      nsc1->CopyFrom(sc1);
    }
    signed_claim_message* nsc2 = trusted_platforms->add_claims();
    printf("\n Successfully added asylo evidence\n");
  } else if (evidence_descriptor == "gramine-evidence") {
    // Evidence should be
    //    sc3: "platformKey says attestationKey is-trusted
    //    attest output (attest)
    //    sc1 --> trusted_measurements
    //    sc2 --> trusted platforms

    evidence* ev1 = evp->add_fact_assertion();
    evidence* ev2 = evp->add_fact_assertion();

    string t_str;
    if (!sc3.SerializeToString(&t_str)) {
      printf("\n Error in adding gramine evidence\n");
      return false;
    }
    ev1->set_evidence_type("signed-claim");
    ev1->set_serialized_evidence((byte*) t_str.data(), t_str.size());
    t_str.clear();

    ev2->set_evidence_type("gramine-evidence");
    ev2->set_serialized_evidence((byte*) final_serialized_attest.data(), final_serialized_attest.size());

    printf("\n Gramine evidence\n");
    print_bytes(final_serialized_attest.size(), (byte*)final_serialized_attest.c_str());
    if (!init_measurements) {
      signed_claim_message* nsc1 = trusted_measurements->add_claims();
      nsc1->CopyFrom(sc1);
    }
    signed_claim_message* nsc2 = trusted_platforms->add_claims();
    printf("\n Successfully added gramine evidence\n");
  } else {
    printf("Bad evidence descriptor\n");
    return false;
  }

  return true;
}

bool test_new_local_certify(string& enclave_type,
          bool init_from_file, string& file_name,
          string& evidence_descriptor) {
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
          init_from_file, file_name, evidence_descriptor,
          &trusted_platforms, &trusted_measurements,
          &policy_key, &policy_pk, &evp))
    return false;

  if (debug_print) {
    printf("test_local_certify, evidence descriptor: %s, enclave type: %s, evidence:\n",
        evidence_descriptor.c_str(), enclave_type.c_str());
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
  if (!validate_evidence(evidence_descriptor, trusted_platforms,
          trusted_measurements, purpose, evp, policy_pk)) {
    printf("validate_evidence failed\n");
    return false;
  }
  return true;
}


// new platform test

bool simulated_sev_Attest(const key_message& vcek, const string& enclave_type,
      int ud_size, byte* ud_data, int* size_out, byte* out) {

  attestation_report ar;
  memset(&ar, 0, sizeof(ar));

  if (!digest_message("sha-384", ud_data, ud_size, ar.report_data, 48)) {
    printf("simulated_sev_Attest: can't digest ud\n");
    return false;
  }
  memset(ar.measurement, 0, 48);
  ar.version = 1;
  ar.guest_svn = 1;
  ar.policy = 0xffff;
  // ar.family_id[16];
  // ar.image_id[16];
  // ar.vmpl;
  // ar.signature_algo;
  // ar.tcb_version platform_version;
  // ar.platform_info;
  // ar.flags;
  // ar.reserved0;
  // ar.host_data[32];
  // ar.id_key_digest[48];
  // ar.author_key_digest[48];
  // ar.report_id[32];
  // ar.report_id_ma[32];
  // ar.tcb_version reported_tcb;
  // ar.reserved1[24];
  // ar.chip_id[64];
  // ar.reserved2[192];
  // ar.signature.r[72];
  // ar.signature.s[72];

  EC_KEY* eck = key_to_ECC(vcek);
  int blk_len = ECDSA_size(eck);
  int sig_size_out = 2 * blk_len;
  byte sig_out[sig_size_out];
  if (!ecc_sign("sha-384", eck, sizeof(ar) - sizeof(ar.signature), (byte*)&ar,
          &sig_size_out, sig_out)) {
    printf("simulated_sev_Attest: can't ec_sign\n");
    return false;
  }
  memcpy(ar.signature.r, sig_out, blk_len);
  memcpy(ar.signature.s, &sig_out[blk_len], blk_len);
  EC_KEY_free(eck);

  sev_attestation_message atm;
  string atm_str;

  atm.mutable_what_was_said()->assign((char*)ud_data, ud_size);
  atm.mutable_reported_attestation()->assign((char*)&ar, sizeof(ar));

  if (!atm.SerializeToString(&atm_str)) {
    printf("simulated_sev_Attest: can't sev attestation\n");
    return false;
  }
  if (*size_out < atm_str.size()) {
    printf("simulated_sev_Attest: output buffer too small\n");
    return false;
  }
  *size_out = atm_str.size();
  memcpy(out, (byte*)atm_str.data(), *size_out);

  return true;
}

bool construct_simulated_sev_platform_evidence(
      const string& purpose, const string& serialized_ark_cert,
      const string& serialized_ask_cert, const string& serialized_vcek_cert,
      const key_message& vcek, evidence_package* evp) {

  evp->set_prover_type("vse-verifier");
  string enclave_type("sev-enclave");

  // certs
  evidence* ev = evp->add_fact_assertion();
  if (ev ==nullptr) {
    printf("construct_simulated_sev_platform_evidence: Can't add to ark platform evidence\n");
    return false;
  }
  ev->set_evidence_type("cert");
  ev->set_serialized_evidence(serialized_ark_cert);
  ev = evp->add_fact_assertion();
  if (ev ==nullptr) {
    printf("construct_simulated_sev_platform_evidence: Can't add to ask platform evidence\n");
    return false;
  }
  ev->set_evidence_type("cert");
  ev->set_serialized_evidence(serialized_vcek_cert);
  ev = evp->add_fact_assertion();
  if (ev ==nullptr) {
    printf("construct_simulated_sev_platform_evidence: Can't add to vcek platform evidence\n");
    return false;
  }
  ev->set_evidence_type("cert");
  ev->set_serialized_evidence(serialized_vcek_cert);

  key_message auth_key;
  RSA* r= RSA_new();
    if (!generate_new_rsa_key(2048, r)) {
      printf("construct_simulated_sev_platform_evidence: Can't generate rsa key\n");
      return false;
    }
    if (!RSA_to_key(r, &auth_key)) {
      printf("construct_simulated_sev_platform_evidence: Can't convert rsa key to key\n");
      RSA_free(r);
      return false;
    }
    RSA_free(r);

  // replace this with real sev certs and attestation
  attestation_user_data ud;
  if (purpose == "authentication") {
    if (!make_attestation_user_data(enclave_type,
          auth_key, &ud)) {
      printf("construct_simulated_sev_platform_evidence: Can't make user data (1)\n");
      return false;
    }
  } else if (purpose == "attestation") {
    if (!make_attestation_user_data(enclave_type,
          auth_key, &ud)) {
      printf("construct_simulated_sev_platform_evidence: Can't make user data (1)\n");
      return false;
    }
  } else {
    printf("construct_simulated_sev_platform_evidence: neither attestation or authorization\n");
    return false;
  }
  string serialized_ud;
  if (!ud.SerializeToString(&serialized_ud)) {
    printf("construct_simulated_sev_platform_evidence: Can't serialize user data\n");
    return false;
  }

  int size_out = 16000;
  byte out[size_out];
#if 0
  if (!Attest(enclave_type, serialized_ud.size(),
        (byte*) serialized_ud.data(), &size_out, out)) {
#else
  if (!simulated_sev_Attest(vcek, enclave_type, serialized_ud.size(),
        (byte*) serialized_ud.data(), &size_out, out)) {
#endif
    printf("construct_simulated_sev_platform_evidence: Attest failed\n");
    return false;
  }
  string the_attestation_str;
  the_attestation_str.assign((char*)out, size_out);

  ev = evp->add_fact_assertion();
  if (ev ==nullptr) {
    printf("construct_simulated_sev_platform_evidence: Can't add to attest platform evidence\n");
    return false;
  }
  ev->set_evidence_type("sev-attestation");
  ev->set_serialized_evidence(the_attestation_str);
  ev = evp->add_fact_assertion();
  if (ev ==nullptr) {
    printf("construct_simulated_sev_platform_evidence: Can't add to vcek platform evidence\n");
    return false;
  }

  return true;
}

bool test_simulated_sev_platform_certify(
          const string& policy_file_name, const string& policy_key_file,
          const string& ark_key_file_name, const string& ask_key_file_name,
          const string& vcek_key_file_name) {

  string enclave_type("sev-enclave");
  string evidence_descriptor("sev-full-platform");
  string enclave_id("test-enclave");
  evidence_package evp;

  debug_print = false;

  // get policy
  signed_claim_sequence signed_statements;
  if (!read_signed_vse_statements(policy_file_name, &signed_statements)) {
    printf("test_simulated_sev_platform_certify: Can't read policy\n");
    return false;
  }

  key_message policy_key;
  key_message policy_pk;
  string policy_key_str;
  if (!read_file_into_string(policy_key_file, &policy_key_str)) {
    printf("test_simulated_sev_platform_certify: Can't read policy key\n");
    return false;
  }
  if (!policy_key.ParseFromString(policy_key_str)) {
    printf("test_simulated_sev_platform_certify: Can't parse policy key\n");
    return false;
  }
  if (!private_key_to_public_key(policy_key, &policy_pk)) {
    printf("test_simulated_sev_platform_certify: Can't convert policy key\n");
    return false;
  }

  // Make ark, ask, vcek certs
  key_message ark_key;
  key_message ark_pk;
  string ark_key_str;
  if (!read_file_into_string(ark_key_file_name, &ark_key_str)) {
    printf("test_simulated_sev_platform_certify: Can't read ark key\n");
    return false;
  }
  if (!ark_key.ParseFromString(ark_key_str)) {
    printf("test_simulated_sev_platform_certify: Can't parse ark key\n");
    return false;
  }
  ark_key.set_key_name("ARKKey");
  ark_key.set_key_type("rsa-2048-private");
  ark_key.set_key_format("vse-key");
  print_key(ark_key); printf("\n");
  if (!private_key_to_public_key(ark_key, &ark_pk)) {
    printf("test_simulated_sev_platform_certify: Can't convert ark key\n");
    return false;
  }

  key_message ask_key;
  key_message ask_pk;
  string ask_key_str;
  if (!read_file_into_string(ask_key_file_name, &ask_key_str)) {
    return false;
  }
  if (!ask_key.ParseFromString(ask_key_str)) {
    return false;
  }
  ask_key.set_key_name("ASKKey");
  ask_key.set_key_type("rsa-2048-private");
  ask_key.set_key_format("vse-key");
  print_key(ask_key); printf("\n");
  if (!private_key_to_public_key(ask_key, &ask_pk)) {
    return false;
  }

  key_message vcek_key;
  key_message vcek_pk;
  string vcek_key_str;
  if (!read_file_into_string(vcek_key_file_name, &vcek_key_str)) {
    return false;
  }
  if (!vcek_key.ParseFromString(vcek_key_str)) {
    return false;
  }
  vcek_key.set_key_name("VCEKKey");
  vcek_key.set_key_type("ecc-384-private");
  vcek_key.set_key_format("vse-key");
  print_key(vcek_key); printf("\n");
  if (!private_key_to_public_key(vcek_key, &vcek_pk)) {
    return false;
  }
  print_key(vcek_key); printf("\n");

  string ark_issuer_desc("platform-provider");
  string ark_issuer_name("AMD");
  string ark_subject_desc("platform-provider");
  string ark_subject_name("AMD");
  X509* x_ark = X509_new();
  if(!produce_artifact(ark_key,
          ark_issuer_name, ark_issuer_desc, ark_pk,
          ark_subject_name, ark_subject_desc, 
          1ULL, 365.26*86400, x_ark, true)) {
    return false;
  }
  string serialized_ark_cert;
  if (!x509_to_asn1(x_ark, &serialized_ark_cert)) {
    return false;
  }

  string ask_issuer_desc("platform-provider");
  string ask_issuer_name("AMD");
  string ask_subject_desc("platform-provider");
  string ask_subject_name("AMD");
  X509* x_ask = X509_new();
  if(!produce_artifact(ask_key,
          ask_issuer_name, ask_issuer_desc, ask_pk,
          ask_subject_name, ask_subject_desc, 
          1ULL, 365.26*86400, x_ask, true)) {
    return false;
  }
  string serialized_ask_cert;
  if (!x509_to_asn1(x_ask, &serialized_ask_cert)) {
    return false;
  }

  string vcek_issuer_desc("platform-provider");
  string vcek_issuer_name("AMD");
  string vcek_subject_desc("platform-provider");
  string vcek_subject_name("AMD");
  X509* x_vcek = X509_new();
  if(!produce_artifact(vcek_key,
          vcek_issuer_name, vcek_issuer_desc, vcek_pk,
          vcek_subject_name, vcek_subject_desc, 
          1ULL, 365.26*86400, x_vcek, true)) {
    return false;
  }
  string serialized_vcek_cert;
  if (!x509_to_asn1(x_vcek, &serialized_vcek_cert)) {
    return false;
  }

  // construct evidence package
  string purpose("authentication");
  if (!construct_simulated_sev_platform_evidence(purpose, serialized_ark_cert,
          serialized_ask_cert, serialized_vcek_cert, vcek_key, &evp)) {
    printf("construct_simulated_sev_platform_evidence failed\n");
    return false;
  }

  if (debug_print) {
    printf("\nPolicy key:\n");
    print_key(policy_pk);
    printf("\nPolicy and evidence:\n");
    for (int i = 0; i < signed_statements.claims_size(); i++) {
      print_signed_claim(signed_statements.claims(i));
      printf("\n");
    }
  }

  if (debug_print) {
    printf("test_platform_certify, evidence descriptor: %s, enclave type: %s, evidence:\n",
        evidence_descriptor.c_str(), enclave_type.c_str());
    for (int i = 0; i < evp.fact_assertion_size(); i++) {
      print_evidence(evp.fact_assertion(i));
      printf("\n");
    }
  }

  if (!validate_evidence_from_policy(evidence_descriptor, signed_statements,
          purpose, evp, policy_pk)) {
    printf("validate_evidence failed\n");
    return false;
  }

  return true;
}

// -----------------------------------------------------------------------------
