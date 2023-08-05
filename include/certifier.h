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

#ifndef _CERTIFIER_H__
#define _CERTIFIER_H__

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <string>
#include <memory>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <cmath>
#include <string>

#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include "certifier.pb.h"

#include "certifier_framework.h"

// Some Data and access functions
// -------------------------------------------------------------------

extern bool   certifier_parent_enclave_type_intitalized;
extern string certifier_parent_enclave_type;

extern bool        certifier_public_policy_key_initialized;
extern key_message certifier_public_policy_key;
const key_message *GetPublicPolicyKey();

bool PublicKeyFromCert(const string &cert, key_message *k);


bool GetParentEvidence(const string &enclave_type,
                       const string &parent_enclave_type,
                       string *      out);

bool GetPlatformStatement(const string &enclave_type,
                          const string &enclave_id,
                          int *         size_out,
                          byte *        out);


// Claims and proofs
// -------------------------------------------------------------------

bool make_attestation_user_data(const string &         enclave_type,
                                const key_message &    enclave_key,
                                attestation_user_data *out);
bool sign_report(const string &     type,
                 const string &     report,
                 const string &     signing_alg,
                 const key_message &signing_key,
                 string *           serialized_signed_report);
bool verify_report(string &           type,
                   string &           serialized_signed_report,
                   const key_message &signer_key);

void print_signed_report(const signed_report &sr);
void print_user_data(attestation_user_data &at);
void print_attestation_info(vse_attestation_report_info &info);

void print_evidence(const evidence &ev);
void print_evidence_package(const evidence_package &evp);
void print_proof_step(const proof_step &ps);
void print_proof(proof &pf);
void print_trust_response_message(trust_response_message &m);
void print_trust_request_message(trust_request_message &m);
bool read_signed_vse_statements(const string &in, signed_claim_sequence *s);

class predicate_dominance {
 public:
  string               predicate_;
  predicate_dominance *first_child_;
  predicate_dominance *next_;

  predicate_dominance();
  ~predicate_dominance();

  void                 print_tree(int indent);
  void                 print_node(int indent);
  void                 print_descendants(int indent);
  predicate_dominance *find_node(const string &pred);
  bool                 insert(const string &parent, const string &descendant);
  bool                 is_child(const string &descendant);
};
bool dominates(predicate_dominance &root,
               const string &       parent,
               const string &       descendant);

// Certifier proofs
// -------------------------------------------------------------

bool statement_already_proved(const vse_clause & cl,
                              proved_statements *are_proved);

bool construct_vse_attestation_statement(const key_message &attest_key,
                                         const key_message &auth_key,
                                         const string &     measurement,
                                         vse_clause *       vse_attest_clause);
bool construct_what_to_say(string &     enclave_type,
                           key_message &enclave_pk,
                           string *     what_to_say);
bool verify_signed_assertion_and_extract_clause(const key_message &         key,
                                                const signed_claim_message &sc,
                                                vse_clause *                cl);

bool init_certifier_rules(certifier_rules &rules);
bool init_axiom(key_message &pk, proved_statements *_proved);
bool init_proved_statements(key_message &      pk,
                            evidence_package & evp,
                            proved_statements *already_proved);

bool verify_rule_1(predicate_dominance &dom_tree,
                   const vse_clause &   c1,
                   const vse_clause &   c2,
                   const vse_clause &   conclusion);
bool verify_rule_2(predicate_dominance &dom_tree,
                   const vse_clause &   c1,
                   const vse_clause &   c2,
                   const vse_clause &   conclusion);
bool verify_rule_3(predicate_dominance &dom_tree,
                   const vse_clause &   c1,
                   const vse_clause &   c2,
                   const vse_clause &   conclusion);
bool verify_rule_4(predicate_dominance &dom_tree,
                   const vse_clause &   c1,
                   const vse_clause &   c2,
                   const vse_clause &   conclusion);
bool verify_rule_5(predicate_dominance &dom_tree,
                   const vse_clause &   c1,
                   const vse_clause &   c2,
                   const vse_clause &   conclusion);
bool verify_rule_6(predicate_dominance &dom_tree,
                   const vse_clause &   c1,
                   const vse_clause &   c2,
                   const vse_clause &   conclusion);
bool verify_external_proof_step(predicate_dominance &dom_tree,
                                proof_step &         step);
bool verify_internal_proof_step(predicate_dominance &dom_tree,
                                const vse_clause     s1,
                                const vse_clause     s2,
                                const vse_clause     conclude,
                                int                  rule_to_apply);

bool verify_proof(key_message &        policy_pk,
                  vse_clause &         to_prove,
                  predicate_dominance &dom_tree,
                  proof *              the_proof,
                  proved_statements *  are_proved);
bool add_fact_from_signed_claim(const signed_claim_message &signedClaim,
                                proved_statements *         already_proved);
bool add_newfacts_for_sdk_platform_attestation(
    key_message &          policy_pk,
    signed_claim_sequence &trusted_platforms,
    signed_claim_sequence &trusted_measurements,
    proved_statements *    already_proved);
bool add_new_facts_for_abbreviatedplatformattestation(
    key_message &          policy_pk,
    signed_claim_sequence &trusted_platforms,
    signed_claim_sequence &trusted_measurements,
    proved_statements *    already_proved);
bool construct_proof_from_sev_evidence(key_message &      policy_pk,
                                       const string &     purpose,
                                       proved_statements *already_proved,
                                       vse_clause *       to_prove,
                                       proof *            pf);
bool construct_proof_from_sdk_evidence(key_message &      policy_pk,
                                       const string &     purpose,
                                       proved_statements *already_proved,
                                       vse_clause *       to_prove,
                                       proof *            pf);
bool construct_proof_from_full_vse_evidence(key_message &      policy_pk,
                                            const string &     purpose,
                                            proved_statements *already_proved,
                                            vse_clause *       to_prove,
                                            proof *            pf);
bool construct_proof_from_request(const string &         evidence_descriptor,
                                  key_message &          policy_pk,
                                  const string &         purpose,
                                  signed_claim_sequence &trusted_platforms,
                                  signed_claim_sequence &trusted_measurements,
                                  evidence_package &     evp,
                                  proved_statements *    already_proved,
                                  vse_clause *           to_prove,
                                  proof *                pf);
bool validate_evidence(const string &         evidence_descriptor,
                       signed_claim_sequence &trusted_platforms,
                       signed_claim_sequence &trusted_measurements,
                       const string &         purpose,
                       evidence_package &     evp,
                       key_message &          policy_pk);

bool get_platform_from_sev_attest(const sev_attestation_message &sev_att,
                                  entity_message *               ent);
bool get_measurement_from_sev_attest(const sev_attestation_message &sev_att,
                                     entity_message *               ent);
bool filter_sev_policy(const sev_attestation_message &sev_att,
                       const key_message &            policy_pk,
                       const signed_claim_sequence &  policy,
                       signed_claim_sequence *        filtered_policy);
bool init_policy(signed_claim_sequence &policy,
                 key_message &          policy_pk,
                 proved_statements *    already_proved);
bool construct_proof_from_sev_evidence_with_plat(
    const string &     evidence_descriptor,
    key_message &      policy_pk,
    const string &     purpose,
    proved_statements *already_proved,
    vse_clause *       to_prove,
    proof *            pf,
    // the following is temporary till we figure out the proto problem
    proof_step *pss,
    int *       num);
bool verify_proof_from_array(key_message &        policy_pk,
                             vse_clause &         to_prove,
                             predicate_dominance &dom_tree,
                             proved_statements *  are_proved,
                             int                  num_steps,
                             proof_step *         steps);
bool validate_evidence_from_policy(const string &         evidence_descriptor,
                                   signed_claim_sequence &policy,
                                   const string &         purpose,
                                   evidence_package &     evp,
                                   key_message &          policy_pk);

// -------------------------------------------------------------------

#endif
