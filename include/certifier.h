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

#ifndef byte
typedef unsigned char byte;
#endif

using std::string;

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


// Some Data and access functions
// -------------------------------------------------------------------

extern bool certifier_parent_enclave_type_intitalized;
extern string certifier_parent_enclave_type;

extern bool certifier_public_policy_key_initialized;
extern key_message certifier_public_policy_key;
const key_message* GetPublicPolicyKey();

bool PublicKeyFromCert(const string& cert, key_message* k);


// Policy store
// -------------------------------------------------------------------

class policy_store {
public:
  enum {MAX_NUM_ENTRIES = 200};
  bool policy_key_valid_;

  key_message policy_key_;

  int max_num_ts_;
  int num_ts_;
  trusted_service_message** ts_;
  int max_num_tsc_;
  int num_tsc_;
  tagged_signed_claim** tsc_;
  int max_num_si_;
  int num_si_;
  storage_info_message** si_;
  int max_num_tc_;
  int num_tc_;
  tagged_claim** tc_;
  int max_num_tkm_;
  int num_tkm_;
  channel_key_message** tkm_;
  int max_num_blobs_;
  int num_blobs_;
  tagged_blob_message** tagged_blob_;

public:

  policy_store();
  policy_store(int max_trusted_services, int max_trusted_signed_claims,
      int max_storage_infos, int max_claims, int max_keys, int max_blobs);
  ~policy_store();

  bool replace_policy_key(key_message& k);
  const key_message* get_policy_key();

  int get_num_trusted_services();
  const trusted_service_message* get_trusted_service_info_by_index(int n);
  int get_trusted_service_index_by_tag(const string tag);
  bool add_trusted_service(trusted_service_message& to_add);
  void delete_trusted_service_by_index(int n);

  int get_num_storage_info();
  const storage_info_message* get_storage_info_by_index(int n);
  bool add_storage_info(storage_info_message& to_add);
  int get_storage_info_index_by_tag(const string& tag);
  void delete_storage_info_by_index(int n);

  int get_num_claims();
  const claim_message* get_claim_by_index(int n);
  bool add_claim(const string& tag, const claim_message& to_add);
  int get_claim_index_by_tag(const string& tag);
  void delete_claim_by_index(int n);

  int get_num_signed_claims();
  const signed_claim_message* get_signed_claim_by_index(int n);
  int get_signed_claim_index_by_tag(const string& tag);
  bool add_signed_claim(const string& tag, const signed_claim_message& to_add);
  void delete_signed_claim_by_index(int n);

  bool add_authentication_key(const string& tag, const key_message& k);
  const key_message* get_authentication_key_by_tag(const string& tag);
  const key_message* get_authentication_key_by_index(int index);
  int get_authentication_key_index_by_tag(const string& tag);
  void delete_authentication_key_by_index(int index);

  bool add_blob(const string& tag, const string& s);
  const string* get_blob_by_tag(const string& tag);
  const string* get_blob_by_index(int index);
  const tagged_blob_message* get_tagged_blob_info_by_index(int n);
  int get_blob_index_by_tag(const string& tag);
  void delete_blob_by_index(int index);
  int get_num_blobs();

  bool Serialize(string* out);
  bool Deserialize(string& in);

  void clear_policy_store();
};
void print_store(policy_store& ps);


// Trusted primitives
// -------------------------------------------------------------------

bool Seal(const string& enclave_type, const string& enclave_id,
  int in_size, byte* in, int* size_out, byte* out);

bool Unseal(const string& enclave_type, const string& enclave_id,
  int in_size, byte* in, int* size_out, byte* out);

bool Attest(const string& enclave_type,
  int what_to_say_size, byte* what_to_say,
  int* size_out, byte* out);

bool GetParentEvidence(const string& enclave_type, const string& parent_enclave_type,
      string* out);

bool GetPlatformStatement(const string& enclave_type, const string& enclave_id,
  int* size_out, byte* out);


// Protect Support
// -------------------------------------------------------------------

bool Protect_Blob(const string& enclave_type,
  key_message& key, int size_unencrypted_data, byte* unencrypted_data,
  int* size_protected_blob, byte* blob);
bool Unprotect_Blob(const string& enclave_type,
  int size_protected_blob, byte* protected_blob,
  key_message* key, int* size_of_unencrypted_data, byte* data);

// -------------------------------------------------------------------


// Claims and proofs
// -------------------------------------------------------------------

bool check_date_range(const string& nb, const string& na);
bool make_attestation_user_data(const string& enclave_type,
       const key_message& enclave_key, attestation_user_data* out);
bool sign_report(const string& type, const string& report, const string& signing_alg,
      const key_message& signing_key, string* serialized_signed_report);
bool verify_report(string& type, string& serialized_signed_report,
      const key_message& signer_key);

void print_signed_report(const signed_report& sr);
void print_user_data(attestation_user_data& at);
void print_attestation_info(vse_attestation_report_info& info);

void print_evidence(const evidence& ev);
void print_evidence_package(const evidence_package& evp);
void print_proof_step(const proof_step& ps);
void print_proof(proof& pf);
void print_trust_response_message(trust_response_message& m);
void print_trust_request_message(trust_request_message& m);
bool read_signed_vse_statements(const string& in, signed_claim_sequence* s);

class predicate_dominance {
public:
  string predicate_;
  predicate_dominance* first_child_;
  predicate_dominance* next_;

  predicate_dominance();
  ~predicate_dominance();

  void print_tree(int indent);
  void print_node(int indent);
  void print_descendants(int indent);
  predicate_dominance* find_node(const string& pred);
  bool insert(const string& parent, const string& descendant);
  bool is_child(const string& descendant);
};
bool dominates(predicate_dominance& root, const string& parent, const string& descendant);

// Certifier proofs
// -------------------------------------------------------------

bool statement_already_proved(const vse_clause& cl, proved_statements* are_proved);

bool construct_vse_attestation_statement(const key_message& attest_key, const key_message& auth_key,
        const string& measurement, vse_clause* vse_attest_clause);
bool construct_what_to_say(string& enclave_type,
      key_message& enclave_pk, string* what_to_say);
bool verify_signed_assertion_and_extract_clause(const key_message& key,
      const signed_claim_message& sc, vse_clause* cl);

bool init_certifier_rules(certifier_rules& rules);
bool init_axiom(key_message& pk, proved_statements* _proved);
bool init_proved_statements(key_message& pk, evidence_package& evp,
      proved_statements* already_proved);

bool verify_rule_1(predicate_dominance& dom_tree, const vse_clause& c1,
    const vse_clause& c2, const vse_clause& conclusion);
bool verify_rule_2(predicate_dominance& dom_tree, const vse_clause& c1,
    const vse_clause& c2, const vse_clause& conclusion);
bool verify_rule_3(predicate_dominance& dom_tree, const vse_clause& c1,
    const vse_clause& c2, const vse_clause& conclusion);
bool verify_rule_4(predicate_dominance& dom_tree, const vse_clause& c1,
    const vse_clause& c2, const vse_clause& conclusion);
bool verify_rule_5(predicate_dominance& dom_tree, const vse_clause& c1,
    const vse_clause& c2, const vse_clause& conclusion);
bool verify_rule_6(predicate_dominance& dom_tree, const vse_clause& c1,
    const vse_clause& c2, const vse_clause& conclusion);
bool verify_external_proof_step(predicate_dominance& dom_tree, proof_step& step);
bool verify_internal_proof_step(predicate_dominance& dom_tree,
        const vse_clause s1, const vse_clause s2,
        const vse_clause conclude, int rule_to_apply);

bool verify_proof(key_message& policy_pk, vse_clause& to_prove,
        predicate_dominance& dom_tree,
        proof *the_proof, proved_statements* are_proved);
bool add_fact_from_signed_claim(const signed_claim_message& signedClaim,
    proved_statements* already_proved);
bool add_newfacts_for_sdk_platform_attestation(key_message& policy_pk,
      signed_claim_sequence& trusted_platforms, signed_claim_sequence& trusted_measurements,
      proved_statements* already_proved);
bool add_new_facts_for_abbreviatedplatformattestation(key_message& policy_pk,
      signed_claim_sequence& trusted_platforms, signed_claim_sequence& trusted_measurements,
      proved_statements* already_proved);
bool construct_proof_from_sev_evidence(key_message& policy_pk, const string& purpose,
      proved_statements* already_proved, vse_clause* to_prove, proof* pf);
bool construct_proof_from_sdk_evidence(key_message& policy_pk, const string& purpose,
      proved_statements* already_proved,
      vse_clause* to_prove, proof* pf);
bool construct_proof_from_full_vse_evidence(key_message& policy_pk,
      const string& purpose, proved_statements* already_proved,
      vse_clause* to_prove, proof* pf);
bool construct_proof_from_request(const string& evidence_descriptor, key_message& policy_pk,
      const string& purpose, signed_claim_sequence& trusted_platforms,
      signed_claim_sequence& trusted_measurements, evidence_package& evp,
      proved_statements* already_proved, vse_clause* to_prove, proof* pf);
bool validate_evidence(const string& evidence_descriptor,
      signed_claim_sequence& trusted_platforms, signed_claim_sequence& trusted_measurements,
      const string& purpose, evidence_package& evp, key_message& policy_pk);

bool get_platform_from_sev_attest(const sev_attestation_message& sev_att, entity_message* ent);
bool get_measurement_from_sev_attest(const sev_attestation_message& sev_att,
      entity_message* ent);
bool filter_sev_policy(const sev_attestation_message& sev_att, const key_message& policy_pk,
        const signed_claim_sequence& policy,
        signed_claim_sequence* filtered_policy);
bool init_policy(signed_claim_sequence& policy, key_message& policy_pk,
      proved_statements* already_proved);
bool construct_proof_from_sev_evidence_with_plat(const string& evidence_descriptor,
      key_message& policy_pk, const string& purpose,
      proved_statements* already_proved, vse_clause* to_prove, proof* pf,
      // the following is temporary till we figure out the proto problem
      proof_step* pss, int* num);
bool verify_proof_from_array(key_message& policy_pk, vse_clause& to_prove,
        predicate_dominance& dom_tree,
        proved_statements* are_proved, int num_steps, proof_step* steps);
bool validate_evidence_from_policy(const string& evidence_descriptor,
        signed_claim_sequence& policy, const string& purpose,
        evidence_package& evp, key_message& policy_pk);

// -------------------------------------------------------------------

#endif
