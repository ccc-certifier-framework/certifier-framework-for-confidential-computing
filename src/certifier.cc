#include "support.h"
#include "certifier.h"
#include "simulated_enclave.h"
#include "application_enclave.h"
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>


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


// Policy store
// -------------------------------------------------------------------

void print_store(policy_store& ps) {
  printf("num_ts: %d\n", ps.num_ts_);
  printf("num_tsc: %d\n", ps.num_tsc_);
  printf("num_si: %d\n", ps.num_si_);
  printf("num_tc: %d\n", ps.num_tc_);
  printf("num_tkm: %d\n", ps.num_tkm_);
}

policy_store::policy_store() {
  policy_key_valid_ = false;

  max_num_ts_ = MAX_NUM_ENTRIES;
  max_num_tsc_ = MAX_NUM_ENTRIES;
  max_num_si_ = MAX_NUM_ENTRIES;
  max_num_tc_ = MAX_NUM_ENTRIES;
  max_num_tkm_ = MAX_NUM_ENTRIES;

  ts_ = new trusted_service_message*[max_num_ts_];
  tsc_ = new tagged_signed_claim*[max_num_tsc_];
  si_ = new storage_info_message*[max_num_si_];
  tc_ = new tagged_claim*[max_num_tc_];
  tkm_ = new channel_key_message*[max_num_tkm_];

  num_ts_ = 0;
  num_tsc_ = 0;
  num_si_ = 0;
  num_tc_ = 0;
  num_tkm_ = 0;
}

policy_store::policy_store(int max_trusted_services, int max_trusted_signed_claims,
      int max_storage_infos, int max_claims, int max_keys) {
  policy_key_valid_ = false;

  max_num_ts_ = max_trusted_services;
  max_num_tsc_ = max_trusted_signed_claims;
  max_num_si_ = max_storage_infos;
  max_num_tc_ = max_claims;
  max_num_tkm_ = max_keys;

  ts_ = new trusted_service_message*[max_num_ts_];
  tsc_ = new tagged_signed_claim*[max_num_tsc_];
  si_ = new storage_info_message*[max_num_si_];
  tc_ = new tagged_claim*[max_num_tc_];
  tkm_ = new channel_key_message*[max_num_tkm_];

  num_ts_ = 0;
  num_tsc_ = 0;
  num_si_ = 0;
  num_tc_ = 0;
  num_tkm_ = 0;
}

policy_store::~policy_store() {
  // clean up sensitive values
}

void policy_store::clear_policy_store() {
  // Todo
}

bool policy_store::replace_policy_key(key_message& k) {
  policy_key_valid_ = true;
  policy_key_.CopyFrom((const key_message)k);
  return true;
}

const key_message* policy_store::get_policy_key() {
  if (!policy_key_valid_)
    return nullptr;
  return &policy_key_;
}

int policy_store::get_num_trusted_services() {
  return num_ts_;
}

const trusted_service_message* policy_store::get_trusted_service_info_by_index(int n) {
  if (n >= num_ts_)
    return nullptr;
  return ts_[n];
}

bool policy_store::add_trusted_service(trusted_service_message& to_add) {
  if ((num_ts_+1) >= max_num_ts_)
    return true;
  trusted_service_message* t = new(trusted_service_message);
  t->CopyFrom(to_add);
  int n = num_ts_++;
  ts_[n] = t;
  return true;
}

int policy_store::get_trusted_service_index_by_tag(string tag) {
  for (int i = 0; i < num_ts_; i++) {
    if (ts_[i]->tag() == tag)
      return i;
  }
  return -1;
}

void policy_store::delete_trusted_service_by_index(int n) {
  if (n >= num_ts_)
    return;
  const trusted_service_message* deleted = get_trusted_service_info_by_index(n);
  for (int i = n; i < (num_ts_ - 1); i++)
    ts_[i] = ts_[i+1];
  num_ts_--;
  ts_[num_ts_] = nullptr;
  // clear deleted and free it
}

int policy_store::get_num_storage_info() {
  return num_si_;
}

const storage_info_message* policy_store::get_storage_info_by_index(int n) {
  if (n >= num_si_)
    return nullptr;
  return si_[n];
}

bool policy_store::add_storage_info(storage_info_message& to_add) {
  if ((num_si_ + 1) >= max_num_si_)
    return false;
  storage_info_message* t = new(storage_info_message);
  int n = num_si_++;
  si_[n] = t;
  si_[n]->CopyFrom(to_add);
  return true;
}

void policy_store::delete_storage_info_by_index(int n) {
  if (n >= num_si_)
    return;
  const storage_info_message* deleted = get_storage_info_by_index(n);
  for (int i = n; i < (num_si_ - 1); i++)
    si_[i] = si_[i+1];
  num_si_--;
  si_[num_si_] = nullptr;
  // clear deleted and free it
}

int policy_store::get_storage_info_index_by_tag(string& tag) {
  for (int i = 0; i < num_si_; i++) {
    if (si_[i]->tag() == tag)
      return i;
  }
  return -1;
}

int policy_store::get_num_claims() {
  return num_tc_;
}

const claim_message* policy_store::get_claim_by_index(int n) {
  if (n >= num_tc_)
    return nullptr;
  return &(tc_[n]->claim());
}

bool policy_store::add_claim(string& tag, const claim_message& to_add) {
  if ((num_tc_ + 1) >= max_num_tc_)
    return false;
  tagged_claim* t = new(tagged_claim);
  int n = num_tc_++;
  t->set_tag(tag);
  tc_[n] = t;
  (tc_[n]->mutable_claim())->CopyFrom(to_add);
  return true;
}

void policy_store::delete_claim_by_index(int n) {
  if (n >= num_tc_)
    return;
  const tagged_claim* deleted = tc_[n];
  for (int i = n; i < (num_tc_ - 1); i++)
    tc_[i] = tc_[i+1];
  num_tc_--;
  tc_[num_tc_] = nullptr;
  // clear deleted and free it
}

int policy_store::get_claim_index_by_tag(string& tag) { // to do
  for (int i = 0; i < num_tc_; i++) {
    if (tc_[i]->tag() == tag)
      return i;
  }
  return -1;
}

bool policy_store::add_authentication_key(string& tag, const key_message& k) {
  if ((num_tkm_ + 1) >= max_num_tkm_)
    return false;
  channel_key_message* t = new(channel_key_message);
  t->set_tag(tag);
  int n = num_tkm_++;
  tkm_[n] = t;
  tkm_[n]->mutable_auth_key()->CopyFrom(k);
  return true;
}

const key_message* policy_store::get_authentication_key_by_tag(string& tag) {
  for (int i = 0; i < num_tkm_; i++) {
    if (tkm_[i]->tag() == tag)
      return &(tkm_[i]->auth_key());
  }
  return nullptr;
}

const key_message* policy_store::get_authentication_key_by_index(int i) {
  if (i >= num_tkm_)
    return nullptr;
  return &(tkm_[i]->auth_key());
}

int policy_store::get_authentication_key_index_by_tag(string& tag) {
  for (int i = 0; i < num_tkm_; i++) {
    if (tkm_[i]->tag() == tag)
      return i;
  }
  return -1;
}

void policy_store::delete_authentication_key_by_index(int n) {
  if (n >= num_tkm_)
    return;
  const key_message* deleted = get_authentication_key_by_index(n);
  for (int i = n; i < (num_tkm_ - 1); i++)
    tkm_[i] = tkm_[i+1];
  num_tkm_--;
  tkm_[num_tkm_] = nullptr;
  // clear deleted and free it
}

bool policy_store::Serialize(string* out) {
  policy_store_message psm;

  // Copy data to psm
  if (policy_key_valid_) {
    psm.mutable_policy_key()->CopyFrom(policy_key_);
  }
  for (int i = 0; i < num_ts_; i++) {
    trusted_service_message* t = psm.add_trusted_services();
    t->CopyFrom(*ts_[i]);
  }
  for (int i = 0; i < num_tsc_; i++) {
    tagged_signed_claim* t = psm.add_signed_claims();
    t->set_tag(tsc_[i]->tag());
    t->mutable_sc()->CopyFrom(tsc_[i]->sc());
  }
  for (int i = 0; i < num_si_; i++) {
    storage_info_message* t = psm.add_storage_info();
    t->CopyFrom(*si_[i]);
  }
  for (int i = 0; i < num_tc_; i++) {
    tagged_claim* t = psm.add_claims();
    t->set_tag(tc_[i]->tag());
    t->mutable_claim()->CopyFrom(tc_[i]->claim());
  }
  for (int i = 0; i < num_tkm_; i++) {
    channel_key_message* t = psm.add_channel_authentication_keys();
    t->set_tag(tkm_[i]->tag());
    t->mutable_auth_key()->CopyFrom(tkm_[i]->auth_key());
  }

  if (!psm.SerializeToString(out))
    return false;

  return true;
}

bool policy_store::Deserialize(string& in) {
  policy_store_message psm;

  if (!psm.ParseFromString(in))
    return false;

  // Copy data to psm
  if (psm.has_policy_key()) {
    policy_key_valid_ = true;
    policy_key_.CopyFrom(psm.policy_key());
  } else
    policy_key_valid_ = false;

  num_ts_ = psm.trusted_services_size();
  for (int i = 0; i < num_ts_; i++) {
    trusted_service_message* t = new(trusted_service_message);
    t->set_tag(psm.trusted_services(i).tag());
    t->CopyFrom(psm.trusted_services(i));
    ts_[i] = t;
  }
  num_tsc_ = psm.signed_claims_size();
  for (int i = 0; i < num_tsc_; i++) {
    tagged_signed_claim* t = new(tagged_signed_claim);
    t->set_tag(psm.signed_claims(i).tag());
    t->mutable_sc()->CopyFrom(psm.signed_claims(i).sc());
    tsc_[i]= t;
  }
  num_si_ = psm.storage_info_size();
  for (int i = 0; i < num_si_; i++) {
    storage_info_message* t = new(storage_info_message);
    t->CopyFrom(psm.storage_info(i));
    si_[i]= t;
  }
  num_tc_ = psm.claims_size();
  for (int i = 0; i < num_tc_; i++) {
    tagged_claim* t = new(tagged_claim);
    t->set_tag(psm.claims(i).tag());
    t->mutable_claim()->CopyFrom(psm.claims(i).claim());
    tc_[i] = t;
  }
  num_tkm_ = psm.channel_authentication_keys_size();
  for (int i = 0; i < num_tkm_; i++) {
    channel_key_message* t = new(channel_key_message);
    t->set_tag(psm.channel_authentication_keys(i).tag());
    t->mutable_auth_key()->CopyFrom(psm.channel_authentication_keys(i).auth_key());
    tkm_[i] = t;
  }

  return true;
}

const signed_claim_message* policy_store::get_signed_claim_by_index(int n) {
  if (n >= num_tsc_)
    return nullptr;
  return &(tsc_[n]->sc());
}

bool policy_store::add_signed_claim(string& tag, const signed_claim_message& to_add) {
  if ((num_tsc_ + 1) >= max_num_tsc_)
    return false;
  tagged_signed_claim* t = new(tagged_signed_claim);
  t->set_tag(tag);
  int n = num_tsc_++;
  tsc_[n] = t;
  tsc_[n]->mutable_sc()->CopyFrom(to_add);
  return true;
}

int policy_store::get_signed_claim_index_by_tag(string& tag) {
  for (int i = 0; i < num_tsc_; i++) {
    if (tsc_[i]->tag() == tag)
      return i;
  }
  return -1;
}

void policy_store::delete_signed_claim_by_index(int n) {
  if (n >= num_tsc_)
    return;
  const signed_claim_message* deleted = get_signed_claim_by_index(n);
  for (int i = n; i < (num_tsc_ - 1); i++)
    tsc_[i] = tsc_[i+1];
  num_tsc_--;
  tsc_[num_tsc_] = nullptr;
  // clear deleted and free it
}


// -------------------------------------------------------------------

// Trusted primitives
// -------------------------------------------------------------------

bool construct_what_to_say(string& enclave_type,
      key_message& attest_pk, key_message& enclave_pk,
      string& expected_measurement, string* what_to_say) {

  if (enclave_type == "simulated-enclave") {
    // attestation-key says enclave-authentication-key speaks-for enclave-measurement
    string descript("test-attest");
    string enclave_id("test-simulated-enclave");
    int size_out = 8192;
    byte attest_out[size_out];
    string final_serialized_attest;
    string serialized_attest;
    vse_clause c;
    vse_clause attest_statement;
    entity_message measurement_entity;
    entity_message attest_key_entity;
    entity_message enclave_key_entity;

    if (!make_key_entity(attest_pk, &attest_key_entity))
      return false;
    if (!make_key_entity(enclave_pk, &enclave_key_entity))
      return false;
    if (!make_measurement_entity(expected_measurement, &measurement_entity))
      return false;
    string sf_verb("speaks-for");
    if (!make_simple_vse_clause(enclave_key_entity, sf_verb, measurement_entity, &c))
      return false;
    string says_verb("says");
    if (!make_indirect_vse_clause(attest_key_entity, says_verb, c, &attest_statement))
      return false;

    if (!vse_attestation(descript, enclave_type, enclave_id,
          attest_statement, what_to_say))
      return false;
    } else if (enclave_type == "oe-enclave") {
      if (!enclave_pk.SerializeToString(what_to_say))
        return false;
    } else {
      return false;
    }
  return true;
}

#ifdef SEV_SNP
extern bool sev_Getmeasurement(int* size_out, byte* out);
extern bool sev_Seal(int in_size, byte* in, int* size_out, byte* out);
extern bool sev_Unseal(int in_size, byte* in, int* size_out, byte* out);
extern bool sev_Attest(int what_to_say_size, byte* what_to_say,
    int* size_out, byte* out);
#endif

bool Seal(const string& enclave_type, const string& enclave_id,
 int in_size, byte* in, int* size_out, byte* out) {

  if (enclave_type == "simulated-enclave") {
   return simulated_Seal(enclave_type, enclave_id,
       in_size, in, size_out, out);
  }
#ifdef OE_CERTIFIER
  if (enclave_type == "oe-enclave") {
   return oe_Seal (POLICY_UNIQUE, in_size, in, 0, NULL, size_out, out);
  }
#endif
#ifdef SEV_SNP
  if (enclave_type == "sev-snp") {
   return sev_Seal(in_size, in, size_out, out);
  }
#endif
 return false;
}

bool Unseal(const string& enclave_type, const string& enclave_id,
 int in_size, byte* in, int* size_out, byte* out) {

  if (enclave_type == "simulated-enclave") {
   return simulated_Unseal(enclave_type, enclave_id,
       in_size, in, size_out, out);
  }
#ifdef OE_CERTIFIER
  if (enclave_type == "oe-enclave") {
   return oe_Unseal (in_size, in, 0, NULL, size_out, out);
  }
#endif
#ifdef SEV_SNP
  if (enclave_type == "sev-snp") {
    return sev_Unseal(in_size, in, size_out, out);
  }
#endif
 return false;
}

bool Attest(const string& enclave_type, int what_to_say_size, byte* what_to_say,
 int* size_out, byte* out) {

  if (enclave_type == "simulated-enclave") {
    return simulated_Attest(enclave_type, what_to_say_size, what_to_say,
       size_out, out);
  }
#ifdef OE_CERTIFIER
  if (enclave_type == "oe-enclave") {
    return oe_Attest(what_to_say_size, what_to_say, size_out, out);
  }
#endif
#ifdef SEV_SNP
  if (enclave_type == "sev-snp") {
    return sev_Attest(what_to_say_size, what_to_say, size_out, out);
  }
#endif

 return false;
}

bool Getmeasurement(const string& enclave_type, const string& enclave_id,
  int* size_out, byte* out) {

  // TODO: We cannot assume the Getmeasurement interface. We do need a
  // unified Certifier attestation report. But the measurement field has
  // to be filled it after Attest at the earliest. We should actually
  // consider doing it after calling SDK Verify since that guarantees
  // that both measurement and custom claims are verified anyway.
  if (enclave_type == "simulated-enclave" || enclave_type == "oe-enclave") {
    return simulated_Getmeasurement(size_out, out);
  }
#ifdef SEV
  if (enclave_type == "simulated-enclave" || enclave_type == "oe-enclave") {
    return simulated_Getmeasurement(size_out, out);
  }
#endif
  return false;
}

// -------------------------------------------------------------------

// Protect Support
// -------------------------------------------------------------------

bool Protect_Blob(const string& enclave_type, key_message& key,
  int size_unencrypted_data, byte* unencrypted_data,
  int* size_protected_blob, byte* blob) {

  // for now, no encryption
  string serialized_key;
  if (!key.SerializeToString(&serialized_key))
    return false;

  int size_sealed_key = serialized_key.size() + 128;
  byte sealed_key[size_sealed_key];
  memset(sealed_key, 0, size_sealed_key);
  string enclave_id("enclave-id");

  if (!Seal(enclave_type, enclave_id, serialized_key.size(), (byte*)serialized_key.data(),
        &size_sealed_key, sealed_key)) {
    printf("Protect_Blob, error 1\n");
    return false;
  }

  byte iv[block_size];
  if (!get_random(8 * block_size, iv)) {
    printf("Protect_Blob, error 2\n");
    return false;
  }

  if (key.key_type() != "aes-256-cbc-hmac-sha256") {
    printf("Protect_Blob, error 3\n");
    return false;
  }
  if (!key.has_secret_key_bits()) {
    printf("Protect_Blob, error 4\n");
    return false;
  }
  byte* key_buf = (byte*)key.secret_key_bits().data();
  if (key.secret_key_bits().size() < 64) {
    printf("Protect_Blob, error 5\n");
    return false;
  }

  int size_encrypted = size_unencrypted_data + 128;
  byte encrypted_data[size_encrypted];
  if (!authenticated_encrypt(unencrypted_data, size_unencrypted_data, key_buf,
            iv, encrypted_data, &size_encrypted)) {
    printf("Protect_Blob, error 6\n");
    return false;
  }
  
  protected_blob_message blob_msg;
  blob_msg.set_encrypted_key((void*)sealed_key, size_sealed_key);
  blob_msg.set_encrypted_data((void*)encrypted_data, size_encrypted);

  string serialized_blob;
  blob_msg.SerializeToString(&serialized_blob);
  if (((int)serialized_blob.size()) > *size_protected_blob) {
    printf("Protect_Blob, error 8\n");
    return false;
  }
  *size_protected_blob = (int)serialized_blob.size();
  memcpy(blob, (byte*)serialized_blob.data(), *size_protected_blob);
  return true;
}

bool Unprotect_Blob(const string& enclave_type, int size_protected_blob,
      byte* protected_blob, key_message* key, int* size_of_unencrypted_data,
      byte* unencrypted_data) {

  // for now, no encryption
  string protected_blob_string;
  protected_blob_string.assign((char*)protected_blob, size_protected_blob);
  protected_blob_message pb;
  if (!pb.ParseFromString(protected_blob_string)) {
    printf("Unprotect_Blob error 1\n");
    return false;
  }
  if (!pb.has_encrypted_key()) {
    printf("Unprotect_Blob error 2\n");
    return false;
  }
  if (!pb.has_encrypted_data()) {
    printf("Unprotect_Blob error 3\n");
    return false;
  }

  int size_unsealed_key = pb.encrypted_key().size();
  byte unsealed_key[size_unsealed_key];
  memset(unsealed_key, 0, size_unsealed_key);
  string enclave_id("enclave-id");

  // Unseal header
  if (!Unseal(enclave_type, enclave_id, pb.encrypted_key().size(), (byte*)pb.encrypted_key().data(),
        &size_unsealed_key, unsealed_key)) {
    printf("Unprotect_Blob error 4\n");
    return false;
  }

  string serialized_key;
  serialized_key.assign((const char*)unsealed_key, size_unsealed_key);
  if (!key->ParseFromString(serialized_key)) {
    printf("Unprotect_Blob error 5\n");
    return false;
  }

  if (key->key_type() != "aes-256-cbc-hmac-sha256") {
    printf("Unprotect_Blob error 6\n");
    return false;
  }
  if (!key->has_secret_key_bits()) {
    printf("Unprotect_Blob error 7\n");
    return false;
  }
  byte* key_buf = (byte*)key->secret_key_bits().data();
  if (key->secret_key_bits().size() < 64) {
    printf("Unprotect_Blob error 8\n");
    return false;
  }

  // decrypt encrypted data
  if (!authenticated_decrypt((byte*)pb.encrypted_data().data(), pb.encrypted_data().size(), key_buf,
            unencrypted_data, size_of_unencrypted_data)) {
    printf("Unprotect_Blob error 9\n");
    return false;
  }
  return true;
}

// -------------------------------------------------------------------

// Claims and proofs
// -------------------------------------------------------------------

/*
  Certifier proofs

  Rules
    rule 1 (R1): If measurement is-trusted and key1 speaks-for measurement then
        key1 is-trusted-for-authentication.
    rule 2 (R2): If key2 speaks-for key1 and key3 speaks-for key2 then key3 speaks-for key1
    rule 3 (R3): If key1 is-trusted and key1 says X, then X is true
    rule 4 (R4): If key2 speaks-for key1 and key1 is-trusted then key2 is-trusted
    rule 5 (R5): If key1 is-trustedXXX and key1 says key2 is-trustedYYY then key2 is-trustedYYY
          provided is-trustedXXX dominates is-trustedYYY
    rule 6 (R6): if key1 is-trustedXXX and key1 says key2 speaks-for measurement then
        key2 speaks-for measurement
          provided is-trustedXXX dominates is-trusted-for-attestation

  A statement, X, signed by entity1 is the same as entity1 says X

  Axioms
    axiom 1 (A1): policy-key is-trusted

  To prove: enclave-authentication-key is-trusted
  Claims asserted
    claim 1 (C1): policy-key says enclave-measurement is-trusted
    claim 2 (C2): policy-key says intel-key is-trusted
    claim 3 (C3): intel-key says attestation-key is-trusted
    claim 4 (C4): attestation-key says enclave-authentication-key speaks-for enclave-measurement
  Proof:
      A1+C2 via R3 --> claim 5 (C5): intel-key is-trusted
      C3+C5 via R3 --> claim 6 (C6): attestation-key is-trusted
      C4+C6 via R3 --> claim 7 (C7): enclave-authentication-key speaks-for enclave-measurement
      A1+C1 via R3 --> claim 8 (C8): enclave-measurement is-trusted
      C8+C7 via R1 --> claim 9 (C9) enclave-authentication-key is-trusted
 */


predicate_dominance::predicate_dominance() {
  first_child_ = nullptr;
  next_ = nullptr;
}

predicate_dominance::~predicate_dominance() {
  predicate_dominance* current = first_child_;
  while (current != nullptr) {
    delete current->next_;
    current = current->next_;
  }
  first_child_ = nullptr;
  next_ = nullptr;
}

predicate_dominance* predicate_dominance::find_node(const string& pred) {

  if (predicate_ ==  pred)
    return this;

  predicate_dominance* current = first_child_;
  predicate_dominance* t = nullptr;

  // breadth first search
  while (current != nullptr) {
    t = find_node(pred);
    if (t != nullptr)
      return t;
    current = current->next_;
  }

  // try children
  current = first_child_;
  while (current != nullptr) {
    t = current->find_node(pred);
    if (t != nullptr)
      return t;
    current = current->next_;
  }

  return nullptr;
}


// initial root must exist
bool predicate_dominance::insert(const string& parent, const string& descendant) {

  predicate_dominance* t = find_node(parent);
  if (t == nullptr)
    return false;
  if (dominates(*t, parent, descendant))
    return true;

  predicate_dominance* to_add = new(predicate_dominance);
  to_add->predicate_.assign(descendant);

  to_add->next_ = t->first_child_;
  t->first_child_= to_add;
  return true;
}

bool predicate_dominance::is_child(const string& descendant) {
  predicate_dominance* current = first_child_;

  while (current != nullptr) {
    if (current->predicate_ == descendant)
      return true;
    current = current->next_;
  }

  current = first_child_;
  while (current != nullptr) {
    if (current->is_child(descendant))
      return true;
    current = current->next_;
  }
  return false;
}

static void indent_spaces(int indent) {
  for (int i = 0; i < indent; i++)
    printf(" ");
}

void predicate_dominance::print_tree(int indent) {
  print_node(indent);
  print_descendants(indent + 2);
}

void predicate_dominance::print_node(int indent) {
  indent_spaces(indent);
  printf("Predicate: %s\n", predicate_.c_str());
}

void predicate_dominance::print_descendants(int indent) {
  predicate_dominance* current = first_child_;
  while (current != nullptr) {
    current->print_tree(indent);
    current = current->next_;
  }
}

bool dominates(predicate_dominance& root, const string& parent, const string& descendant) {
  if (parent == descendant)
    return true;
  predicate_dominance* pn = root.find_node(parent);
  if (pn == nullptr)
    return false;
  return pn->is_child(descendant);
}

bool init_certifier_rules(certifier_rules& rules) {
  string* r1 =  rules.add_rule();
  string* r2 =  rules.add_rule();
  string* r3 =  rules.add_rule();
  string* r4 =  rules.add_rule();
  string* r5 =  rules.add_rule();
  string* r6 =  rules.add_rule();
  r1->assign("If measurement is-trusted and key1 speaks-for measurement then key1 is-trusted-for-authentication.");
  r2->assign("If key2 speaks-for key1 and key3 speaks-for key2 then key3 speaks-for key1.");
  r3->assign("If key1 is-trusted and key1 says X, then X is true.");
  r4->assign("If key2 speaks-for key1 and key1 is-trusted then key2 is-trusted.");
  r5->assign("If key1 is-trusted-for-a-purpose and key1 says key2 is-trusted-for-another-purpose then key2 is-trusted-for-another-purpose, if is-trusted-for-a-purpose dominate is-trusted-for-another-purpose.");
  r6->assign("If key1 is-trusted-for-a-purpose and key1 says key2 speaks-for measurement provided is-trusted-for-a-purpose dominates is-trusted-for-attestation.");
  return true;
}

bool convert_attestation_to_vse_clause(const claim_message& asserted_claim, vse_clause* cl) {
  
  string serialized_attestation;
  serialized_attestation.assign((char*)asserted_claim.serialized_claim().data(), (int)asserted_claim.serialized_claim().size());
  attestation at;
    if (!at.ParseFromString(serialized_attestation))
      return false;
  // in the future the attestation may not be in vse-clauses in some cases
  cl->CopyFrom(at.clause());;
  return true;
}

bool verify_signed_assertion_and_extract_clause(const key_message& key,
      const signed_claim_message& sc, vse_clause* cl) {

  if (!sc.has_serialized_claim_message() || !sc.has_signing_key() ||
      !sc.has_signing_algorithm() || !sc.has_signature())
    return false;

  // Deserialize claim to get clasue
  string serialized_claim_string;
  claim_message asserted_claim;
  serialized_claim_string.assign((char*)sc.serialized_claim_message().data(), (int)sc.serialized_claim_message().size());
  if (!asserted_claim.ParseFromString(serialized_claim_string))
    return false;

  if (!asserted_claim.has_claim_format())
    return false;

  if (asserted_claim.claim_format() == "vse-clause") {

    string serialized_vse_string;
    vse_clause asserted_vse;
    serialized_vse_string.assign((char*)asserted_claim.serialized_claim().data(), (int)asserted_claim.serialized_claim().size());
    if (!asserted_vse.ParseFromString(serialized_vse_string))
      return false;
    cl->CopyFrom(asserted_vse);
  } else if (asserted_claim.claim_format() == "vse-attestation") {
    if (!convert_attestation_to_vse_clause(asserted_claim, cl))
      return false;
  } else {
    return false;
  }

  // verify signature
  return verify_signed_claim(sc, key);
}

static const int num_is_trusted_kids = 2;
static const char* kids[2] = {
  "is-trusted-for-attestation",
  "is-trusted-for-authentication",
};
bool init_dominance_tree(predicate_dominance& root) {
  root.predicate_.assign("is-trusted");

  string descendant;
  for (int i = 0; i < num_is_trusted_kids; i++) {
    descendant.assign(kids[i]);
    if (!root.insert(root.predicate_, descendant))
      return false;
  }

  return true;
}

bool init_axiom(key_message& pk, proved_statements* are_proved) {
  // Add axiom pk is-trusted
  entity_message policy_key_entity;
  vse_clause axiom;
  if (!make_key_entity(pk, &policy_key_entity))
    return false;
  string is_trusted_verb("is-trusted");
  if (!make_unary_vse_clause(policy_key_entity, is_trusted_verb, &axiom))
    return false;
  vse_clause* to_insert = are_proved->add_proved();
  to_insert->CopyFrom(axiom);
  return true;
}

bool init_proved_statements(key_message& pk, evidence_package& evp,
      proved_statements* already_proved) {

  // verify already signed assertions, converting to vse_clause
  int nsa = evp.fact_assertion_size();
  for (int i = 0; i < nsa; i++) {
    if (evp.fact_assertion(i).evidence_type() == "signed-claim") {
      signed_claim_message sc;
      string t_str;
      t_str.assign((char*)evp.fact_assertion(i).serialized_evidence().data(),
          evp.fact_assertion(i).serialized_evidence().size());
      if (!sc.ParseFromString(t_str))
        return false;

      vse_clause to_add;
      const key_message& km= sc.signing_key();

      if (!verify_signed_assertion_and_extract_clause(km, sc, &to_add)) {
        printf("signed claim %d failed\n", i);
        return false;
      }
      // We can only add Key says statements and we must make
      // sure the subject of says is the signing key
      if (!to_add.has_subject() || !to_add.has_verb() || to_add.verb() != "says")
        return false;
      if (to_add.subject().entity_type() != "key")
        return false;
      const key_message& ks = to_add.subject().key();
      if (!same_key(km, ks)) {
        // wrong key signed message
        return false;
      }
      vse_clause* cl_to_insert = already_proved->add_proved();
      cl_to_insert->CopyFrom(to_add);
#ifdef OE_CERTIFIER
    } else if (evp.fact_assertion(i).evidence_type() == "oe-assertion") {
      size_t user_data_size = 4096;
      byte user_data[user_data_size];
      size_t measurement_out_size = 256;
      byte measurement_out[measurement_out_size];

      if (!oe_Verify((byte *)evp.fact_assertion(i).serialized_evidence().data(),
                     evp.fact_assertion(i).serialized_evidence().size(),
                     user_data, &user_data_size, measurement_out, &measurement_out_size)) {
        printf("init_proved_statements: oe_Verify failed\n");
        return false;
      }

      // user_data should be a serialized key
      key_message km;
      string km_str;
      km_str.assign((char*)user_data, user_data_size);
      if (!km.ParseFromString(km_str))
        return false;

      // construct vse-clause (key speaks-for measurement)
      entity_message* key_ent = new(entity_message);
      if (!make_key_entity(km, key_ent)) {
        printf("init_proved_statements: make_key_entity failed\n");
        return false;
      }
      entity_message* measurement_ent = new(entity_message);
      string m;
      m.assign((char*)measurement_out, measurement_out_size);
      if (!make_measurement_entity(m, measurement_ent)) {
        printf("init_proved_statements: make_measurement_entity failed\n");
        return false;
      }
      vse_clause* cl_to_insert = already_proved->add_proved();
      string sf("speaks-for");
      if (!make_simple_vse_clause(*key_ent, sf, *measurement_ent, cl_to_insert)) {
        printf("init_proved_statements: make_simple_vse_clause failed\n");
        return false;
      }
#endif
    } else {
      return false;
    }
  }
  return true;
}

// R1: If measurement is-trusted and key1 speaks-for measurement then
//    key1 is-trusted-for-authentication.
bool verify_rule_1(predicate_dominance& dom_tree, const vse_clause& c1,
        const vse_clause& c2, const vse_clause& conclusion) {

  // Make sure clauses are in the right form.
  if (!c1.has_subject() || !c1.has_verb())
    return false;
  if (c1.has_object() || c1.has_clause())
    return false;
  if (c1.verb() != "is-trusted")
    return false;
  if (c1.subject().entity_type() != "measurement")
    return false;

  if (!c2.has_subject() || !c2.has_verb())
    return false;
  if (c2.verb() != "speaks-for")
    return false;
  if (!c2.has_object() || c2.has_clause())
    return false;
  if (c2.object().entity_type() != "measurement")
    return false;
  if (!same_entity(c1.subject(), c2.object()))
    return false;

  // Make sure subject of conclusion is subject of c2 and verb "is-trusted"
  if (!conclusion.has_subject() || !conclusion.has_verb() || 
       conclusion.has_object() || conclusion.has_clause())
    return false;
  if (conclusion.verb() != "is-trusted" &&
      conclusion.verb() != "is-trusted-for-authentication")
    return false;

  return same_entity(conclusion.subject(), c2.subject());
}

// R2: If key2 speaks-for key1 and key3 speaks-for key2 then key3 speaks-for key1
bool verify_rule_2(predicate_dominance& dom_tree, const vse_clause& c1,
        const vse_clause& c2, const vse_clause& conclusion) {
  return false;
}

// R3: If key1 is-trusted and key1 says X, then X is true
bool verify_rule_3(predicate_dominance& dom_tree, const vse_clause& c1, const vse_clause& c2, const vse_clause& conclusion) {
  if (!c1.has_subject() || !c1.has_verb())
    return false;
  if (c1.has_object() || c1.has_clause())
    return false;
  if (c1.verb() != "is-trusted")
    return false;

  if (!c2.has_subject() || !c2.has_verb())
    return false;
  if (c2.has_object() || !c2.has_clause())
    return false;
  if (c2.verb() != "says")
    return false;
  if (!same_entity(c1.subject(), c2.subject()))
    return false;
  return same_vse_claim(c2.clause(), conclusion);
}

// R4: If key2 speaks-for key1 and key1 is-trustedXXX then key2 is-trustedXXX
bool verify_rule_4(predicate_dominance& dom_tree, const vse_clause& c1,
    const vse_clause& c2, const vse_clause& conclusion) {
  return false;
}

// R5: If key1 is-trustedXXX and key1 says key2 is-trustedYYY then then key2 is-trustedYYY
//    provided is-trustedXXX dominates is-trustedYYY
bool verify_rule_5(predicate_dominance& dom_tree, const vse_clause& c1,
      const vse_clause& c2, const vse_clause& conclusion) {

  if (!c1.has_subject() || !c1.has_verb())
    return false;
  if (c1.has_object() || c1.has_clause())
    return false;

  if (!c2.has_subject() || !c2.has_verb())
    return false;
  if (c2.verb() != "says")
    return false;
  if (c2.has_object() || !c2.has_clause())
    return false;

  if (!same_entity(c1.subject(), c2.subject()))
    return false;

  if (!c2.clause().has_subject() || !c2.clause().has_verb())
    return false;
  if (c2.clause().has_object() || c2.clause().has_clause())
    return false;

  if (!dominates(dom_tree, c1.verb(), c2.clause().verb()))
    return false;
  return same_vse_claim(c2.clause(), conclusion);
}

// R6: if key1 is-trustedXXX and key1 says key2 speaks-for measurement then
//  key2 speaks-for measurement
//      provided is-trustedXXX dominates is-trusted-for-attestation
bool verify_rule_6(predicate_dominance& dom_tree, const vse_clause& c1,
      const vse_clause& c2, const vse_clause& conclusion) {

  if (!c1.has_subject() || !c1.has_verb())
    return false;
  if (c1.has_object() || c1.has_clause())
    return false;
  string p1 = c1.verb();

  if (!c2.has_subject() || !c2.has_verb())
    return false;
  if (c2.has_object() || !c2.has_clause())
    return false;
  if (c2.verb() != "says")
    return false;

  if (!c2.clause().has_subject() || !c2.clause().has_verb())
    return false;
  if (!c2.clause().has_object() || c2.clause().has_clause())
    return false;
  if (c2.clause().verb() != "speaks-for")
    return false;

  if (c2.clause().subject().entity_type() != "key")
    return false;
  if (c2.clause().object().entity_type() != "measurement")
    return false;

  if (!same_entity(c1.subject(), c2.subject()))
    return false;

  string p2("is-trusted-for-attestation");
  if (!dominates(dom_tree, c1.verb(), p2))
    return false;

  return same_vse_claim(c2.clause(), conclusion);
}

bool verify_external_proof_step(predicate_dominance& dom_tree, proof_step& step) {
  if (!step.has_rule_applied())
    return false;
  if (!step.has_s1() || !step.has_s2()|| !step.has_conclusion())
    return false;
  switch(step.rule_applied()) {
    default:
      return false;
  case 1:
    return verify_rule_1(dom_tree, step.s1(), step.s2(), step.conclusion());
  case 2:
    return verify_rule_2(dom_tree, step.s1(), step.s2(), step.conclusion());
  case 3:
    return verify_rule_3(dom_tree, step.s1(), step.s2(), step.conclusion());
  case 4:
    return verify_rule_4(dom_tree, step.s1(), step.s2(), step.conclusion());
  case 5:
    return verify_rule_5(dom_tree, step.s1(), step.s2(), step.conclusion());
  case 6:
    return verify_rule_6(dom_tree, step.s1(), step.s2(), step.conclusion());
  }
  return false;
}

char hex_digit(byte v) {
  if (v >= 0 && v <= 9)
    return '0' + v;
  if (v >= 10 && v <= 15)
    return 'a' + v - 10;
  return ' ';
}

bool make_enclave_name(string enclave_type, string* enclave_name) {
  int measurement_size = 32;
  byte m[measurement_size];
  string enclave_id;
  if (!Getmeasurement(enclave_type, enclave_id, &measurement_size, m))
    return false;
  char hex[65];
  int pos = 0;
  hex[64] = 0;
  for (int i = 0; i < measurement_size; i++) {
    hex[2*i] = hex_digit(m[i]>>4);
    hex[2*i + 1] = hex_digit(m[i]&0xff);
  }
  enclave_name->append((const char*)hex);
 return true; 
}

bool verify_internal_proof_step(predicate_dominance& dom_tree,
      vse_clause s1, vse_clause s2, vse_clause conclude, int rule_to_apply) {
  if (rule_to_apply < 1 || rule_to_apply > 6)
    return false;
  switch(rule_to_apply) {
    default:
      return false;
    case 1:
      return verify_rule_1(dom_tree, s1, s2, conclude);
    case 2:
      return verify_rule_2(dom_tree, s1, s2, conclude);
    case 3:
      return verify_rule_3(dom_tree, s1, s2, conclude);
    case 4:
      return verify_rule_4(dom_tree, s1, s2, conclude);
    case 5:
      return verify_rule_5(dom_tree, s1, s2, conclude);
    case 6:
      return verify_rule_6(dom_tree, s1, s2, conclude);
  }
  return true;
}

bool statement_already_proved(const vse_clause& cl, proved_statements* are_proved) {
 int n = are_proved->proved_size();
 for (int i = 0; i < n; i++) {
   const vse_clause& in_list = are_proved->proved(i);
   if (same_vse_claim(cl, in_list))
     return true;
  }
  return false;
}

bool verify_proof(key_message& policy_pk, vse_clause& to_prove,
        predicate_dominance& dom_tree,
        proof *the_proof, proved_statements* are_proved) {

  // verify proof
  for (int i = 0; i < the_proof->steps_size(); i++) {
    bool success;
    if (!statement_already_proved(the_proof->steps(i).s1(), are_proved))

    if (!statement_already_proved(the_proof->steps(i).s2(), are_proved))
      return false;
    success = verify_internal_proof_step(dom_tree,
              the_proof->steps(i).s1(), the_proof->steps(i).s2(),
              the_proof->steps(i).conclusion(), the_proof->steps(i).rule_applied());
    if (!success) {
      printf("Proof step %d failed\n", i);
      return false;
    }
    vse_clause* to_add = are_proved->add_proved();
    to_add->CopyFrom(the_proof->steps(i).conclusion());
  }

  int n = are_proved->proved_size();
  if (n < 1)
    return false;
  const vse_clause& last_proved = are_proved->proved(n-1);
  return same_vse_claim(to_prove, last_proved);
}

// -------------------------------------------------------------------

// Certify API
// -------------------------------------------------------------------

bool add_fact_from_signed_claim(signed_claim_message& signed_claim, proved_statements* already_proved) {

  const key_message& k = signed_claim.signing_key();
  vse_clause tcl;
  if (verify_signed_assertion_and_extract_clause(k, signed_claim, &tcl)) {
    if (tcl.verb() != "says" || tcl.subject().entity_type() != "key") {
      printf("Error 1 in add_fact_from_signed_claim\n");
      return false;
    }
    if (!same_key(k, tcl.subject().key())) {
      printf("Error 2 in add_fact_from_signed_claim\n");
      return false;
    }
    vse_clause* c = already_proved->add_proved();
    c->CopyFrom(tcl);
    return true;
  }
  return false;
}

bool get_vse_clause_from_signed_claim(const signed_claim_message& scm, vse_clause* c) {
  string serialized_cl;
  serialized_cl.assign((char*)scm.serialized_claim_message().data(), scm.serialized_claim_message().size());
  claim_message cm;
  if (!cm.ParseFromString(serialized_cl))
    return false;
  if (cm.claim_format() != "vse-clause")
    return false;

  string vse_cl_str;
  vse_cl_str.assign((char*)cm.serialized_claim().data(), cm.serialized_claim().size());
  vse_clause vse;
  if (!c->ParseFromString(vse_cl_str))
    return false;

  return true;
}

bool get_signed_measurement_claim_from_trusted_list(
        string& expected_measurement,
        signed_claim_sequence& trusted_measurements,
        signed_claim_message* claim) {

  for (int i= 0; i < trusted_measurements.claims_size(); i++) {
    vse_clause c;
    if (!get_vse_clause_from_signed_claim(trusted_measurements.claims(i), &c)) {
      continue;
    }
    string says_verb("says");
    string it_verb("is-trusted");
    if (c.verb() != says_verb) {
      continue;
    }
    // policy-key says measurement is-trusted
    if (!c.has_clause() || c.verb() != says_verb) {
      continue;
    }
    if (c.clause().verb() != it_verb || !c.clause().has_subject()) {
      continue;
    }
    if (c.clause().subject().entity_type() != "measurement") {
      continue;
    }
    if (memcmp(c.clause().subject().measurement().data(),
            (byte*) expected_measurement.data(), expected_measurement.size()) == 0) {
      claim->CopyFrom(trusted_measurements.claims(i));
      return true;
    }
  }
  return false;
}

bool get_signed_platform_claim_from_trusted_list(
        const key_message& expected_key,
        signed_claim_sequence& trusted_platforms,
        signed_claim_message* claim) {

  for (int i= 0; i < trusted_platforms.claims_size(); i++) {
    vse_clause c;
    if (!get_vse_clause_from_signed_claim(trusted_platforms.claims(i), &c))
      continue;
    string says_verb("says");
    string it_verb("is-trusted");
    if (c.verb() != says_verb)
      continue;
    // policy-key says platform-key is-trusted
    if (!c.has_clause() || c.verb() != says_verb)
      continue;
    if (c.clause().verb() != it_verb || !c.clause().has_subject())
      continue;
    if (c.clause().subject().entity_type() != "key")
      continue;
    if (same_key(c.clause().subject().key(), expected_key)) {
      claim->CopyFrom(trusted_platforms.claims(i));
      return true;
    }
  }
  return false;
}

bool add_newfacts_for_oeplatform_attestation(key_message& policy_pk,
      signed_claim_sequence& trusted_platforms, signed_claim_sequence& trusted_measurements,
      proved_statements* already_proved) {
  // At this point, the already_proved should be
  //      "policyKey is-trusted"
  //      "platformKey says attestationKey is-trusted
  //      "enclaveKey speaks-for measurement"
  // Add
  //   "policyKey says measurement is-trusted"
  if (!already_proved->proved(2).has_object()) {
    printf("Error 1, add_newfacts_for_oeplatform_attestation\n");
    return false;
  }

  // "enclaveKey speaks-for measurement"
  string expected_measurement;
  if (!already_proved->proved(2).has_object())
    return false;
  const entity_message& m_ent = already_proved->proved(2).object();
  expected_measurement.assign((char*)m_ent.measurement().data(), m_ent.measurement().size());
  signed_claim_message sc;
  if (!get_signed_measurement_claim_from_trusted_list(expected_measurement,
        trusted_measurements, &sc))
    return false;
  if (!add_fact_from_signed_claim(sc, already_proved))
    return false;

  return true;
}

bool add_new_facts_for_abbreviatedplatformattestation(key_message& policy_pk,
      signed_claim_sequence& trusted_platforms, signed_claim_sequence& trusted_measurements,
      proved_statements* already_proved) {

  // At this point, the already_proved should be
  //    "policyKey is-trusted"
  //    "platformKey says attestationKey is-trusted
  //    "attestKey says enclaveKey speaks-for measurement
  // Add
  //    "policyKey says measurement is-trusted"
  //    "policyKey says platformKey is-trusted"
  //    TODO: change last one to "policyKey says platformKey is-trusted-for-attestation"

  // "attestKey says enclaveKey speaks-for measurement
  string expected_measurement;
  if (!already_proved->proved(2).has_clause()) {
    return false;
  }
  if (!already_proved->proved(2).clause().has_object()) {
    return false;
  }
  const entity_message& m_ent = already_proved->proved(2).clause().object();
  expected_measurement.assign((char*)m_ent.measurement().data(), m_ent.measurement().size());
  signed_claim_message sc;
  if (!get_signed_measurement_claim_from_trusted_list(expected_measurement,
        trusted_measurements, &sc)) {
    return false;
  }
  if (!add_fact_from_signed_claim(sc, already_proved)) {
    return false;
  }

  // "platformKey says attestationKey is-trusted
  if (!already_proved->proved(1).has_subject()) {
    return false;
  }
  if (already_proved->proved(1).subject().entity_type() != "key") {
    return false;
  }
  const key_message& expected_key = already_proved->proved(1).subject().key();
  if (!get_signed_platform_claim_from_trusted_list(expected_key,
        trusted_platforms, &sc)) {
    return false;
  }
  if (!add_fact_from_signed_claim(sc, already_proved)) {
    return false;
  }

  return true;
}

bool construct_proof_from_oeevidence(key_message& policy_pk,
      proved_statements* already_proved,
      vse_clause* to_prove, proof* pf) {

  // At this point, the already_proved should be
  //    "policyKey is-trusted"
  //    "platformKey says attestationKey is-trusted
  //    "enclaveKey speaks-for measurement"
  //    "policyKey says measurement is-trusted"

  if (!already_proved->proved(2).has_subject()) {
    printf("Error 1, construct_proof_from_oeevidence\n");
    return false;
  }
  string it("is-trusted");
  if (!make_unary_vse_clause(already_proved->proved(2).subject(), it, to_prove))
      return false;

  proof_step* ps = nullptr;

  //  "policyKey is-trusted" AND "policyKey says measurement is-trusted" --> "measurement is-trusted"
  const entity_message& m_ent = already_proved->proved(2).object();
  ps = pf->add_steps();
  ps->mutable_s1()->CopyFrom(already_proved->proved(0));
  ps->mutable_s2()->CopyFrom(already_proved->proved(3));
  ps->mutable_conclusion()->CopyFrom(already_proved->proved(3).clause());
  ps->set_rule_applied(3);
  const vse_clause& platformkey_is_trusted = ps->conclusion();

  //  "measurement is-trusted" AND "enclaveKey speaks-for measurement --> "enclaveKey is trusted"
  ps = pf->add_steps();
  ps->mutable_s1()->CopyFrom(already_proved->proved(3).clause());
  ps->mutable_s2()->CopyFrom(already_proved->proved(2));
  ps->mutable_conclusion()->CopyFrom(*to_prove);
  ps->set_rule_applied(1);

  return true;
}

// #define UNCONSTRAINED_DELEGATION
#ifdef UNCONSTRAINED_DELEGATION

// This is the olde version before trust restrictions
bool construct_proof_from_full_vse_evidence(key_message& policy_pk,
      proved_statements* already_proved, vse_clause* to_prove, proof* pf) {

  // At this point, the already_proved should be
  //      "policyKey is-trusted"
  //      "platformKey says attestKey is-trusted
  //      "attestKey says enclaveKey speaks-for measurement
  //      "policyKey says measurement is-trusted"
  //      "policyKey says platformKey is-trusted"

  if (already_proved->proved_size() != 5) {
    printf("Error 0, construct_proof_from_full_vse_evidence\n");
    return false;
  }

  if (!already_proved->proved(2).has_clause() || !already_proved->proved(2).clause().has_subject()) {
    printf("Error 1, construct_proof_from_full_vse_evidence\n");
    return false;
  }
  const entity_message& enclave_key = already_proved->proved(2).clause().subject();
  string it("is-trusted");
  if (!make_unary_vse_clause(enclave_key, it, to_prove))
      return false;

  proof_step* ps = nullptr;

  // "policyKey is-trusted" AND "policyKey says platformKey is-trusted" --> "platformKey is-trusted"
  if (!already_proved->proved(4).has_clause()) {
    printf("Error 2, construct_proof_from_full_vse_evidence\n");
    return false;
  }
  ps = pf->add_steps();
  ps->mutable_s1()->CopyFrom(already_proved->proved(0));
  ps->mutable_s2()->CopyFrom(already_proved->proved(4));
  ps->mutable_conclusion()->CopyFrom(already_proved->proved(4).clause());
  ps->set_rule_applied(3);
  const vse_clause& platformkey_is_trusted = ps->conclusion();

  // "policyKey is-trusted" AND "policyKey says measurement is-trusted" --> "measurement is-trusted"
  if (!already_proved->proved(3).has_clause()) {
    printf("Error 3, construct_proof_from_full_vse_evidence\n");
    return false;
  }
  ps = pf->add_steps();
  ps->mutable_s1()->CopyFrom(already_proved->proved(0));
  ps->mutable_s2()->CopyFrom(already_proved->proved(3));
  ps->mutable_conclusion()->CopyFrom(already_proved->proved(3).clause());
  ps->set_rule_applied(3);
  const vse_clause& measurement_is_trusted = ps->conclusion();

  // "platformKey is-trusted" AND "platformKey says attestKey is-trusted" --> "attestKey is-trusted"
  if (!already_proved->proved(1).has_clause()) {
    printf("Error 4, construct_proof_from_full_vse_evidence\n");
    return false;
  }
  ps = pf->add_steps();
  ps->mutable_s1()->CopyFrom(platformkey_is_trusted);
  ps->mutable_s2()->CopyFrom(already_proved->proved(1));
  ps->mutable_conclusion()->CopyFrom(already_proved->proved(1).clause());
  ps->set_rule_applied(3);
  const vse_clause& attestkey_is_trusted = ps->conclusion();

  // "attestKey is-trusted" AND  "attestKey says enclaveKey speaks-for measurement" --> "enclaveKey speaks-for measurement"
  if (!already_proved->proved(2).has_clause()) {
    printf("Error 5, construct_proof_from_full_vse_evidence\n");
    return false;
  }
  ps = pf->add_steps();
  ps->mutable_s1()->CopyFrom(attestkey_is_trusted);
  ps->mutable_s2()->CopyFrom(already_proved->proved(2));
  ps->mutable_conclusion()->CopyFrom(already_proved->proved(2).clause());
  ps->set_rule_applied(3);
  const vse_clause& enclave_speaksfor_measurement = ps->conclusion();

  // "measurement is-trusted" AND "enclaveKey speaks-for measurement" --> "enclaveKey is-trusted"
  ps = pf->add_steps();
  ps->mutable_s1()->CopyFrom(measurement_is_trusted);
  ps->mutable_s2()->CopyFrom(enclave_speaksfor_measurement);
  ps->mutable_conclusion()->CopyFrom(*to_prove);
  ps->set_rule_applied(1);

  return true;
}

#else

bool construct_proof_from_full_vse_evidence(key_message& policy_pk,
      proved_statements* already_proved, vse_clause* to_prove, proof* pf) {

  // At this point, the already_proved should be
  //      "policyKey is-trusted"
  //      "platformKey says attestKey is-trusted-for-attestation
  //      "attestKey says enclaveKey speaks-for measurement
  //      "policyKey says measurement is-trusted"
  //      "policyKey says platformKey is-trusted-for-attestation"

  if (already_proved->proved_size() != 5) {
    printf("Error 0, construct_proof_from_full_vse_evidence\n");
    return false;
  }

  if (!already_proved->proved(2).has_clause() || !already_proved->proved(2).clause().has_subject()) {
    printf("Error 1, construct_proof_from_full_vse_evidence\n");
    return false;
  }
  const entity_message& enclave_key = already_proved->proved(2).clause().subject();
  string it("is-trusted-for-authentication");
  if (!make_unary_vse_clause(enclave_key, it, to_prove))
      return false;

  proof_step* ps = nullptr;

  // "policyKey is-trusted" AND "policyKey says platformKey is-trusted-for-attestation"
  //     --> "platformKey is-trusted-for-attestation"
  if (!already_proved->proved(4).has_clause()) {
    printf("Error 2, construct_proof_from_full_vse_evidence\n");
    return false;
  }
  ps = pf->add_steps();
  ps->mutable_s1()->CopyFrom(already_proved->proved(0));
  ps->mutable_s2()->CopyFrom(already_proved->proved(4));
  ps->mutable_conclusion()->CopyFrom(already_proved->proved(4).clause());
  ps->set_rule_applied(3);
  const vse_clause& platformkey_is_trusted = ps->conclusion();

  // "policyKey is-trusted" AND "policyKey says measurement is-trusted" --> "measurement is-trusted"
  if (!already_proved->proved(3).has_clause()) {
    printf("Error 3, construct_proof_from_full_vse_evidence\n");
    return false;
  }
  ps = pf->add_steps();
  ps->mutable_s1()->CopyFrom(already_proved->proved(0));
  ps->mutable_s2()->CopyFrom(already_proved->proved(3));
  ps->mutable_conclusion()->CopyFrom(already_proved->proved(3).clause());
  ps->set_rule_applied(3);
  const vse_clause& measurement_is_trusted = ps->conclusion();

  // "platformKey is-trusted-for-attestation" AND "platformKey says attestKey is-trusted-for-attestation"
  //      --> "attestKey is-trusted"
  if (!already_proved->proved(1).has_clause()) {
    printf("Error 4, construct_proof_from_full_vse_evidence\n");
    return false;
  }
  ps = pf->add_steps();
  ps->mutable_s1()->CopyFrom(platformkey_is_trusted);
  ps->mutable_s2()->CopyFrom(already_proved->proved(1));
  ps->mutable_conclusion()->CopyFrom(already_proved->proved(1).clause());
  ps->set_rule_applied(5);
  const vse_clause& attestkey_is_trusted = ps->conclusion();

  // "attestKey is-trusted-for-attestation" AND  "attestKey says enclaveKey speaks-for measurement"
  //      --> "enclaveKey speaks-for measurement"
  if (!already_proved->proved(2).has_clause()) {
    printf("Error 5, construct_proof_from_full_vse_evidence\n");
    return false;
  }
  ps = pf->add_steps();
  ps->mutable_s1()->CopyFrom(attestkey_is_trusted);
  ps->mutable_s2()->CopyFrom(already_proved->proved(2));
  ps->mutable_conclusion()->CopyFrom(already_proved->proved(2).clause());
  ps->set_rule_applied(6);
  const vse_clause& enclave_speaksfor_measurement = ps->conclusion();

  // "measurement is-trusted" AND "enclaveKey speaks-for measurement"
  //      --> "enclaveKey is-trusted-for-authentication"
  ps = pf->add_steps();
  ps->mutable_s1()->CopyFrom(measurement_is_trusted);
  ps->mutable_s2()->CopyFrom(enclave_speaksfor_measurement);
  ps->mutable_conclusion()->CopyFrom(*to_prove);
  ps->set_rule_applied(1);

  return true;
}

#endif

bool construct_proof_from_request(string& evidence_descriptor, key_message& policy_pk, 
      signed_claim_sequence& trusted_platforms, signed_claim_sequence& trusted_measurements,
      evidence_package& evp, proved_statements* already_proved, vse_clause* to_prove, proof* pf) {

  if (!init_proved_statements(policy_pk, evp, already_proved))
    return false;

#if 0
  printf("initial proved statements:\n");
  for (int i = 0; i < already_proved->proved_size(); i++) {
    print_vse_clause(already_proved->proved(i));
    printf("\n");
  }
  printf("\n");
#endif

  if (evidence_descriptor == "full-vse-support") {
    if (!construct_proof_from_full_vse_evidence(policy_pk, already_proved, to_prove, pf))
      return false;
  } else if (evidence_descriptor == "platform-attestation-only") {
    if (!add_new_facts_for_abbreviatedplatformattestation(policy_pk, 
              trusted_platforms, trusted_measurements, already_proved)) {
      printf("add_new_facts_for_abbreviatedplatformattestation failed\n");
      return false;
    }
    if (!construct_proof_from_full_vse_evidence(policy_pk, already_proved, to_prove, pf)) {
      printf("construct_proof_from_full_vse_evidence in construct_proof_from_request failed\n");
      return false;
    }
  } else if (evidence_descriptor == "oe-evidence") {
    if (!add_newfacts_for_oeplatform_attestation(policy_pk, 
              trusted_platforms, trusted_measurements, already_proved))
      return false;
    return construct_proof_from_oeevidence(policy_pk, already_proved, to_prove, pf);
  } else {
    return false;
  }

  return true;
}

bool validate_evidence(string& evidence_descriptor, signed_claim_sequence& trusted_platforms,
        signed_claim_sequence& trusted_measurements,
        evidence_package& evp, key_message& policy_pk) {

  proved_statements already_proved;
  vse_clause to_prove;
  proof pf;
  predicate_dominance predicate_dominance_root;

  if (!init_dominance_tree(predicate_dominance_root)) {
    printf("validate_evidence: can't init predicate dominance tree\n");
    return false;
  }

  if (!init_axiom(policy_pk, &already_proved)) {
    printf("validate_evidence: can't init axiom\n");
    return false;
  }

  if (!construct_proof_from_request(evidence_descriptor, policy_pk,
            trusted_platforms, trusted_measurements,
            evp, &already_proved, &to_prove, &pf)) {
    printf("validate_evidence: can't construct proof\n");
    return false;
  }

#if 0
  // Debug: print proof
  printf("proved statements after additions:\n");
  for (int i = 0; i < pf.steps_size(); i++) {
    print_vse_clause(already_proved.proved(i));
    printf("\n");
  }
  printf("\n");

  printf("to prove : ");
  print_vse_clause(to_prove);
  printf("\n\n");
  printf("proposed proof:\n");
  print_proof(pf);
  printf("\n");
#endif

  if (!verify_proof(policy_pk, to_prove, predicate_dominance_root,
            &pf, &already_proved)) {
    printf("verify_proof failed\n");
    return false;
  }

#if 0
  printf("Proved:"); print_vse_clause(to_prove); printf("\n");
  printf("final proved statements:\n");
  for (int i = 0; i < already_proved.proved_size(); i++) {
    print_vse_clause(already_proved.proved(i));
    printf("\n");
  }
  printf("\n");
#endif

  return true;
}

// -------------------------------------------------------------------

// Trust exchange message support
// -------------------------------------------------------------------

// Messages for entity 1 to request trust assessement from entity 2
//  and returned artifacts for entity 2 from entity 1

void print_evidence(const evidence& ev) {
  if (ev.has_evidence_type()) {
    printf("Evidence type: %s\n", ev.evidence_type().c_str());
    if (ev.evidence_type() == "signed-claim") {
      string sc_st;
      sc_st.assign((char*)ev.serialized_evidence().data(),
          ev.serialized_evidence().size());
      signed_claim_message sc;
      if (sc.ParseFromString(sc_st))
        print_signed_claim(sc);
    }
    if (ev.evidence_type() == "oe-assertion") {
      print_bytes(ev.serialized_evidence().size(), (byte*)ev.serialized_evidence().data());
      printf("\n");
    }
  }
}

void print_trust_request_message(trust_request_message& m) {
  if (m.has_requesting_enclave_tag()) {
    printf("Requesting enclave     :  %s\n", m.requesting_enclave_tag().c_str());
  }
  if (m.has_providing_enclave_tag()) {
    printf("Providing  enclave     :  %s\n", m.providing_enclave_tag().c_str());
  }
  if (m.has_submitted_evidence_type()) {
    printf("Evidence type          :  %s\n", m.submitted_evidence_type().c_str());
  }
  if (m.support().has_prover_type()) {
    printf("Prover type: %s\n", m.support().prover_type().c_str());
  }
  if (m.has_policy_key()) {
    print_key(m.policy_key());
  }
  if (m.has_service_address()) {
    printf("Service address: %s\n", m.service_address().c_str());
  }
  if (m.has_serialized_policy_key()) {
    printf("Serialized policy key:\n");
    print_bytes(m.serialized_policy_key().size(), (byte*)m.serialized_policy_key().data());
    printf("\n");
  }
  if (m.has_signed_policy_key()) {
    printf("Signed policy key:\n");
    print_bytes(m.signed_policy_key().size(), (byte*)m.signed_policy_key().data());
    printf("\n");
  }
}

void print_trust_response_message(trust_response_message& m) {
  if (m.has_status()) {
    printf("Status                 :  %s\n", m.status().c_str());
  }
  if (m.has_requesting_enclave_tag()) {
    printf("Requesting enclave     :  %s\n", m.requesting_enclave_tag().c_str());
  }
  if (m.has_providing_enclave_tag()) {
    printf("Providing  enclave     :  %s\n", m.providing_enclave_tag().c_str());
  }
  if (m.has_artifact()) {
    printf("Artifact               : \n");
    print_bytes((int)m.artifact().size(), (byte*)m.artifact().data());
    printf("\n");
  }
}

void print_proof_step(const proof_step& ps) {
  if (ps.has_s1()) {
    print_vse_clause(ps.s1());
    printf(" AND ");
  }
  if (ps.has_s2()) {
    print_vse_clause(ps.s2());
    printf("--> ");
  }
  if (ps.has_conclusion()) {
    print_vse_clause(ps.conclusion());
  }
  if (ps.has_rule_applied()) {
    printf("via %d", ps.rule_applied());
  }
}

void print_proof(proof& pf) {
  // to_prove
  // already_proved
  printf("\nproof steps:\n");
  for (int i = 0; i < pf.steps_size(); i++) {
    print_proof_step(pf.steps(i));
    printf("\n");
  }
}

// -------------------------------------------------------------------

// TLS client/server with auth


int OpenConnection(const char* hostname, int port) {
  struct hostent *host;
  struct sockaddr_in addr;

  if ((host = gethostbyname(hostname)) == NULL) {
    return -1;
  }
  int sd = socket(PF_INET, SOCK_STREAM, 0);
  bzero(&addr, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = *(long*)(host->h_addr);
  if (connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
    close(sd);
    return -1;
  }
  return sd;
}

SSL_CTX* InitCTX() {
  SSL_CTX *ctx;

  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();
  SSL_METHOD* method = (SSL_METHOD*)SSLv23_client_method();
  ctx = SSL_CTX_new(method);
  if ( ctx == NULL ) {
    return nullptr;
  }
  return ctx;
}

// -------------------------------------------------------------------
