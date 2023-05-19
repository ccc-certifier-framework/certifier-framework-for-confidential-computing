#include "support.h"
#include "certifier.h"
#include "simulated_enclave.h"
#include "application_enclave.h"
#include <sys/socket.h>
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

using namespace certifier::framework;
using namespace certifier::utilities;

// Policy store
// -------------------------------------------------------------------

void certifier::framework::print_store(policy_store& ps) {
  printf("Algorithm: %s\n", ps.encryption_algorithm_.c_str());
  printf("num_ts: %d\n", ps.num_ts_);
  printf("num_tsc: %d\n", ps.num_tsc_);
  printf("num_si: %d\n", ps.num_si_);
  printf("num_tc: %d\n", ps.num_tc_);
  printf("num_tkm: %d\n", ps.num_tkm_);
}

certifier::framework::policy_store::policy_store() {
  policy_key_valid_ = false;
  encryption_algorithm_ = "aes-256-cbc-hmac-sha256";

  max_num_ts_ = MAX_NUM_ENTRIES;
  max_num_tsc_ = MAX_NUM_ENTRIES;
  max_num_si_ = MAX_NUM_ENTRIES;
  max_num_tc_ = MAX_NUM_ENTRIES;
  max_num_tkm_ = MAX_NUM_ENTRIES;
  max_num_tkm_ = MAX_NUM_ENTRIES;
  max_num_blobs_ = MAX_NUM_ENTRIES;

  ts_ = new trusted_service_message*[max_num_ts_];
  tsc_ = new tagged_signed_claim*[max_num_tsc_];
  si_ = new storage_info_message*[max_num_si_];
  tc_ = new tagged_claim*[max_num_tc_];
  tkm_ = new channel_key_message*[max_num_tkm_];
  tagged_blob_ = new tagged_blob_message*[max_num_blobs_];

  num_ts_ = 0;
  num_tsc_ = 0;
  num_si_ = 0;
  num_tc_ = 0;
  num_tkm_ = 0;
  num_blobs_ = 0;
}

certifier::framework::policy_store::policy_store(const string enc_alg,
int max_trusted_services, int max_trusted_signed_claims,
      int max_storage_infos, int max_claims, int max_keys, int max_blobs) {

  policy_key_valid_ = false;
  encryption_algorithm_ = enc_alg;

  max_num_ts_ = max_trusted_services;
  max_num_tsc_ = max_trusted_signed_claims;
  max_num_si_ = max_storage_infos;
  max_num_tc_ = max_claims;
  max_num_tkm_ = max_keys;
  max_num_blobs_ = max_blobs;

  ts_ = new trusted_service_message*[max_num_ts_];
  tsc_ = new tagged_signed_claim*[max_num_tsc_];
  si_ = new storage_info_message*[max_num_si_];
  tc_ = new tagged_claim*[max_num_tc_];
  tkm_ = new channel_key_message*[max_num_tkm_];
  tagged_blob_ = new tagged_blob_message *[max_num_blobs_];

  num_ts_ = 0;
  num_tsc_ = 0;
  num_si_ = 0;
  num_tc_ = 0;
  num_tkm_ = 0;
  num_blobs_ = 0;
}

certifier::framework::policy_store::~policy_store() {
  // Todo: clean up sensitive values
  //    not necessary on most platfroms
}

void certifier::framework::policy_store::clear_policy_store() {
  // Todo: not necessary on most platfroms
}

bool certifier::framework::policy_store::replace_policy_key(key_message& k) {
  policy_key_valid_ = true;
  policy_key_.CopyFrom((const key_message)k);
  return true;
}

const key_message* certifier::framework::policy_store::get_policy_key() {
  if (!policy_key_valid_)
    return nullptr;
  return &policy_key_;
}

int certifier::framework::policy_store::get_num_trusted_services() {
  return num_ts_;
}

const trusted_service_message* certifier::framework::policy_store::get_trusted_service_info_by_index(int n) {
  if (n >= num_ts_)
    return nullptr;
  return ts_[n];
}

bool certifier::framework::policy_store::add_trusted_service(trusted_service_message& to_add) {
  if ((num_ts_+1) >= max_num_ts_)
    return true;
  trusted_service_message* t = new(trusted_service_message);
  t->CopyFrom(to_add);
  int n = num_ts_++;
  ts_[n] = t;
  return true;
}

int certifier::framework::policy_store::get_trusted_service_index_by_tag(const string tag) {
  for (int i = 0; i < num_ts_; i++) {
    if (ts_[i]->tag() == tag)
      return i;
  }
  return -1;
}

void certifier::framework::policy_store::delete_trusted_service_by_index(int n) {
  if (n >= num_ts_)
    return;
  const trusted_service_message* deleted = get_trusted_service_info_by_index(n);
  for (int i = n; i < (num_ts_ - 1); i++)
    ts_[i] = ts_[i+1];
  num_ts_--;
  ts_[num_ts_] = nullptr;
  delete deleted;
}

int certifier::framework::policy_store::get_num_storage_info() {
  return num_si_;
}

const storage_info_message* certifier::framework::policy_store::get_storage_info_by_index(int n) {
  if (n >= num_si_)
    return nullptr;
  return si_[n];
}

bool certifier::framework::policy_store::add_storage_info(storage_info_message& to_add) {
  if ((num_si_ + 1) >= max_num_si_)
    return false;
  storage_info_message* t = new(storage_info_message);
  int n = num_si_++;
  si_[n] = t;
  si_[n]->CopyFrom(to_add);
  return true;
}

void certifier::framework::policy_store::delete_storage_info_by_index(int n) {
  if (n >= num_si_)
    return;
  const storage_info_message* deleted = get_storage_info_by_index(n);
  for (int i = n; i < (num_si_ - 1); i++)
    si_[i] = si_[i+1];
  num_si_--;
  si_[num_si_] = nullptr;
  delete deleted;
}

int certifier::framework::policy_store::get_storage_info_index_by_tag(const string& tag) {
  for (int i = 0; i < num_si_; i++) {
    if (si_[i]->tag() == tag)
      return i;
  }
  return -1;
}

int certifier::framework::policy_store::get_num_claims() {
  return num_tc_;
}

const claim_message* certifier::framework::policy_store::get_claim_by_index(int n) {
  if (n >= num_tc_)
    return nullptr;
  return &(tc_[n]->claim());
}

bool certifier::framework::policy_store::add_claim(const string& tag, const claim_message& to_add) {
  if ((num_tc_ + 1) >= max_num_tc_)
    return false;
  tagged_claim* t = new(tagged_claim);
  int n = num_tc_++;
  t->set_tag(tag);
  tc_[n] = t;
  (tc_[n]->mutable_claim())->CopyFrom(to_add);
  return true;
}

void certifier::framework::policy_store::delete_claim_by_index(int n) {
  if (n >= num_tc_)
    return;
  const tagged_claim* deleted = tc_[n];
  for (int i = n; i < (num_tc_ - 1); i++)
    tc_[i] = tc_[i+1];
  num_tc_--;
  tc_[num_tc_] = nullptr;
  delete deleted;
}

int certifier::framework::policy_store::get_claim_index_by_tag(const string& tag) { // to do
  for (int i = 0; i < num_tc_; i++) {
    if (tc_[i]->tag() == tag)
      return i;
  }
  return -1;
}

bool certifier::framework::policy_store::add_authentication_key(const string& tag, const key_message& k) {
  if ((num_tkm_ + 1) >= max_num_tkm_)
    return false;
  channel_key_message* t = new(channel_key_message);
  t->set_tag(tag);
  int n = num_tkm_++;
  tkm_[n] = t;
  tkm_[n]->mutable_auth_key()->CopyFrom(k);
  return true;
}

const key_message* certifier::framework::policy_store::get_authentication_key_by_tag(const string& tag) {
  for (int i = 0; i < num_tkm_; i++) {
    if (tkm_[i]->tag() == tag)
      return &(tkm_[i]->auth_key());
  }
  return nullptr;
}

const key_message* certifier::framework::policy_store::get_authentication_key_by_index(int i) {
  if (i >= num_tkm_)
    return nullptr;
  return &(tkm_[i]->auth_key());
}

int certifier::framework::policy_store::get_authentication_key_index_by_tag(const string& tag) {
  for (int i = 0; i < num_tkm_; i++) {
    if (tkm_[i]->tag() == tag)
      return i;
  }
  return -1;
}

void certifier::framework::policy_store::delete_authentication_key_by_index(int n) {
  if (n >= num_tkm_)
    return;
  const key_message* deleted = get_authentication_key_by_index(n);
  for (int i = n; i < (num_tkm_ - 1); i++)
    tkm_[i] = tkm_[i+1];
  num_tkm_--;
  tkm_[num_tkm_] = nullptr;
  delete deleted;
}

bool certifier::framework::policy_store::Serialize(string* out) {
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
  for (int i = 0; i < num_blobs_; i++) {
    tagged_blob_message* t = psm.add_blobs();
    t->CopyFrom(*tagged_blob_[i]);
  }

  if (!psm.SerializeToString(out))
    return false;

  return true;
}

bool certifier::framework::policy_store::Deserialize(string& in) {
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
  num_blobs_ = psm.blobs_size();
  for (int i = 0; i < num_blobs_; i++) {
    tagged_blob_message* t = new(tagged_blob_message);
    t->CopyFrom(psm.blobs(i));
    tagged_blob_[i] = t;
  }

  return true;
}

const signed_claim_message* certifier::framework::policy_store::get_signed_claim_by_index(int n) {
  if (n >= num_tsc_)
    return nullptr;
  return &(tsc_[n]->sc());
}

bool certifier::framework::policy_store::add_signed_claim(const string& tag, const signed_claim_message& to_add) {
  if ((num_tsc_ + 1) >= max_num_tsc_)
    return false;
  tagged_signed_claim* t = new(tagged_signed_claim);
  t->set_tag(tag);
  int n = num_tsc_++;
  tsc_[n] = t;
  tsc_[n]->mutable_sc()->CopyFrom(to_add);
  return true;
}

int certifier::framework::policy_store::get_signed_claim_index_by_tag(const string& tag) {
  for (int i = 0; i < num_tsc_; i++) {
    if (tsc_[i]->tag() == tag)
      return i;
  }
  return -1;
}

void certifier::framework::policy_store::delete_signed_claim_by_index(int n) {
  if (n >= num_tsc_)
    return;
  const signed_claim_message* deleted = get_signed_claim_by_index(n);
  for (int i = n; i < (num_tsc_ - 1); i++)
    tsc_[i] = tsc_[i+1];
  num_tsc_--;
  tsc_[num_tsc_] = nullptr;
  delete deleted;
}

bool certifier::framework::policy_store::add_blob(const string& tag, const string& s) {
  if (num_blobs_ >= max_num_blobs_)
    return false;
  int n = get_blob_index_by_tag(tag);
  if (n >= 0)
    return false;
  tagged_blob_message* t = new(tagged_blob_message);
  t->set_tag(tag);
  t->set_b(s);
  tagged_blob_[num_blobs_++] = t;
  return true;
}

const string* certifier::framework::policy_store::get_blob_by_tag(const string& tag) {
  int index = get_blob_index_by_tag(tag);
  if (index < 0)
    return nullptr;
  return &tagged_blob_[index]->b();
}

const tagged_blob_message* certifier::framework::policy_store::get_tagged_blob_info_by_index(int n) {
  if (n >= num_blobs_)
    return nullptr;
  return tagged_blob_[n];
}

const string* certifier::framework::policy_store::get_blob_by_index(int index) {
  if (index >= num_blobs_)
    return nullptr;
  return &(tagged_blob_[index]->b());
}

int certifier::framework::policy_store::get_blob_index_by_tag(const string& tag) {
  for (int i = 0; i < num_blobs_; i++) {
    if (tag == tagged_blob_[i]->tag())
      return i;
  }
  return -1;
}

void certifier::framework::policy_store::delete_blob_by_index(int index) {
  if (index >= num_blobs_)
    return;
  const tagged_blob_message* deleted = get_tagged_blob_info_by_index(index);
  for (int i = index; i < (num_blobs_ - 1); i++)
    tagged_blob_[i] = tagged_blob_[i+1];
  num_blobs_--;
  tagged_blob_[num_blobs_] = nullptr;
  // clear deleted and free it

}

int certifier::framework::policy_store::get_num_blobs() {
  return num_blobs_;
}


// -------------------------------------------------------------------

// Trusted primitives
// -------------------------------------------------------------------

bool certifier_public_policy_key_initialized = false;
key_message certifier_public_policy_key;
const key_message* GetPublicPolicyKey() {
  if (!certifier_public_policy_key_initialized)
    return nullptr;
  return &certifier_public_policy_key;
}

bool GetX509FromCert(const string& cert, X509* x) {
  return asn1_to_x509(cert, x);
}

bool PublicKeyFromCert(const string& cert, key_message* k) {
  X509* x = X509_new();
  EVP_PKEY* epk = nullptr;
  X509_NAME* sn = nullptr;
  int s = 0;
  bool res = true;
  int len = -1;
  string subject_name_str;
  string* cert_str = nullptr;

  if (!GetX509FromCert(cert, x)) {
    printf("PublicKeyFromCert: Can't get X509 from cert\n");
    res = false;
    goto done;
  }

  // make key message for public policy key from cert
  epk = X509_get_pubkey(x);
  if (epk == nullptr) {
    printf("PublicKeyFromCert: Can't get subject key\n");
    res = false;
    goto done;
  }

  sn = X509_get_subject_name(x);
  if (sn == nullptr) {
    printf("PublicKeyFromCert: Can't get subject name\n");
    res = false;
    goto done;
  }

  len = X509_NAME_get_text_by_NID(sn, NID_commonName, nullptr, 0);
  if (len < 0) {
    printf("PublicKeyFromCert: Can't X509_NAME_get_text_by_NID length\n");
    res = false;
    goto done;
  }
  len++;
  {
    char name_buf[len];
    if (X509_NAME_get_text_by_NID(sn, NID_commonName, name_buf, len) < 0) {
      printf("PublicKeyFromCert: Can't X509_NAME_get_text_by_NID\n");
      res = false;
    }
    subject_name_str.assign((const char*) name_buf);
  }
  if (!res)
    goto done;

  if (EVP_PKEY_base_id(epk) == EVP_PKEY_RSA) {
    const RSA* rk = nullptr;
    rk = EVP_PKEY_get0_RSA(epk);
    if (rk == nullptr) {
      printf("PublicKeyFromCert: Can't get RSA key from evp\n");
      res = false;
      goto done;
    }
    if (!RSA_to_key(rk, k)) {
      printf("PublicKeyFromCert: Can't get internal key from RSA key\n");
      res = false;
      goto done;
    }
  } else if (EVP_PKEY_base_id(epk) == EVP_PKEY_EC) {
    const EC_KEY* ek = EVP_PKEY_get0_EC_KEY(epk);
    if (ek == nullptr) {
      printf("PublicKeyFromCert: Can't get ECC key from evp\n");
      res = false;
      goto done;
    }
    if (!ECC_to_key(ek, k)) {
      printf("PublicKeyFromCert: Can't convert ECC key to internal key\n");
      res = false;
      goto done;
    }
  } else {
    res = false;
    goto done;
  }

  k->set_key_name(subject_name_str);
  k->set_key_format("vse-key");

  cert_str = new(string);
  cert_str->assign((char*)cert.data(), cert.size());
  k->set_allocated_certificate(cert_str);

done:
  if (epk != nullptr)
    EVP_PKEY_free(epk);
  if (x != nullptr)
    X509_free(x);
  return res;
}

#ifdef SEV_SNP
extern bool sev_Init(const string& platform_certs_file);
extern bool sev_GetParentEvidence(string* out);
extern bool sev_Seal(int in_size, byte* in, int* size_out, byte* out);
extern bool sev_Unseal(int in_size, byte* in, int* size_out, byte* out);
extern bool sev_Attest(int what_to_say_size, byte* what_to_say,
    int* size_out, byte* out);
#endif

#ifdef ASYLO_CERTIFIER
extern bool asylo_Attest(int claims_size, byte* claims, int* size_out, byte* out);
extern bool asylo_Verify(int claims_size, byte* claims, int *user_data_out_size,
                  byte *user_data_out, int* size_out, byte* out);
extern bool asylo_Seal(int in_size, byte* in, int* size_out, byte* out);
extern bool asylo_Unseal(int in_size, byte* in, int* size_out, byte* out);
#endif

#ifdef GRAMINE_CERTIFIER
extern bool gramine_Attest(const int what_to_say_size, byte* what_to_say, int* size_out, byte* out);
extern bool gramine_Verify(const int what_to_say_size, byte* what_to_say, const int attestation_size,
                  byte *attestation, int* size_out, byte* out);
extern bool gramine_Seal(int in_size, byte* in, int* size_out, byte* out);
extern bool gramine_Unseal(int in_size, byte* in, int* size_out, byte* out);
#endif

// Buffer overflow check: Seal returns true and the buffer size in size_out.
// Check on Gramine.
bool certifier::framework::Seal(const string& enclave_type, const string& enclave_id,
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
  if (enclave_type == "sev-enclave") {
   return sev_Seal(in_size, in, size_out, out);
  }
#endif
#ifdef ASYLO_CERTIFIER
  if (enclave_type == "asylo-enclave") {
   return asylo_Seal(in_size, in, size_out, out);
  }
#endif
#ifdef GRAMINE_CERTIFIER
  if (enclave_type == "gramine-enclave") {
   return gramine_Seal(in_size, in, size_out, out);
  }
#endif
  if (enclave_type == "application-enclave") {
   return application_Seal(in_size, in, size_out, out);
  }
 return false;
}

// Buffer overflow check: Done for SEV, OE, simulated enclave and application service.
// If out is NULL, Unseal returns true and the buffer size in size_out.  Check Gramine.
bool certifier::framework::Unseal(const string& enclave_type, const string& enclave_id,
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
  if (enclave_type == "sev-enclave") {
    return sev_Unseal(in_size, in, size_out, out);
  }
#endif
#ifdef ASYLO_CERTIFIER
  if (enclave_type == "asylo-enclave") {
   return asylo_Unseal(in_size, in, size_out, out);
  }
#endif
#ifdef GRAMINE_CERTIFIER
  if (enclave_type == "gramine-enclave") {
   return gramine_Unseal(in_size, in, size_out, out);
  }
#endif
  if (enclave_type == "application-enclave") {
    return application_Unseal(in_size, in, size_out, out);
  }
 return false;
}

//  Buffer overflow check: Attest returns true and the buffer size in size_out.  Check on Gramine.
bool certifier::framework::Attest(const string& enclave_type, int what_to_say_size, byte* what_to_say,
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
  if (enclave_type == "sev-enclave") {
    return sev_Attest(what_to_say_size, what_to_say, size_out, out);
  }
#endif
#ifdef ASYLO_CERTIFIER
  if (enclave_type == "asylo-enclave") {
    return asylo_Attest(what_to_say_size, what_to_say, size_out, out);
  }
#endif
#ifdef GRAMINE_CERTIFIER
  if (enclave_type == "gramine-enclave") {
    // Gramine attest returns an attestation, not a
    // serialized gramine_attestation_message.
    int t_size_out;
    int t_size = *size_out;
    if (!gramine_Attest(what_to_say_size, what_to_say, &t_size_out, out)) {
      return false;
    }
    string ra;
    string wws;
    ra.assign((char*)out, t_size_out);
    wws.assign((char*)what_to_say, what_to_say_size);
    gramine_attestation_message gam;
    gam.set_what_was_said(wws);
    gam.set_reported_attestation(ra);
    string serialized_gramine_at;
    if (!gam.SerializeToString(&serialized_gramine_at)) {
      return false;
    }
    if (*size_out < serialized_gramine_at.size()) {
      return false;
    }
    memset(out, 0, *size_out);
    memcpy(out, (byte*)serialized_gramine_at.data(), serialized_gramine_at.size());
    *size_out = serialized_gramine_at.size();
    return true;
  }
#endif
  if (enclave_type == "application-enclave") {
    return application_Attest(what_to_say_size, what_to_say, size_out, out);
  }

 return false;
}

bool GetParentEvidence(const string& enclave_type, const string& parent_enclave_type,
    string* out) {
#ifdef OE_CERTIFIER
  if (enclave_type == "oe-enclave") {
    return false;
  }
#endif
#ifdef SEV_SNP
  if (enclave_type == "sev-enclave") {
    return sev_GetParentEvidence(out);
  }
#endif
#ifdef ASYLO_CERTIFIER
  if (enclave_type == "asylo-enclave") {
    return false;
  }
#endif
#ifdef GRAMINE_CERTIFIER
  if (enclave_type == "gramine-enclave") {
    return false;
  }
#endif
  if (enclave_type == "application-enclave") {
    return application_GetParentEvidence(out);
  }
  return false;
}

bool GetPlatformStatement(const string& enclave_type, const string& enclave_id,
  int* size_out, byte* out) {
  if (enclave_type == "application-enclave") {
#ifdef DEBUG
    printf("Calling application_GetPlatformStatement\n");
#endif
    return application_GetPlatformStatement(size_out, out);
  }
#ifdef DEBUG
  printf("application_GetPlatformStatement dropped through\n");
#endif
  return false;
}

bool certifier_parent_enclave_type_intitalized = false;
string certifier_parent_enclave_type;
bool GetParentEnclaveType(string* type) {
  if (!certifier_parent_enclave_type_intitalized)
    return false;
  *type = certifier_parent_enclave_type;
  return true;
}

// -------------------------------------------------------------------

// Protect Support
// -------------------------------------------------------------------

// the padding size includes an IV and possibly 3 additional blocks
const int max_key_seal_pad = 1024;
const int protect_key_size = 64;

bool certifier::framework::Protect_Blob(const string& enclave_type, key_message& key,
  int size_unencrypted_data, byte* unencrypted_data,
  int* size_protected_blob, byte* blob) {

  string serialized_key;
  if (!key.SerializeToString(&serialized_key)) {
    printf("Protect_Blob: can't serialize key\n");
    return false;
  }

  int size_sealed_key = serialized_key.size() + max_key_seal_pad;
  byte sealed_key[size_sealed_key];
  memset(sealed_key, 0, size_sealed_key);
  string enclave_id("enclave-id");

  if (!Seal(enclave_type, enclave_id, serialized_key.size(), (byte*)serialized_key.data(),
        &size_sealed_key, sealed_key)) {
    printf("Protect_Blob: can't seal\n");
    return false;
  }

  byte iv[block_size];
  if (!get_random(8 * block_size, iv)) {
    printf("Protect_Blob, can't get random number\n");
    return false;
  }
  if (!key.has_secret_key_bits()) {
    printf("Protect_Blob: no key bits\n");
    return false;
  }
  byte* key_buf = (byte*)key.secret_key_bits().data();
  if (key.secret_key_bits().size() < protect_key_size) {
    printf("Protect_Blob: key too small\n");
    return false;
  }

  int size_encrypted = size_unencrypted_data + max_key_seal_pad;
  byte encrypted_data[size_encrypted];
  if (!authenticated_encrypt(key.key_type().c_str(),
          unencrypted_data, size_unencrypted_data,
          key_buf, iv, encrypted_data, &size_encrypted)) {
    printf("Protect_Blob: authenticate encryption failed\n");
    return false;
  }
  
  protected_blob_message blob_msg;
  blob_msg.set_encrypted_key((void*)sealed_key, size_sealed_key);
  blob_msg.set_encrypted_data((void*)encrypted_data, size_encrypted);

  string serialized_blob;
  blob_msg.SerializeToString(&serialized_blob);
  if (((int)serialized_blob.size()) > *size_protected_blob) {
    printf("Protect_Blob: furnished buffer is too small\n");
    return false;
  }
  *size_protected_blob = (int)serialized_blob.size();
  memcpy(blob, (byte*)serialized_blob.data(), *size_protected_blob);
  return true;
}

bool certifier::framework::Unprotect_Blob(const string& enclave_type, int size_protected_blob,
      byte* protected_blob, key_message* key, int* size_of_unencrypted_data,
      byte* unencrypted_data) {

  string protected_blob_string;
  protected_blob_string.assign((char*)protected_blob, size_protected_blob);
  protected_blob_message pb;
  if (!pb.ParseFromString(protected_blob_string)) {
    printf("Unprotect_Blob: can't parse protected blob message\n");
    return false;
  }
  if (!pb.has_encrypted_key()) {
    printf("Unprotect_Blob: no encryption key\n");
    return false;
  }
  if (!pb.has_encrypted_data()) {
    printf("Unprotect_Blob: no encrypted data\n");
    return false;
  }

  int size_unsealed_key = pb.encrypted_key().size();
  byte unsealed_key[size_unsealed_key];
  memset(unsealed_key, 0, size_unsealed_key);
  string enclave_id("enclave-id");

  // Unseal header
  if (!Unseal(enclave_type, enclave_id, pb.encrypted_key().size(), (byte*)pb.encrypted_key().data(),
        &size_unsealed_key, unsealed_key)) {
    printf("Unprotect_Blob: can't unseal\n");
    return false;
  }

  string serialized_key;
  serialized_key.assign((const char*)unsealed_key, size_unsealed_key);
  if (!key->ParseFromString(serialized_key)) {
    printf("Unprotect_Blob: can't parse unsealed key\n");
    return false;
  }

  if (key->key_type() != "aes-256-cbc-hmac-sha256") {
    printf("Unprotect_Blob, unsupported encryption scheme\n");
    return false;
  }
  if (!key->has_secret_key_bits()) {
    printf("Unprotect_Blob: no key bits\n");
    return false;
  }
  byte* key_buf = (byte*)key->secret_key_bits().data();
  if (key->secret_key_bits().size() < protect_key_size) {
    printf("Unprotect_Blob: key too small\n");
    return false;
  }

  // decrypt encrypted data
  if (!authenticated_decrypt(key->key_type().c_str(), (byte*)pb.encrypted_data().data(),
          pb.encrypted_data().size(), key_buf, unencrypted_data, size_of_unencrypted_data)) {
    printf("Unprotect_Blob: authenticated decrypt failed\n");
    return false;
  }
  return true;
}

bool certifier::framework::Reprotect_Blob(const string& enclave_type, key_message* key,
      int size_protected_blob, byte* protected_blob,
      int* size_new_encrypted_blob, byte* data) {
  return false;
}

// -------------------------------------------------------------------

bool certifier::utilities::check_date_range(const string& nb, const string& na) {
  time_point t_now;
  time_point t_nb;
  time_point t_na;

  if (!time_now(&t_now))
    return false;
  if (!string_to_time(nb, &t_nb))
    return false;
  if (!string_to_time(na, &t_na))
    return false;

  if (compare_time(t_now, t_nb) < 0 || compare_time(t_na, t_now) < 0) {
    printf("No longer valid\n");
    return false;
  }
  return true;
}

// -------------------------------------------------------------------

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
    if (ev.evidence_type() == "oe-attestation-report") {
      print_bytes(ev.serialized_evidence().size(), (byte*)ev.serialized_evidence().data());
        printf("\n");
    }
    if (ev.evidence_type() == "asylo-evidence") {
        print_bytes(ev.serialized_evidence().size(), (byte*)ev.serialized_evidence().data());
      printf("\n");
    }
    if (ev.evidence_type() == "gramine-evidence") {
        print_bytes(ev.serialized_evidence().size(), (byte*)ev.serialized_evidence().data());
      printf("\n");
    }
    if (ev.evidence_type() == "cert") {
      printf("Cert: ");
      print_bytes(ev.serialized_evidence().size(), (byte*)ev.serialized_evidence().data());
      printf("\n");
    }
    if (ev.evidence_type() == "signed-vse-attestation-report") {
      signed_report sr;
      if (sr.ParseFromString(ev.serialized_evidence())) {
        print_signed_report(sr);
        printf("\n");
      }
    }
    if (ev.evidence_type() == "sev-attestation") {
      print_bytes(ev.serialized_evidence().size(), (byte*)ev.serialized_evidence().data());
        printf("\n");
    }
  }
}

void print_evidence_package(const evidence_package& evp) {
  printf("Evidence package.  Prover: %s\n", evp.prover_type().c_str());
  for (int i = 0; i < evp.fact_assertion_size(); i++) {
    printf("%02d: \n", i);
    print_evidence(evp.fact_assertion(i));
    printf("\n");
  }
}

void print_trust_request_message(trust_request_message& m) {
  if (m.has_requesting_enclave_tag()) {
    printf("Requesting enclave     :  %s\n", m.requesting_enclave_tag().c_str());
  }
  if (m.has_providing_enclave_tag()) {
    printf("Providing  enclave     :  %s\n", m.providing_enclave_tag().c_str());
  }
  if (m.has_purpose()) {
    printf("Purpose                :  %s\n", m.purpose().c_str());
  }
  if (m.has_submitted_evidence_type()) {
    printf("Evidence type          :  %s\n", m.submitted_evidence_type().c_str());
  }
  if (m.support().has_prover_type()) {
    printf("Prover type: %s\n", m.support().prover_type().c_str());
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
  printf("\nproof steps:\n");
  for (int i = 0; i < pf.steps_size(); i++) {
    printf("\n%2d: ", i);
    print_proof_step(pf.steps(i));
    printf("\n");
  }
}

void print_attestation_info(vse_attestation_report_info& r) {
  printf("\nvse attestation report\n");
  if (r.has_enclave_type()) {
    printf("Enclave type: %s\n", r.enclave_type().c_str());
  }
  if (r.has_verified_measurement()) {
    printf("Measurement: ");
    print_bytes(r.verified_measurement().size(),
        (byte*)r.verified_measurement().data());
    printf("\n");
  }
  if (r.has_not_before() && r.has_not_after()) {
    printf("Not before : %s\n", r.not_before().c_str());
    printf("Not after  : %s\n", r.not_after().c_str());
  }
  if (r.has_user_data()) {
    printf("User data  : ");
    print_bytes(r.user_data().size(), (byte*)r.user_data().data());
    printf("\n");
  }
  printf("\n");
}

void print_user_data(attestation_user_data& ud) {
  printf("\nUser data\n");
  if (ud.has_enclave_type()) {
    printf("Enclave type: %s\n", ud.enclave_type().c_str());
  }
  if (ud.has_time()) {
    printf("Time        : %s\n", ud.time().c_str());
  }
  if (ud.has_enclave_key()) {
    printf("Auth key    :");
    print_key(ud.enclave_key());
    printf("\n");
  }
  if (ud.has_policy_key()) {
  }
  printf("\n");
}

void print_signed_report(const signed_report& sr) {
  printf("\nSigned report\n");
  if (sr.has_report_format()) {
    printf("Report format: %s\n", sr.report_format().c_str());
  }
  if (sr.has_report()) {
    printf("Report     :\n");
    print_bytes(sr.report().size(), (byte*)sr.report().data());
    printf("\n");
  }
  if (sr.has_signing_key()) {
    printf("Signing key:\n");
    print_key(sr.signing_key());
    printf("\n");
  }
  if (sr.has_signing_algorithm()) {
    printf("Signing algorithm: %s\n", sr.signing_algorithm().c_str());
  }
  if (sr.has_signature()) {
    printf("Signature   :\n");
    print_bytes(sr.signature().size(), (byte*)sr.signature().data());
    printf("\n");
  }
  printf("\n");
}

bool read_signed_vse_statements(const string& in, signed_claim_sequence* s) {
  string str;
  if(!read_file_into_string(in, &str)) {
    printf("read_signed_vse_statements: Can't read %s\n", in.c_str());
    return false;
  }
  if (!s->ParseFromString(str)) {
    printf("read_signed_vse_statements: Can't parse claim sequence\n");
    return false;
  }
  return true;
}

// -----------------------------------------------------------------------------

