//  Copyright (c) 2021-23, VMware Inc, and the Certifier Authors.  All rights
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

#include <sys/socket.h>
#include <netdb.h>
#include <algorithm>
#include "support.h"
#include "certifier.h"
#include "simulated_enclave.h"
#include "application_enclave.h"
#ifdef SEV_SNP
#  include "sev_vcek_ext.h"
#endif

using namespace certifier::framework;
using namespace certifier::utilities;

// Policy store
// -------------------------------------------------------------------

certifier::framework::store_entry::store_entry() {}

certifier::framework::store_entry::~store_entry() {}

void certifier::framework::store_entry::print() {
  printf("Tag: %s, type: %s, value: ", tag_.c_str(), type_.c_str());
  if (type_ == "string") {
    printf("%s\n", value_.c_str());
  } else {
    print_bytes((int)value_.size(), (byte *)value_.data());
  }
}

certifier::framework::policy_store::policy_store(unsigned max_ents) {
  max_num_ents_ = max_ents;
  num_ents_ = 0;
  entry_ = new store_entry *[max_ents];
}

certifier::framework::policy_store::policy_store() {
  max_num_ents_ = MAX_NUM_ENTRIES;
  num_ents_ = 0;
  entry_ = new store_entry *[MAX_NUM_ENTRIES];
}

certifier::framework::policy_store::~policy_store() {
  for (unsigned i = 0; i < num_ents_; i++) {
    delete entry_[i];
    entry_[i] = nullptr;
  }
  delete[] entry_;
  num_ents_ = 0;
}

unsigned certifier::framework::policy_store::get_num_entries() {
  return num_ents_;
}

bool certifier::framework::policy_store::add_entry(const string &tag,
                                                   const string &type,
                                                   const string &value) {
  if (num_ents_ >= max_num_ents_)
    return false;
  entry_[num_ents_] = new store_entry;
  entry_[num_ents_]->tag_ = tag;
  entry_[num_ents_]->type_ = type;
  entry_[num_ents_]->value_.assign(value.data(), value.size());
  num_ents_++;
  return true;
}

int certifier::framework::policy_store::find_entry(const string &tag,
                                                   const string &type) {
  for (unsigned i = 0; i < num_ents_; i++) {
    if (entry_[i]->tag_ == tag && entry_[i]->type_ == type)
      return (int)i;
  }
  return -1;
}

bool certifier::framework::policy_store::get(unsigned ent, string *v) {
  if (ent >= num_ents_)
    return false;
  *v = entry_[ent]->value_;
  return true;
}

bool certifier::framework::policy_store::put(unsigned ent, const string v) {
  if (ent >= num_ents_)
    return false;
  entry_[ent]->value_ = v;
  return true;
}

const string *certifier::framework::policy_store::tag(unsigned ent) {
  if (ent >= num_ents_)
    return nullptr;
  return &entry_[ent]->tag_;
}

const string *certifier::framework::policy_store::type(unsigned ent) {
  if (ent >= num_ents_)
    return nullptr;
  return &entry_[ent]->type_;
}

store_entry *certifier::framework::policy_store::get_entry(unsigned ent) {
  if (ent >= num_ents_)
    return nullptr;
  return entry_[ent];
}

bool certifier::framework::policy_store::update_or_insert(const string &tag,
                                                          const string &type,
                                                          const string &value) {
  int ent = find_entry(tag, type);
  if (ent < 0) {
    return add_entry(tag, type, value);
  }
  if (!put(ent, value))
    return false;
  return true;
}

bool certifier::framework::policy_store::delete_entry(unsigned ent) {
  if (ent >= num_ents_)
    return false;

  delete entry_[ent];
  for (unsigned i = ent; i < num_ents_; i++) {
    entry_[i] = entry_[i + 1];
  }
  entry_[num_ents_ - 1] = nullptr;
  num_ents_--;
  return true;
}

void certifier::framework::policy_store::print() {
  printf("Number of entries: %d, max number of ents: %d\n",
         num_ents_,
         max_num_ents_);

  for (unsigned i = 0; i < num_ents_; i++) {
    printf("  Entry %3d: ", i);
    entry_[i]->print();
    printf("\n");
  }
}

bool certifier::framework::policy_store::Serialize(string *psout) {
  policy_store_message psm;

  psm.set_max_ents(max_num_ents_);

  for (unsigned i = 0; i < num_ents_; i++) {
    policy_store_entry *pe = psm.add_entries();
    store_entry *       se = entry_[i];
    pe->set_tag(se->tag_);
    pe->set_type(se->type_);
    pe->set_value(se->value_);
  }

  return (psm.SerializeToString(psout));
}

bool certifier::framework::policy_store::Deserialize(string &in) {

  policy_store_message psm;

  if (!psm.ParseFromString(in))
    return false;

  if (psm.has_max_ents()) {
    max_num_ents_ = psm.max_ents();
  } else {
    max_num_ents_ = MAX_NUM_ENTRIES;
  }

  for (int i = 0; i < psm.entries_size(); i++) {
    const policy_store_entry &pe = psm.entries(i);
    store_entry *             se = new store_entry();
    entry_[i] = se;
    se->tag_ = pe.tag();
    se->type_ = pe.type();
    se->value_ = pe.value();
  }
  num_ents_ = psm.entries_size();

  return true;
}

// -------------------------------------------------------------------

// Trusted primitives
// -------------------------------------------------------------------

bool               certifier_public_policy_key_initialized = false;
key_message        certifier_public_policy_key;
const key_message *GetPublicPolicyKey() {
  if (!certifier_public_policy_key_initialized)
    return nullptr;
  return &certifier_public_policy_key;
}

bool GetX509FromCert(const string &cert, X509 *x) {
  return asn1_to_x509(cert, x);
}

#ifdef SEV_SNP

static bool vcek_ext_byte_value(X509 *         vcek,
                                const char *   oid,
                                unsigned char *value) {
  int                  nid = -1, idx = -1, extlen = -1;
  X509_EXTENSION *     ex = NULL;
  ASN1_STRING *        extvalue = NULL;
  const unsigned char *vals = NULL;

  // Use OID for both lname and sname so OBJ_create does not fail
  nid = OBJ_create(oid, oid, oid);
  if (nid == NID_undef) {
    return false;
  }
  idx = X509_get_ext_by_NID(vcek, nid, -1);
  if (idx == -1) {
    return false;
  }

  ex = X509_get_ext(vcek, idx);
  extvalue = X509_EXTENSION_get_data(ex);
  extlen = ASN1_STRING_length(extvalue);
  vals = ASN1_STRING_get0_data(extvalue);

  if (vals[0] != 0x2) {
    printf("%s() error, line %d, Invalid extension type!\n",
           __func__,
           __LINE__);
    return false;
  }

  if (vals[1] != 0x1 && vals[1] != 0x2) {
    printf("%s() error, line %d, Invalid extension length!\n",
           __func__,
           __LINE__);
    return false;
  }

  *value = vals[extlen - 1];
  return true;
}

uint64_t get_tcb_version_from_vcek(X509 *vcek) {
  unsigned char blSPL, teeSPL, snpSPL, ucodeSPL;
  uint64_t      tcb_version = (uint64_t)-1;

  if (vcek_ext_byte_value(vcek, VCEK_EXT_BLSPL, &blSPL)
      && vcek_ext_byte_value(vcek, VCEK_EXT_TEESPL, &teeSPL)
      && vcek_ext_byte_value(vcek, VCEK_EXT_SNPSPL, &snpSPL)
      && vcek_ext_byte_value(vcek, VCEK_EXT_UCODESPL, &ucodeSPL)) {
    tcb_version = blSPL | ((uint64_t)teeSPL << 8) | ((uint64_t)snpSPL << 48)
                  | ((uint64_t)ucodeSPL << 56);
  }

  return tcb_version;
}

static bool get_chipid_from_vcek(X509 *vcek, unsigned char *chipid, int idlen) {
  int                  nid = -1, idx = -1, extlen = -1;
  X509_EXTENSION *     ex = NULL;
  ASN1_STRING *        extvalue = NULL;
  const unsigned char *vals = NULL;

  nid = OBJ_create(VCEK_EXT_HWID, VCEK_EXT_HWID, VCEK_EXT_HWID);
  if (nid == NID_undef) {
    printf("%s() Warning, line %d, Failed to create NID\n", __func__, __LINE__);
    return false;
  }
  idx = X509_get_ext_by_NID(vcek, nid, -1);
  if (idx == -1) {
    return false;
  }

  ex = X509_get_ext(vcek, idx);
  extvalue = X509_EXTENSION_get_data(ex);
  extlen = ASN1_STRING_length(extvalue);
  vals = ASN1_STRING_get0_data(extvalue);

  if (idlen < extlen || chipid == nullptr) {
    return false;
  }

  std::copy(vals, vals + extlen, chipid);
  return true;
}
#endif  // SEV_SNP

bool PublicKeyFromCert(const string &cert, key_message *k) {
  X509 *     x = X509_new();
  EVP_PKEY * epk = nullptr;
  X509_NAME *sn = nullptr;
  int        s = 0;
  bool       res = true;
  int        len = -1;
  string     subject_name_str;
  string *   cert_str = nullptr;
#ifdef SEV_SNP
  enum { CHIP_ID_SIZE = 64 };
  unsigned char chipid[CHIP_ID_SIZE];
#endif  // SEV_SNP

  if (!GetX509FromCert(cert, x)) {
    printf("%s() error, line %d, PublicKeyFromCert: Can't get X509 from cert\n",
           __func__,
           __LINE__);
    res = false;
    goto done;
  }

  // make key message for public policy key from cert
  epk = X509_get_pubkey(x);
  if (epk == nullptr) {
    printf("%s() error, line %d, PublicKeyFromCert: Can't get subject key\n",
           __func__,
           __LINE__);
    res = false;
    goto done;
  }

  sn = X509_get_subject_name(x);
  if (sn == nullptr) {
    printf("%s() error, line %d, PublicKeyFromCert: Can't get subject name\n",
           __func__,
           __LINE__);
    res = false;
    goto done;
  }

  len = X509_NAME_get_text_by_NID(sn, NID_commonName, nullptr, 0);
  if (len < 0) {
    printf("%s() error, line %d, PublicKeyFromCert: Can't "
           "X509_NAME_get_text_by_NID length\n",
           __func__,
           __LINE__);
    res = false;
    goto done;
  }
  len++;
  {
    char name_buf[len];
    if (X509_NAME_get_text_by_NID(sn, NID_commonName, name_buf, len) < 0) {
      printf("%s() error, line %d, PublicKeyFromCert: Can't "
             "X509_NAME_get_text_by_NID\n",
             __func__,
             __LINE__);
      res = false;
    }
    subject_name_str.assign((const char *)name_buf);
  }
  if (!res)
    goto done;

  if (EVP_PKEY_base_id(epk) == EVP_PKEY_RSA) {
    const RSA *rk = nullptr;
    rk = EVP_PKEY_get0_RSA(epk);
    if (rk == nullptr) {
      printf("%s() error, line %d, PublicKeyFromCert: Can't get RSA key from "
             "evp\n",
             __func__,
             __LINE__);
      res = false;
      goto done;
    }
    if (!RSA_to_key(rk, k)) {
      printf("%s() error, line %d, PublicKeyFromCert: Can't get internal key "
             "from RSA key\n",
             __func__,
             __LINE__);
      res = false;
      goto done;
    }
  } else if (EVP_PKEY_base_id(epk) == EVP_PKEY_EC) {
    const EC_KEY *ek = EVP_PKEY_get0_EC_KEY(epk);
    if (ek == nullptr) {
      printf("%s() error, line %d, PublicKeyFromCert: Can't get ECC key from "
             "evp\n",
             __func__,
             __LINE__);
      res = false;
      goto done;
    }
    if (!ECC_to_key(ek, k)) {
      printf("%s() error, line %d, PublicKeyFromCert: Can't convert ECC key to "
             "internal key\n",
             __func__,
             __LINE__);
      res = false;
      goto done;
    }
  } else {
    res = false;
    goto done;
  }

  k->set_key_name(subject_name_str);
  k->set_key_format("vse-key");

  cert_str = new (string);
  cert_str->assign((char *)cert.data(), cert.size());
  k->set_allocated_certificate(cert_str);

#ifdef SEV_SNP
  // If we have VCEK in the policy in the future, this takes care of the
  // extensions.
  k->set_snp_tcb_version(get_tcb_version_from_vcek(x));
  memset(chipid, 0, CHIP_ID_SIZE);
  get_chipid_from_vcek(x, chipid, CHIP_ID_SIZE);
  k->set_snp_chipid(chipid, CHIP_ID_SIZE);
#endif  // SEV_SNP

done:
  if (epk != nullptr)
    EVP_PKEY_free(epk);
  if (x != nullptr)
    X509_free(x);
  return res;
}

#ifdef SEV_SNP
extern bool sev_Init(const string &platform_certs_file);
extern bool sev_GetParentEvidence(string *out);
extern bool sev_Seal(int in_size, byte *in, int *size_out, byte *out);
extern bool sev_Unseal(int in_size, byte *in, int *size_out, byte *out);
extern bool sev_Attest(int   what_to_say_size,
                       byte *what_to_say,
                       int * size_out,
                       byte *out);
#endif  // SEV_SNP

#ifdef ASYLO_CERTIFIER
extern bool asylo_Attest(int   claims_size,
                         byte *claims,
                         int * size_out,
                         byte *out);
extern bool asylo_Verify(int   claims_size,
                         byte *claims,
                         int * user_data_out_size,
                         byte *user_data_out,
                         int * size_out,
                         byte *out);
extern bool asylo_Seal(int in_size, byte *in, int *size_out, byte *out);
extern bool asylo_Unseal(int in_size, byte *in, int *size_out, byte *out);
#endif

#ifdef GRAMINE_CERTIFIER
extern bool gramine_Attest(const int what_to_say_size,
                           byte *    what_to_say,
                           int *     size_out,
                           byte *    out);
extern bool gramine_Verify(const int what_to_say_size,
                           byte *    what_to_say,
                           const int attestation_size,
                           byte *    attestation,
                           int *     size_out,
                           byte *    out);
extern bool gramine_Seal(int in_size, byte *in, int *size_out, byte *out);
extern bool gramine_Unseal(int in_size, byte *in, int *size_out, byte *out);
#endif

#ifdef KEYSTONE_CERTIFIER
extern bool keystone_Init(const int size, byte *der_cert);
extern bool keystone_Seal(int in_size, byte *in, int *size_out, byte *out);
extern bool keystone_Unseal(int in_size, byte *in, int *size_out, byte *out);
extern bool keystone_Attest(int   what_to_say_size,
                            byte *what_to_say,
                            int * size_out,
                            byte *out);
extern bool keystone_Verify(const int what_to_say_size,
                            byte *    what_to_say,
                            const int attestation_size,
                            byte *    attestation,
                            int *     measurement_out_size,
                            byte *    measurement_out);
#endif

#ifdef ISLET_CERTIFIER
#  include "islet_api.h"
#endif  // ISLET_CERTIFIER

// Buffer overflow check: Seal returns true and the buffer size in size_out.
// Check on Gramine.
bool certifier::framework::Seal(const string &enclave_type,
                                const string &enclave_id,
                                int           in_size,
                                byte *        in,
                                int *         size_out,
                                byte *        out) {

  if (enclave_type == "simulated-enclave") {
    return simulated_Seal(enclave_type, enclave_id, in_size, in, size_out, out);
  }
#ifdef OE_CERTIFIER
  if (enclave_type == "oe-enclave") {
    return oe_Seal(POLICY_UNIQUE, in_size, in, 0, NULL, size_out, out);
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
#ifdef KEYSTONE_CERTIFIER
  if (enclave_type == "keystone-enclave") {
    return keystone_Seal(in_size, in, size_out, out);
  }
#endif
#ifdef ISLET_CERTIFIER
  if (enclave_type == "islet-enclave") {
    return islet_Seal(in_size, in, size_out, out);
  }
#endif
  if (enclave_type == "application-enclave") {
    return application_Seal(in_size, in, size_out, out);
  }
  return false;
}

// Buffer overflow check: Done for SEV, OE, simulated enclave and application
// service. If out is NULL, Unseal returns true and the buffer size in size_out.
// Check Gramine.
bool certifier::framework::Unseal(const string &enclave_type,
                                  const string &enclave_id,
                                  int           in_size,
                                  byte *        in,
                                  int *         size_out,
                                  byte *        out) {

  if (enclave_type == "simulated-enclave") {
    return simulated_Unseal(enclave_type,
                            enclave_id,
                            in_size,
                            in,
                            size_out,
                            out);
  }
#ifdef OE_CERTIFIER
  if (enclave_type == "oe-enclave") {
    return oe_Unseal(in_size, in, 0, NULL, size_out, out);
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
#ifdef KEYSTONE_CERTIFIER
  if (enclave_type == "keystone-enclave") {
    return keystone_Unseal(in_size, in, size_out, out);
  }
#endif
#ifdef ISLET_CERTIFIER
  if (enclave_type == "islet-enclave") {
    return islet_Unseal(in_size, in, size_out, out);
  }
#endif  // ISLET_CERTIFIER
  if (enclave_type == "application-enclave") {
    return application_Unseal(in_size, in, size_out, out);
  }
  return false;
}

//  Buffer overflow check: Attest returns true and the buffer size in size_out.
//  Check on Gramine.
bool certifier::framework::Attest(const string &enclave_type,
                                  int           what_to_say_size,
                                  byte *        what_to_say,
                                  int *         size_out,
                                  byte *        out) {

  if (enclave_type == "simulated-enclave") {
    return simulated_Attest(enclave_type,
                            what_to_say_size,
                            what_to_say,
                            size_out,
                            out);
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
    ra.assign((char *)out, t_size_out);
    wws.assign((char *)what_to_say, what_to_say_size);
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
    memcpy(out,
           (byte *)serialized_gramine_at.data(),
           serialized_gramine_at.size());
    *size_out = serialized_gramine_at.size();
    return true;
  }
#endif
#ifdef KEYSTONE_CERTIFIER
  if (enclave_type == "keystone-enclave") {
    int t_size_out;
    int t_size = *size_out;
    if (!keystone_Attest(what_to_say_size, what_to_say, &t_size_out, out)) {
      printf("%s() error, line %d, keystone_Attest failed\n",
             __func__,
             __LINE__);
      return false;
    }
    string ra;
    string wws;
    ra.assign((char *)out, t_size_out);
    wws.assign((char *)what_to_say, what_to_say_size);
    keystone_attestation_message kam;
    kam.set_what_was_said(wws);
    kam.set_reported_attestation(ra);
    string serialized_keystone_at;
    if (!kam.SerializeToString(&serialized_keystone_at)) {
      printf("%s() error, line %d, serialize failed\n", __func__, __LINE__);
      return false;
    }
    if (*size_out < (int)serialized_keystone_at.size()) {
      printf("%s() error, line %d, serialize failed\n", __func__, __LINE__);
      return false;
    }
    memset(out, 0, *size_out);
    memcpy(out,
           (byte *)serialized_keystone_at.data(),
           serialized_keystone_at.size());
    *size_out = serialized_keystone_at.size();
    return true;
  }
#endif
#ifdef ISLET_CERTIFIER
  if (enclave_type == "islet-enclave") {
    int t_size_out;
    int t_size = *size_out;
    if (!islet_Attest(what_to_say_size, what_to_say, &t_size_out, out)) {
      printf("%s() error, line %d, islet_Attest failed\n", __func__, __LINE__);
      return false;
    }
    string ra;
    string wws;
    ra.assign((char *)out, t_size_out);
    wws.assign((char *)what_to_say, what_to_say_size);
    islet_attestation_message iam;
    iam.set_what_was_said(wws);
    iam.set_reported_attestation(ra);
    string serialized_islet_at;
    if (!iam.SerializeToString(&serialized_islet_at)) {
      printf("%s() error, line %d, Islet Serialize to string \n",
             __func__,
             __LINE__);
      return false;
    }
    if (*size_out < (int)serialized_islet_at.size()) {
      printf("%s() error, line %d, Islet output too small\n",
             __func__,
             __LINE__);
      return false;
    }
    memset(out, 0, *size_out);
    memcpy(out, (byte *)serialized_islet_at.data(), serialized_islet_at.size());
    *size_out = serialized_islet_at.size();
    return true;
  }
#endif  // ISLET_CERTIFIER
  if (enclave_type == "application-enclave") {
    return application_Attest(what_to_say_size, what_to_say, size_out, out);
  }

  return false;
}

bool GetParentEvidence(const string &enclave_type,
                       const string &parent_enclave_type,
                       string *      out) {
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
#ifdef KEYSTONE_CERTIFIER
  if (enclave_type == "keystone-enclave") {
    return false;
  }
#endif
#ifdef ISLET_CERTIFIER
  if (enclave_type == "islet-enclave") {
    return false;
  }
#endif
  if (enclave_type == "application-enclave") {
    return application_GetParentEvidence(out);
  }
  return false;
}

bool GetPlatformStatement(const string &enclave_type,
                          const string &enclave_id,
                          int *         size_out,
                          byte *        out) {
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

bool   certifier_parent_enclave_type_intitalized = false;
string certifier_parent_enclave_type;
bool   GetParentEnclaveType(string *type) {
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

bool certifier::framework::protect_blob(const string &enclave_type,
                                        key_message & key,
                                        int           size_unencrypted_data,
                                        byte *        unencrypted_data,
                                        int *         size_protected_blob,
                                        byte *        blob) {

  string serialized_key;
  if (!key.SerializeToString(&serialized_key)) {
    printf("%s() error, line %d, protect_blob can't serialize key\n",
           __func__,
           __LINE__);
    return false;
  }

  int  size_sealed_key = serialized_key.size() + max_key_seal_pad;
  byte sealed_key[size_sealed_key];
  memset(sealed_key, 0, size_sealed_key);
  string enclave_id("enclave-id");

  if (!Seal(enclave_type,
            enclave_id,
            serialized_key.size(),
            (byte *)serialized_key.data(),
            &size_sealed_key,
            sealed_key)) {
    printf("%s() error, line %d, protect_blob can't seal\n",
           __func__,
           __LINE__);
    return false;
  }

  byte iv[block_size];
  if (!get_random(8 * block_size, iv)) {
    printf("%s() error, line %d, protect_blob can't get random number\n",
           __func__,
           __LINE__);
    return false;
  }
  if (!key.has_secret_key_bits()) {
    printf("%s() error, line %d, protect_blob: no key bits\n",
           __func__,
           __LINE__);
    return false;
  }
  byte *key_buf = (byte *)key.secret_key_bits().data();
  if (key.secret_key_bits().size() < protect_key_size) {
    printf("%s() error, line %d, protect_blob: key too small\n",
           __func__,
           __LINE__);
    return false;
  }

  int  size_encrypted = size_unencrypted_data + max_key_seal_pad;
  byte encrypted_data[size_encrypted];
  if (!authenticated_encrypt(key.key_type().c_str(),
                             unencrypted_data,
                             size_unencrypted_data,
                             key_buf,
                             key.secret_key_bits().size(),
                             iv,
                             16,
                             encrypted_data,
                             &size_encrypted)) {
    printf(
        "%s() error, line %d, protect_blob: authenticate encryption failed\n",
        __func__,
        __LINE__);
    return false;
  }

  protected_blob_message blob_msg;
  blob_msg.set_encrypted_key((void *)sealed_key, size_sealed_key);
  blob_msg.set_encrypted_data((void *)encrypted_data, size_encrypted);

  string serialized_blob;
  blob_msg.SerializeToString(&serialized_blob);
  if (((int)serialized_blob.size()) > *size_protected_blob) {
    printf("%s() error, line %d, protect_blob: furnished buffer is too small\n",
           __func__,
           __LINE__);
    return false;
  }
  *size_protected_blob = (int)serialized_blob.size();
  memcpy(blob, (byte *)serialized_blob.data(), *size_protected_blob);
  return true;
}

bool certifier::framework::unprotect_blob(const string &enclave_type,
                                          int           size_protected_blob,
                                          byte *        protected_blob,
                                          key_message * key,
                                          int * size_of_unencrypted_data,
                                          byte *unencrypted_data) {

  string protected_blob_string;
  protected_blob_string.assign((char *)protected_blob, size_protected_blob);
  protected_blob_message pb;
  if (!pb.ParseFromString(protected_blob_string)) {
    printf("%s() error, line %d, unprotect_blob: can't parse protected blob "
           "message\n",
           __func__,
           __LINE__);
    return false;
  }
  if (!pb.has_encrypted_key()) {
    printf("%s() error, line %d, unprotect_blob: no encryption key\n",
           __func__,
           __LINE__);
    return false;
  }
  if (!pb.has_encrypted_data()) {
    printf("%s() error, line %d, unprotect_blob: no encrypted data\n",
           __func__,
           __LINE__);
    return false;
  }

  int  size_unsealed_key = pb.encrypted_key().size();
  byte unsealed_key[size_unsealed_key];
  memset(unsealed_key, 0, size_unsealed_key);
  string enclave_id("enclave-id");

  // Unseal header
  if (!Unseal(enclave_type,
              enclave_id,
              pb.encrypted_key().size(),
              (byte *)pb.encrypted_key().data(),
              &size_unsealed_key,
              unsealed_key)) {
    printf("%s() error, line %d, unprotect_blob: can't unseal\n",
           __func__,
           __LINE__);
    return false;
  }

  string serialized_key;
  serialized_key.assign((const char *)unsealed_key, size_unsealed_key);
  if (!key->ParseFromString(serialized_key)) {
    printf("%s() error, line %d, unprotect_blob: can't parse unsealed key\n",
           __func__,
           __LINE__);
    return false;
  }

  if (key->key_type() != Enc_method_aes_256_cbc_hmac_sha256) {
    printf("%s() error, line %d, unprotect_blob, unsupported encryption "
           "scheme: '%s'\n",
           __func__,
           __LINE__,
           key->key_type().c_str());
    return false;
  }
  if (!key->has_secret_key_bits()) {
    printf("%s() error, line %d, unprotect_blob: no key bits\n",
           __func__,
           __LINE__);
    return false;
  }
  byte *key_buf = (byte *)key->secret_key_bits().data();
  if (key->secret_key_bits().size() < protect_key_size) {
    printf("%s() error, line %d, unprotect_blob: key too small\n",
           __func__,
           __LINE__);
    return false;
  }
  int key_len = key->secret_key_bits().size();

  // decrypt encrypted data
  if (!authenticated_decrypt(key->key_type().c_str(),
                             (byte *)pb.encrypted_data().data(),
                             pb.encrypted_data().size(),
                             key_buf,
                             key_len,
                             unencrypted_data,
                             size_of_unencrypted_data)) {
    printf(
        "%s() error, line %d, unprotect_blob: authenticated decrypt failed\n",
        __func__,
        __LINE__);
    return false;
  }
  return true;
}

bool certifier::framework::reprotect_blob(const string &enclave_type,
                                          key_message * key,
                                          int           size_protected_blob,
                                          byte *        protected_blob,
                                          int *         size_new_encrypted_blob,
                                          byte *        data) {

  key_message new_key;
  int         size_unencrypted_data = size_protected_blob;
  byte        unencrypted_data[size_unencrypted_data];

  if (!unprotect_blob(enclave_type,
                      size_protected_blob,
                      protected_blob,
                      &new_key,
                      &size_unencrypted_data,
                      unencrypted_data)) {
    printf("%s() error, line %d, reprotect_blob: Can't unprotect\n",
           __func__,
           __LINE__);
    return false;
  }

  // Generate new key
  int size_byte_key = cipher_key_byte_size(new_key.key_type().c_str());
  if (size_byte_key <= 0) {
    printf("%s() error, line %d, reprotect_blob: Can't get key size\n",
           __func__,
           __LINE__);
    return false;
  }
  if (new_key.secret_key_bits().size() < (size_t)size_byte_key) {
    printf("%s() error, line %d, reprotect_blob: key buffer too small\n",
           __func__,
           __LINE__);
    return false;
  }
  if (!get_random(8 * size_byte_key,
                  (byte *)new_key.secret_key_bits().data())) {
    printf("%s() error, line %d, reprotect_blob: Can't generate key\n",
           __func__,
           __LINE__);
    return false;
  }

  if (!protect_blob(enclave_type,
                    new_key,
                    size_unencrypted_data,
                    unencrypted_data,
                    size_new_encrypted_blob,
                    data)) {
    printf("%s() error, line %d, reprotect_blob: Can't Protect\n",
           __func__,
           __LINE__);
    return false;
  }
  return true;
}

// -------------------------------------------------------------------

bool certifier::utilities::check_date_range(const string &nb,
                                            const string &na) {
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

void print_evidence(const evidence &ev) {
  if (ev.has_evidence_type()) {
    printf("Evidence type: %s\n", ev.evidence_type().c_str());
    if (ev.evidence_type() == "signed-claim") {
      string sc_st;
      sc_st.assign((char *)ev.serialized_evidence().data(),
                   ev.serialized_evidence().size());
      signed_claim_message sc;
      if (sc.ParseFromString(sc_st))
        print_signed_claim(sc);
    }
    if (ev.evidence_type() == "oe-attestation-report") {
      print_bytes(ev.serialized_evidence().size(),
                  (byte *)ev.serialized_evidence().data());
      printf("\n");
    }
    if (ev.evidence_type() == "asylo-evidence") {
      print_bytes(ev.serialized_evidence().size(),
                  (byte *)ev.serialized_evidence().data());
      printf("\n");
    }
    if (ev.evidence_type() == "gramine-evidence") {
      print_bytes(ev.serialized_evidence().size(),
                  (byte *)ev.serialized_evidence().data());
      printf("\n");
    }
    if (ev.evidence_type() == "keystone-evidence") {
      print_bytes(ev.serialized_evidence().size(),
                  (byte *)ev.serialized_evidence().data());
      printf("\n");
    }
    if (ev.evidence_type() == "islet-evidence") {
      print_bytes(ev.serialized_evidence().size(),
                  (byte *)ev.serialized_evidence().data());
      printf("\n");
    }
    if (ev.evidence_type() == "cert") {
      printf("Cert: ");
      print_bytes(ev.serialized_evidence().size(),
                  (byte *)ev.serialized_evidence().data());
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
      print_bytes(ev.serialized_evidence().size(),
                  (byte *)ev.serialized_evidence().data());
      printf("\n");
    }
  }
}

void print_evidence_package(const evidence_package &evp) {
  printf("Evidence package.  Prover: %s\n", evp.prover_type().c_str());
  for (int i = 0; i < evp.fact_assertion_size(); i++) {
    printf("%02d: \n", i);
    print_evidence(evp.fact_assertion(i));
    printf("\n");
  }
}

void print_trust_request_message(trust_request_message &m) {
  if (m.has_requesting_enclave_tag()) {
    printf("Requesting enclave     :  %s\n",
           m.requesting_enclave_tag().c_str());
  }
  if (m.has_providing_enclave_tag()) {
    printf("Providing  enclave     :  %s\n", m.providing_enclave_tag().c_str());
  }
  if (m.has_purpose()) {
    printf("Purpose                :  %s\n", m.purpose().c_str());
  }
  if (m.has_submitted_evidence_type()) {
    printf("Evidence type          :  %s\n",
           m.submitted_evidence_type().c_str());
  }
  if (m.support().has_prover_type()) {
    printf("Prover type: %s\n", m.support().prover_type().c_str());
  }
}

void print_trust_response_message(trust_response_message &m) {
  if (m.has_status()) {
    printf("Status                 :  %s\n", m.status().c_str());
  }
  if (m.has_requesting_enclave_tag()) {
    printf("Requesting enclave     :  %s\n",
           m.requesting_enclave_tag().c_str());
  }
  if (m.has_providing_enclave_tag()) {
    printf("Providing  enclave     :  %s\n", m.providing_enclave_tag().c_str());
  }
  if (m.has_artifact()) {
    printf("Artifact               : \n");
    print_bytes((int)m.artifact().size(), (byte *)m.artifact().data());
    printf("\n");
  }
}

void print_proof_step(const proof_step &ps) {
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

void print_proof(proof &pf) {
  printf("\nproof steps:\n");
  for (int i = 0; i < pf.steps_size(); i++) {
    printf("\n%2d: ", i);
    print_proof_step(pf.steps(i));
    printf("\n");
  }
}

void print_attestation_info(vse_attestation_report_info &r) {
  printf("\nvse attestation report\n");
  if (r.has_enclave_type()) {
    printf("Enclave type: %s\n", r.enclave_type().c_str());
  }
  if (r.has_verified_measurement()) {
    printf("Measurement: ");
    print_bytes(r.verified_measurement().size(),
                (byte *)r.verified_measurement().data());
    printf("\n");
  }
  if (r.has_not_before() && r.has_not_after()) {
    printf("Not before : %s\n", r.not_before().c_str());
    printf("Not after  : %s\n", r.not_after().c_str());
  }
  if (r.has_user_data()) {
    printf("User data  : ");
    print_bytes(r.user_data().size(), (byte *)r.user_data().data());
    printf("\n");
  }
  printf("\n");
}

void print_user_data(attestation_user_data &ud) {
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

void print_signed_report(const signed_report &sr) {
  printf("\nSigned report\n");
  if (sr.has_report_format()) {
    printf("Report format: %s\n", sr.report_format().c_str());
  }
  if (sr.has_report()) {
    printf("Report     :\n");
    print_bytes(sr.report().size(), (byte *)sr.report().data());
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
    print_bytes(sr.signature().size(), (byte *)sr.signature().data());
    printf("\n");
  }
  printf("\n");
}

bool read_signed_vse_statements(const string &in, signed_claim_sequence *s) {
  string str;
  if (!read_file_into_string(in, &str)) {
    printf("read_signed_vse_statements: Can't read %s\n", in.c_str());
    return false;
  }
  if (!s->ParseFromString(str)) {
    printf("%s() error, line %d, read_signed_vse_statements: Can't parse claim "
           "sequence\n",
           __func__,
           __LINE__);
    return false;
  }
  return true;
}

// -----------------------------------------------------------------------------
