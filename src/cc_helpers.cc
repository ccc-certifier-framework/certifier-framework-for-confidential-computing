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

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/err.h>

#include "support.h"
#include "certifier.h"
#include "simulated_enclave.h"
#include "application_enclave.h"
#include "cc_helpers.h"
#ifdef GRAMINE_CERTIFIER
#  include "gramine_api.h"
#endif
#include "cc_useful.h"

#ifdef KEYSTONE_CERTIFIER
#  include "keystone_api.h"
#endif

#ifdef ISLET_CERTIFIER
#  include "islet_api.h"
#endif  // ISLET_CERTIFIER

#ifdef SEV_SNP
#  include "sev_support.h"
#endif  // SEV_SNP

using namespace certifier::framework;
using namespace certifier::utilities;

#ifdef SEV_SNP
extern bool   sev_Init(const string &ark_der,
                       const string &ask_der,
                       const string &vcek_der);
extern bool   plat_certs_initialized;
extern string platform_certs;
extern string serialized_ark_cert;
extern string serialized_ask_cert;
extern string serialized_vcek_cert;
#endif

#if OE_CERTIFIER
extern bool   oe_Init(const string &pem_cert_chain_file);
extern string pem_cert_chain;
#endif

#ifdef GRAMINE_CERTIFIER
extern bool   gramine_platform_cert_initialized;
extern string gramine_platform_cert;
#endif

//  This is a collection of functions that accomplish almost all the
//  Confidential Computing functions for basic enclaves including:
//    Initializing policy key information
//    Initializing authentication key (if purpose is "authentication")
//    Initializing service key (if purpose is "attestation")
//    Initializing symmetric keys (if purpose is "authentication")
//    Initializing sealing keys (if purpose is "attestation")
//    Encrypting and saving the policy store
//    Reading and decrypting the policy store and filling in trust data from it
//
//  You may want to augment these or write replacements if your needs are
//  fancier.

//#define DEBUG

certifier::framework::accelerator::accelerator() {
  num_certs_ = 0;
  certs_ = nullptr;
  verified_ = false;
}

certifier::framework::accelerator::~accelerator() {
  if (num_certs_ > 0) {
    delete[] certs_;
    certs_ = nullptr;
  }
  verified_ = false;
}

certifier::framework::cc_trust_manager::cc_trust_manager(
    const string &enclave_type,
    const string &purpose,
    const string &policy_store_name) {
  cc_trust_manager_default_init();
  if (purpose == "authentication" || purpose == "attestation") {
    purpose_ = purpose;
    cc_basic_data_initialized_ = true;
  }
  enclave_type_ = enclave_type;
  store_file_name_ = policy_store_name;
}

certifier::framework::cc_trust_manager::cc_trust_manager() {
  cc_trust_manager_default_init();
}

void certifier::framework::cc_trust_manager::cc_trust_manager_default_init() {
  cc_basic_data_initialized_ = false;
  purpose_ = "unknown";
  cc_policy_info_initialized_ = false;
  cc_policy_store_initialized_ = false;
  cc_service_key_initialized_ = false;
  cc_service_cert_initialized_ = false;
  cc_service_platform_rule_initialized_ = false;
  cc_sealing_key_initialized_ = false;
  cc_provider_provisioned_ = false;
  x509_policy_cert_ = nullptr;
  cc_is_certified_ = false;
  peer_data_initialized_ = false;
  num_accelerators_ = 0;
  max_num_certified_domains_ = MAX_NUM_CERTIFIERS;
  num_certified_domains_ = 0;
  certified_domains_ = new certifiers *[max_num_certified_domains_];
  for (int i = 0; i < max_num_certified_domains_; i++) {
    certified_domains_[i] = nullptr;
  }
}

certifier::framework::cc_trust_manager::~cc_trust_manager() {
  for (int i = 0; i < num_certified_domains_; i++) {
    if (certified_domains_[i] != nullptr) {
      delete certified_domains_[i];
      certified_domains_[i] = nullptr;
    }
  }
  delete certified_domains_;
  certified_domains_ = nullptr;
  num_certified_domains_ = 0;
}

bool certifier::framework::cc_trust_manager::initialize_enclave(
    int     n,
    string *params) {

  if (enclave_type_ == "simulated-enclave") {

    if (n < 3) {
      printf("%s() error, line %d, Wrong number of arguments\n",
             __func__,
             __LINE__);
      return false;
    }
    return initialize_simulated_enclave(params[0], params[1], params[2]);
  } else if (enclave_type_ == "sev-enclave") {

    if (n == 0) {
#ifdef SEV_SNP
      // Fetch platform certificates using extended guest request
      string ark, ask, vcek;
      if (sev_get_platform_certs(&vcek, &ask, &ark) != EXIT_SUCCESS) {
        printf("%s() error, line %d, Failed to fetch platform certs\n",
               __func__,
               __LINE__);
      }
      return initialize_sev_enclave(ark, ask, vcek);
#else
      printf("%s() error, line %d, Wrong number of sev parameters\n",
             __func__,
             __LINE__);
      return false;
#endif  // SEV_SNP
    } else if (n < 3) {
      printf("%s() error, line %d, Wrong number of sev parameters\n",
             __func__,
             __LINE__);
      return false;
    }
    return initialize_sev_enclave(params[0], params[1], params[2]);
  } else if (enclave_type_ == "oe-enclave") {
    return initialize_oe_enclave(params[0]);
  } else if (enclave_type_ == "gramine-enclave") {

    if (n == 0) {
      // Fetch params
      printf(
          "%s() error, line %d, Can't fetch sev parameters automatically yet\n",
          __func__,
          __LINE__);
      return false;
    }

    if (n < 1) {
      printf("%s() error, line %d, Wrong number of gramine parameters\n",
             __func__,
             __LINE__);
      return false;
    }
    return initialize_gramine_enclave(params[0].size(),
                                      (byte *)params[0].data());
  } else if (enclave_type_ == "application-enclave") {
    if (n < 3) {
      printf("%s() error, line %d, Wrong number of application enclave "
             "parameters\n",
             __func__,
             __LINE__);
      return false;
    }
    int in_fd = atoi(params[1].c_str());
    int out_fd = atoi(params[2].c_str());
    return initialize_application_enclave(params[0], in_fd, out_fd);
  } else if (enclave_type_ == "keystone-enclave") {
    return initialize_keystone_enclave();
  } else if (enclave_type_ == "islet-enclave") {
    return initialize_islet_enclave();
  } else {
    printf("%s() error, line %d, unsupported enclave type\n",
           __func__,
           __LINE__);
    return false;
  }
}

bool certifier::framework::cc_trust_manager::cc_all_initialized() {
  if (purpose_ == "authentication") {
    return cc_basic_data_initialized_ & cc_auth_key_initialized_
           & cc_symmetric_key_initialized_ & cc_policy_info_initialized_
           & cc_provider_provisioned_ & cc_policy_store_initialized_;
  } else if (purpose_ == "attestation") {
    return cc_basic_data_initialized_ & cc_service_key_initialized_
           & cc_sealing_key_initialized_ & cc_policy_info_initialized_
           & cc_service_platform_rule_initialized_ & cc_provider_provisioned_
           & cc_policy_store_initialized_;
  } else {
    return false;
  }
}

bool certifier::framework::cc_trust_manager::initialize_application_enclave(
    const string &parent_enclave_type,
    int           in_fd,
    int           out_fd) {

  if (!cc_policy_info_initialized_) {
    printf("%s() error, line %d, Policy key must be initialized first\n",
           __func__,
           __LINE__);
    return false;
  }

  if (enclave_type_ != "application-enclave") {
    printf("%s() error, line %d, Not a application enclave\n",
           __func__,
           __LINE__);
    return false;
  }
  if (!application_Init(parent_enclave_type, in_fd, out_fd)) {
    printf("%s() error, line %d, Can't init application-enclave\n",
           __func__,
           __LINE__);
    return false;
  }
  cc_provider_provisioned_ = true;
  return true;
}

bool certifier::framework::cc_trust_manager::initialize_simulated_enclave(
    const string &serialized_attest_key,
    const string &measurement,
    const string &serialized_attest_endorsement) {

  if (!cc_policy_info_initialized_) {
    printf("%s() error, line %d, Policy key must be initialized first\n",
           __func__,
           __LINE__);
    return false;
  }

  if (enclave_type_ != "simulated-enclave") {
    printf("%s() error, line %d, Not a simulated enclave\n",
           __func__,
           __LINE__);
    return false;
  }
  if (!simulated_Init(serialized_attest_key,
                      measurement,
                      serialized_attest_endorsement)) {
    printf("%s() error, line %d, simulated_init failed\n", __func__, __LINE__);
    return false;
  }
  cc_provider_provisioned_ = true;
  return true;
}

// Wrapper interface used for Python bindings.
bool certifier::framework::cc_trust_manager::
    python_initialize_simulated_enclave(
        const byte *serialized_attest_key,
        int         attest_key_size,
        const byte *measurement,
        int         measurement_size,
        const byte *serialized_attest_endorsement,
        int         attest_endorsement_size) {

  return initialize_simulated_enclave(
      string((const char *)serialized_attest_key, attest_key_size),
      string((const char *)measurement, measurement_size),
      string((const char *)serialized_attest_endorsement,
             attest_endorsement_size));
}

bool certifier::framework::cc_trust_manager::initialize_gramine_enclave(
    const int size,
    byte *    cert) {
#ifdef GRAMINE_CERTIFIER
  return gramine_Init(size, cert);
#endif
  return true;
}

bool certifier::framework::cc_trust_manager::initialize_sev_enclave(
    const string &ark_der,
    const string &ask_der,
    const string &vcek_der) {

#ifdef SEV_SNP
  if (!sev_Init(ark_der, ask_der, vcek_der)) {
    printf("%s() error, line %d, sev_Init failed\n", __func__, __LINE__);
    return false;
  }

  cc_provider_provisioned_ = true;
  return true;
#else
  return false;
#endif
}

bool certifier::framework::cc_trust_manager::initialize_oe_enclave(
    const string &pem_cert_chain_file) {
#if OE_CERTIFIER
  cc_provider_provisioned_ = true;

  if (!oe_Init(pem_cert_chain_file)) {
    printf("%s() error, line %d, oe_Init failed\n", __func__, __LINE__);
    return false;
  }
  cc_provider_provisioned_ = true;
  return true;
#else
  return false;
#endif
}

bool certifier::framework::cc_trust_manager::accelerator_verified(
    const string &acc_type) {
  for (int i = 0; i < num_accelerators_; i++) {
    if (acc_type == accelerators_[i].accelerator_type_)
      return accelerators_[i].verified_;
  }
  return false;
}

bool certifier::framework::cc_trust_manager::add_accelerator(
    const string &acc_type,
    int           num_certs,
    string *      certs) {
  return false;
}

bool certifier::framework::cc_trust_manager::init_policy_key(
    byte *asn1_cert,
    int   asn1_cert_size) {
  serialized_policy_cert_.assign((char *)asn1_cert, asn1_cert_size);

  x509_policy_cert_ = X509_new();
  if (x509_policy_cert_ == nullptr)
    return false;
  if (!asn1_to_x509(serialized_policy_cert_, x509_policy_cert_)) {
    printf("%s() error, line %d, Can't translate cert\n", __func__, __LINE__);
    return false;
  }
  if (!PublicKeyFromCert(serialized_policy_cert_, &public_policy_key_)) {
    printf("%s() error, line %d, Can't get public policy key\n",
           __func__,
           __LINE__);
    return false;
  }
  cc_policy_info_initialized_ = true;
  return true;
}

bool certifier::framework::cc_trust_manager::initialize_keystone_enclave() {

#ifdef KEYSTONE_CERTIFIER
  if (!cc_policy_info_initialized_) {
    printf("%s() error, line %d, Policy key must be initialized first\n",
           __func__,
           __LINE__);
    return false;
  }

  if (enclave_type_ != "keystone-enclave") {
    printf("%s() error, line %d, Not a simulated enclave\n",
           __func__,
           __LINE__);
    return false;
  }

  // TODO
  byte der_cert[250];
  if (!keystone_Init(0, der_cert)) {
    printf("%s() error, line %d, keystone_init failed\n", __func__, __LINE__);
    return false;
  }
  cc_provider_provisioned_ = true;

  return true;
#else
  return false;
#endif
}

bool certifier::framework::cc_trust_manager::initialize_islet_enclave() {

#ifdef ISLET_CERTIFIER
  if (!cc_policy_info_initialized_) {
    printf("%s(): Policy key must be initialized first\n", __func__);
    return false;
  }

  if (enclave_type_ != "islet-enclave") {
    printf("%s(): '%s' is not a simulated enclave\n",
           __func__,
           enclave_type_.c_str());
    return false;
  }
  // TODO
  byte der_cert[100];
  if (!islet_Init(0, der_cert)) {
    printf("%s(): islet_Init failed\n", __func__);
    return false;
  }
  cc_provider_provisioned_ = true;

  return true;
#else
  return false;
#endif
}


void certifier::framework::cc_trust_manager::print_trust_data() {
  if (!cc_basic_data_initialized_) {
    printf("%s() error, line %d, No trust info initialized\n",
           __func__,
           __LINE__);
    return;
  }
  printf("\nTrust data, enclave_type: %s, purpose: %s, policy file: %s\n",
         enclave_type_.c_str(),
         purpose_.c_str(),
         store_file_name_.c_str());

  if (cc_policy_info_initialized_) {
    printf("\nPolicy key\n");
    print_key(public_policy_key_);
    printf("\nPolicy cert\n");
    print_bytes(serialized_policy_cert_.size(),
                (byte *)serialized_policy_cert_.data());
    printf("\n");
  }

  if (cc_auth_key_initialized_) {
    printf("\nPrivate auth key\n");
    print_key(private_auth_key_);
    printf("\nPublic auth key\n");
    print_key(public_auth_key_);
    printf("\n\n");
  }
  if (cc_service_key_initialized_) {
    printf("\nPrivate service key\n");
    print_key(private_service_key_);
    printf("\nPublic service key\n");
    print_key(public_service_key_);
    printf("\n\n");
  }

  if (cc_symmetric_key_initialized_) {
    printf("\nSymmetric key\n");
    print_key(symmetric_key_);
    printf("\n\n");
  }
  if (cc_sealing_key_initialized_) {
    printf("\nSealing key\n");
    print_key(service_sealing_key_);
    printf("\n\n");
  }

  if (cc_service_cert_initialized_) {
    printf("Serialized service cert:\n");
    print_bytes(serialized_service_cert_.size(),
                (byte *)serialized_service_cert_.data());
    printf("\n\n");
  }

  if (cc_service_platform_rule_initialized_) {
    printf("platform rule:\n");
    print_signed_claim(platform_rule_);
  }

  if (cc_basic_data_initialized_) {
    printf("cc_basic_data_initialized_ is true\n");
  } else {
    printf("cc_basic_data_initialized_ is false\n");
  }
  if (cc_policy_info_initialized_) {
    printf("cc_policy_info_initialized_ is true\n");
  } else {
    printf("cc_policy_info_initialized_ is false\n");
  }
  if (cc_provider_provisioned_) {
    printf("cc_provider_provisioned_ is true\n");
  } else {
    printf("cc_provider_provisioned_ is false\n");
  }
  if (cc_is_certified_) {
    printf("cc_is_certified_ is true\n");
  } else {
    printf("cc_is_certified_ is false\n");
  }
  if (cc_auth_key_initialized_) {
    printf("cc_auth_key_initialized_ is true\n");
  } else {
    printf("cc_auth_key_initialized_ is false\n");
  }
  if (cc_symmetric_key_initialized_) {
    printf("cc_symmetric_key_initialized_ is true\n");
  } else {
    printf("cc_symmetric_key_initialized_ is false\n");
  }
  if (cc_service_key_initialized_) {
    printf("cc_service_key_initialized_ is true\n");
  } else {
    printf("cc_service_key_initialized_ is false\n");
  }
  if (cc_service_cert_initialized_) {
    printf("cc_service_cert_initialized_ is true\n");
  } else {
    printf("cc_service_cert_initialized_ is false\n");
  }
  if (cc_service_platform_rule_initialized_) {
    printf("cc_service_platform_rule_initialized_ is true\n");
  } else {
    printf("cc_service_platform_rule_initialized_ is false\n");
  }
  if (cc_sealing_key_initialized_) {
    printf("cc_sealing_key_initialized_ is true\n");
  } else {
    printf("cc_sealing_key_initialized_ is false\n");
  }
  if (cc_policy_store_initialized_) {
    printf("cc_policy_store_initialized_ is true\n");
  } else {
    printf("cc_policy_store_initialized_ is false\n");
  }
  if (cc_all_initialized()) {
    printf("all initialized\n");
  } else {
    printf("all not initialized\n");
  }

  printf("Number of certifiers: %d\n", num_certified_domains_);
  for (int i = 0; i < num_certified_domains_; i++) {
    certified_domains_[i]->print_certifiers_entry();
  }
}

const int max_pad_size_for_store = 1024;

bool certifier::framework::cc_trust_manager::save_store() {

#if 0
  printf("Saved trust data:\n");
  print_trust_data();
  printf("\n");
  printf("End saved trust data\n");
#endif

  string serialized_store;
  if (!store_.Serialize(&serialized_store)) {
    printf("%s() error, line %d, save_store() can't serialize store\n",
           __func__,
           __LINE__);
    return false;
  }

  int  size_protected_blob = serialized_store.size() + max_pad_size_for_store;
  byte protected_blob[size_protected_blob];

  byte pkb[max_symmetric_key_size_];
  memset(pkb, 0, max_symmetric_key_size_);

  int num_key_bytes = cipher_key_byte_size(symmetric_key_algorithm_.c_str());
  if (num_key_bytes <= 0) {
    printf("%s() error, line %d, can't get key size\n", __func__, __LINE__);
    return false;
  }
  if (!get_random(8 * num_key_bytes, pkb)) {
    printf("%s() error, line %d, can't generate key\n", __func__, __LINE__);
    return false;
  }
  key_message pk;
  pk.set_key_name("protect-key");
  pk.set_key_type(symmetric_key_algorithm_);
  pk.set_key_format("vse-key");
  pk.set_secret_key_bits(pkb, num_key_bytes);

  if (!protect_blob(enclave_type_,
                    pk,
                    serialized_store.size(),
                    (byte *)serialized_store.data(),
                    &size_protected_blob,
                    protected_blob)) {
    printf("%s() error, line %d, can't protect blob\n", __func__, __LINE__);
    return false;
  }

  if (!write_file(store_file_name_, size_protected_blob, protected_blob)) {
    printf("%s() error, line %d, Save_store can't write %s\n",
           __func__,
           __LINE__,
           store_file_name_.c_str());
    return false;
  }
  return true;
}

bool certifier::framework::cc_trust_manager::fetch_store() {

  int size_protected_blob = file_size(store_file_name_);
  if (size_protected_blob < 0) {
    printf("%s(): Invalid size_protected_blob=%d for store file name='%s'\n",
           __func__,
           size_protected_blob,
           store_file_name_.c_str());
    return false;
  }
  byte protected_blob[size_protected_blob];
  int  size_unprotected_blob = size_protected_blob;
  byte unprotected_blob[size_unprotected_blob];

  memset(protected_blob, 0, size_protected_blob);
  memset(unprotected_blob, 0, size_unprotected_blob);

  if (!read_file(store_file_name_, &size_protected_blob, protected_blob)) {
    printf("%s(): Can't read %s\n", __func__, store_file_name_.c_str());
    return false;
  }

  key_message pk;
  pk.set_key_name("protect-key");
  pk.set_key_type(Enc_method_aes_256_cbc_hmac_sha256);
  pk.set_key_format("vse-key");

  if (!unprotect_blob(enclave_type_,
                      size_protected_blob,
                      protected_blob,
                      &pk,
                      &size_unprotected_blob,
                      unprotected_blob)) {
    printf("%s(): Can't Unprotect\n", __func__);
    return false;
  }

  // read policy store
  string serialized_store;
  serialized_store.assign((char *)unprotected_blob, size_unprotected_blob);
  if (!store_.Deserialize(serialized_store)) {
    printf("%s(): Can't deserialize store\n", __func__);
    return false;
  }

  return true;
}

void certifier::framework::cc_trust_manager::clear_sensitive_data() {
  // Clear symmetric and private keys.
  // Not necessary on most platforms.
}

//  cc_trust_manager relies on the following data in the store
//    public_policy_key
//    public_key_algorithm
//    symmetric_key_algorithm
//    For attestation
//      service-attest-key
//      sealing-key
//    For authentication
//      auth-key
//      app-symmetric-key
//    Some platforms require obtaining a platform rule; in that case, it
//    will also be stored.
//  initialized cert is in the array initialized_cert with size
//  initialized_cert_size These are set in embed+policy_key.cc.
bool certifier::framework::cc_trust_manager::put_trust_data_in_store() {

#if 0
  store_.policy_key_.CopyFrom(public_policy_key_);
  store_.policy_key_valid_ = true;
#endif

  const string string_type("string");
  const string key_type("key");
  const string signed_claim_type("signed_claim");

  const string symmetric_key_algorithm_tag("symmetric-key-algorithm");
  const string public_key_alg_tag("public-key-algorithm");
  const string service_key_tag("service-attest-key");
  const string sealing_key_tag("sealing-key");

  string value;

  if (!store_.update_or_insert(public_key_alg_tag,
                               string_type,
                               public_key_algorithm_)) {
    printf("%s() error, line %d, can't set public key algorithm\n",
           __func__,
           __LINE__);
    return false;
  }

  const string symmetric_key_algorithm_type("symmetric-key-algorithm");
  if (!store_.update_or_insert(symmetric_key_algorithm_tag,
                               string_type,
                               symmetric_key_algorithm_)) {
    printf("%s() error, line %d, can't set symmetric key algorithm\n",
           __func__,
           __LINE__);
    return false;
  }

  if (purpose_ == "attestation") {

    // put private service key and symmetric keys in store
    value.clear();
    if (!private_service_key_.SerializeToString(&value)) {
      printf("%s() error, line %d, can't serialize private service key\n",
             __func__,
             __LINE__);
      return false;
    }
    if (!store_.update_or_insert(service_key_tag, key_type, value)) {
      printf("%s() error, line %d, can't set private service key\n",
             __func__,
             __LINE__);
      return false;
    }
    string sealing_key_tag("sealing-key");
    value.clear();
    if (!service_sealing_key_.SerializeToString(&value)) {
      printf("%s() error, line %d, can't serialize sealing key\n",
             __func__,
             __LINE__);
      return false;
    }
    if (!store_.update_or_insert(sealing_key_tag, key_type, value)) {
      printf("%s() error, line %d, can't set sealing key\n",
             __func__,
             __LINE__);
      return false;
    }

    if (cc_service_platform_rule_initialized_) {
      string rule_tag("platform-rule");
      value.clear();
      if (!platform_rule_.SerializeToString(&value)) {
        printf("%s() error, line %d, can't serialize platform rule\n",
               __func__,
               __LINE__);
        return false;
      }
      if (!store_.update_or_insert(rule_tag, signed_claim_type, value)) {
        printf("%s() error, line %d, can't set platform rule\n",
               __func__,
               __LINE__);
        return false;
      }
    }

    if (!put_certifiers_in_store()) {
      printf("%s() error, line %d, can't set certifiers data\n",
             __func__,
             __LINE__);
      return false;
    }
    return true;
  }

  if (purpose_ == "authentication") {

    string auth_tag("auth-key");
    string symmetric_key_tag("app-symmetric-key");

    value.clear();
    if (!private_auth_key_.SerializeToString(&value)) {
      printf("%s() error, line %d, can't serialize auth-key\n",
             __func__,
             __LINE__);
      return false;
    }
    if (!store_.update_or_insert(auth_tag, key_type, value)) {
      printf("%s() error, line %d, can't set serialized auth-key\n",
             __func__,
             __LINE__);
      return false;
    }
    value.clear();
    if (!symmetric_key_.SerializeToString(&value)) {
      printf("%s() error, line %d, can't serialize app symmetric key\n",
             __func__,
             __LINE__);
      return false;
    }
    if (!store_.update_or_insert(symmetric_key_tag, key_type, value)) {
      printf("%s() error, line %d, can't set serialized app symmetric key\n",
             __func__,
             __LINE__);
      return false;
    }

    if (!put_certifiers_in_store()) {
      printf("%s() error, line %d, can't set certifiers data\n",
             __func__,
             __LINE__);
      return false;
    }

#if 0
    // Debug
    printf("put_trust_data_from_store: outgoing store\n");
    store_.print();
#endif
    return true;
  }

  return false;
}

bool certifier::framework::cc_trust_manager::get_trust_data_from_store() {

  const string string_type("string");
  const string key_type("key");
  const string signed_claim_type("signed_claim");

  const string symmetric_key_alg_tag("symmetric-key-algorithm");
  const string public_key_alg_tag("public-key-algorithm");
  const string service_key_tag("service-attest-key");
  const string sealing_key_tag("sealing-key");

  int    ent;
  string value;

  ent = store_.find_entry(public_key_alg_tag, string_type);
  if (ent < 0) {
    printf("%s() error, line %d, Can't get public key algorithm\n",
           __func__,
           __LINE__);
    return false;
  }
  if (!store_.get(ent, &public_key_algorithm_)) {
    printf("%s() error, line %d, Can't get public key algorithm\n",
           __func__,
           __LINE__);
    return false;
  }
  ent = store_.find_entry(symmetric_key_alg_tag, string_type);
  if (ent < 0) {
    printf("%s() error, line %d, Can't get symmetric key algorithm\n",
           __func__,
           __LINE__);
    return false;
  }
  if (!store_.get(ent, &symmetric_key_algorithm_)) {
    printf("%s() error, line %d, Can't get symmetric key algorithm\n",
           __func__,
           __LINE__);
    return false;
  }

  if (!get_certifiers_from_store()) {
    printf("%s() error, line %d, Can't get certifiers from store\n",
           __func__,
           __LINE__);
    return false;
  }

  if (num_certified_domains_ > 0 && certified_domains_[0]->is_certified_) {
    primary_admissions_cert_valid_ = true;
    serialized_primary_admissions_cert_ =
        certified_domains_[0]->admissions_cert_;
  }

  if (purpose_ == "attestation") {

    // put private service key and symmetric keys in store
    string service_key_tag("service-attest-key");
    ent = store_.find_entry(service_key_tag, key_type);
    if (ent < 0) {
      printf("%s() error, line %d, Can't get service-attest-key\n",
             __func__,
             __LINE__);
      return false;
    }
    value.clear();
    if (!store_.get(ent, &value)) {
      printf("%s() error, line %d, Can't get service-attest-key\n",
             __func__,
             __LINE__);
      return false;
    }
    if (!private_service_key_.ParseFromString(value)) {
      printf("%s() error, line %d, Can't parse private service key\n",
             __func__,
             __LINE__);
      return false;
    }
    if (!private_key_to_public_key(private_service_key_,
                                   &public_service_key_)) {
      printf("%s() error, line %d, Can't transform to public key\n",
             __func__,
             __LINE__);
      return false;
    }
    cc_service_key_initialized_ = true;

    ent = store_.find_entry(sealing_key_tag, key_type);
    if (ent < 0) {
      printf("%s() error, line %d, Can't get sealing-key\n",
             __func__,
             __LINE__);
      return false;
    }
    value.clear();
    if (!store_.get(ent, &value)) {
      printf("%s() error, line %d, Can't get sealing-key\n",
             __func__,
             __LINE__);
      return false;
    }

    if (!service_sealing_key_.ParseFromString(value)) {
      printf("%s() error, line %d, Can't parse sealing-key\n",
             __func__,
             __LINE__);
      return false;
    }
    memset(sealing_key_bytes_, 0, max_symmetric_key_size_);
    memcpy(sealing_key_bytes_,
           (byte *)service_sealing_key_.secret_key_bits().data(),
           service_sealing_key_.secret_key_bits().size());

    cc_symmetric_key_initialized_ = true;

    // platform rule?
    string rule_tag("platform-rule");
    ent = store_.find_entry(rule_tag, signed_claim_type);
    if (ent >= 0) {
      value.clear();
      if (!store_.get(ent, &value)) {
        printf("%s() error, line %d, Can't find platform_rule from store\n",
               __func__,
               __LINE__);
        return false;
      }
      if (!platform_rule_.ParseFromString(value)) {
        printf("%s() error, line %d, Can't parse platform rule\n",
               __func__,
               __LINE__);
        return false;
      }
      cc_service_platform_rule_initialized_ = true;
    }
    cc_is_certified_ = true;
    return true;
  }

  if (purpose_ == "authentication") {

    string auth_key_tag("auth-key");
    ent = store_.find_entry(auth_key_tag, key_type);
    if (ent < 0) {
      printf("%s() error, line %d, Can't get auth-key\n", __func__, __LINE__);
      return false;
    }
    value.clear();
    if (!store_.get(ent, &value)) {
      printf("%s() error, line %d, Can't get auth-key\n", __func__, __LINE__);
      return false;
    }
    if (!private_auth_key_.ParseFromString(value)) {
      printf("%s() error, line %d, Can't parse auth key\n", __func__, __LINE__);
      return false;
    }
    if (!private_key_to_public_key(private_auth_key_, &public_auth_key_)) {
      printf("%s() error, line %d, Can't transform to public key\n",
             __func__,
             __LINE__);
      return false;
    }
#ifdef DEBUG
    printf("Warm restart auth key:\n");
    printf("Private auth key:\n");
    print_key(private_auth_key_);
    printf("\n");
    printf("Public auth key:\n");
    print_key(public_auth_key_);
    printf("\n");
#endif
    cc_auth_key_initialized_ = true;
    if (private_auth_key_.has_certificate()) {
      cc_is_certified_ = true;
#ifdef DEBUG
      X509 *x = X509_new();
      if (asn1_to_x509(private_auth_key_.certificate(), x)) {
        X509_print_fp(stdout, x);
      }
      X509_free(x);
#endif
    }

    string symmetric_key_tag("app-symmetric-key");
    ent = store_.find_entry(symmetric_key_tag, key_type);
    if (ent < 0) {
      printf("%s() error, line %d, Can't get app-symmetric-key\n",
             __func__,
             __LINE__);
      return false;
    }
    value.clear();
    if (!store_.get(ent, &value)) {
      printf("%s() error, line %d, Can't parse app-symmetric-key\n",
             __func__,
             __LINE__);
      return false;
    }
    if (!symmetric_key_.ParseFromString(value)) {
      printf("%s() error, line %d, Can't parse app-symmetric-key\n",
             __func__,
             __LINE__);
      return false;
    }
    cc_symmetric_key_initialized_ = true;

    return true;
  }

  return false;
}

// If regen is true, replace them even if they are valid
bool certifier::framework::cc_trust_manager::generate_symmetric_key(
    bool regen) {

  if (cc_symmetric_key_initialized_ && !regen)
    return true;

  // Make up symmetric keys (e.g.-for sealing) for app
  int num_key_bytes;
  if (symmetric_key_algorithm_ == Enc_method_aes_256_cbc_hmac_sha256
      || symmetric_key_algorithm_ == Enc_method_aes_256_cbc_hmac_sha384
      || symmetric_key_algorithm_ == Enc_method_aes_256_gcm) {
    num_key_bytes = cipher_key_byte_size(symmetric_key_algorithm_.c_str());
    if (num_key_bytes <= 0) {
      printf("%s() error, line %d, Can't recover symmetric alg key size\n",
             __func__,
             __LINE__);
      return false;
    }
  } else {
    printf("%s() error, line %d, unsupported encryption algorithm: '%s'\n",
           __func__,
           __LINE__,
           symmetric_key_algorithm_.c_str());
    return false;
  }
  memset(symmetric_key_bytes_, 0, max_symmetric_key_size_);
  if (!get_random(8 * num_key_bytes, symmetric_key_bytes_)) {
    printf("%s() error, line %d, Can't get random bytes for app key\n",
           __func__,
           __LINE__);
    return false;
  }
  symmetric_key_.set_key_name("app-symmetric-key");
  symmetric_key_.set_key_type(symmetric_key_algorithm_);
  symmetric_key_.set_key_format("vse-key");
  symmetric_key_.set_secret_key_bits(symmetric_key_bytes_, 8 * num_key_bytes);

  return true;
}

bool certifier::framework::cc_trust_manager::generate_sealing_key(bool regen) {

  if (cc_sealing_key_initialized_ && !regen)
    return true;

  // Make up symmetric keys (e.g.-for sealing)for app
  int num_key_bytes;
  if (symmetric_key_algorithm_ == Enc_method_aes_256_cbc_hmac_sha256
      || symmetric_key_algorithm_ == Enc_method_aes_256_cbc_hmac_sha384
      || symmetric_key_algorithm_ == Enc_method_aes_256_gcm) {
    num_key_bytes = cipher_key_byte_size(symmetric_key_algorithm_.c_str());
    if (num_key_bytes <= 0) {
      printf("%s() error, line %d, Can't get symmetric alg key size\n",
             __func__,
             __LINE__);
      return false;
    }
  } else {
    printf("%s() error, line %d, unsupported encryption algorithm: '%s'\n",
           __func__,
           __LINE__,
           symmetric_key_algorithm_.c_str());
    return false;
  }
  memset(sealing_key_bytes_, 0, max_symmetric_key_size_);
  if (!get_random(8 * num_key_bytes, sealing_key_bytes_)) {
    printf("%s() error, line %d, Can't get random bytes for app key\n",
           __func__,
           __LINE__);
    return false;
  }
  service_sealing_key_.set_key_name("sealing-key");
  service_sealing_key_.set_key_type(symmetric_key_algorithm_);
  service_sealing_key_.set_key_format("vse-key");
  service_sealing_key_.set_secret_key_bits(sealing_key_bytes_,
                                           8 * num_key_bytes);

  return true;
}

bool certifier::framework::cc_trust_manager::generate_auth_key(bool regen) {

  if (cc_auth_key_initialized_ && !regen)
    return true;

  // make app auth private and public key
  if (public_key_algorithm_ == Enc_method_rsa_2048) {
    if (!make_certifier_rsa_key(2048, &private_auth_key_)) {
      printf("%s() error, line %d, Can't generate App private key\n",
             __func__,
             __LINE__);
      return false;
    }
  } else if (public_key_algorithm_ == Enc_method_rsa_3072) {
    if (!make_certifier_rsa_key(3072, &private_auth_key_)) {
      printf("%s() error, line %d, Can't generate App private key\n",
             __func__,
             __LINE__);
      return false;
    }
  } else if (public_key_algorithm_ == Enc_method_rsa_4096) {
    if (!make_certifier_rsa_key(4096, &private_auth_key_)) {
      printf("%s() error, line %d, Can't generate App private key\n",
             __func__,
             __LINE__);
      return false;
    }
  } else if (public_key_algorithm_ == Enc_method_ecc_384) {
    if (!make_certifier_ecc_key(384, &private_auth_key_)) {
      printf("%s() error, line %d, Can't generate App private key\n",
             __func__,
             __LINE__);
      return false;
    }
  } else {
    printf("%s() error, line %d, Unsupported public key algorithm: '%s'\n",
           __func__,
           __LINE__,
           public_key_algorithm_.c_str());
    return false;
  }

  private_auth_key_.set_key_name("auth-key");
  if (!private_key_to_public_key(private_auth_key_, &public_auth_key_)) {
    printf("%s() error, line %d, Can't make public Auth key\n",
           __func__,
           __LINE__);
    return false;
  }

  return true;
}

bool certifier::framework::cc_trust_manager::generate_service_key(bool regen) {

  if (cc_service_key_initialized_ && !regen)
    return true;

  // make app service private and public key
  if (public_key_algorithm_ == Enc_method_rsa_2048) {
    if (!make_certifier_rsa_key(2048, &private_service_key_)) {
      printf("%s() error, line %d, Can't generate App private key\n",
             __func__,
             __LINE__);
      return false;
    }
  } else if (public_key_algorithm_ == Enc_method_rsa_3072) {
    if (!make_certifier_rsa_key(3072, &private_service_key_)) {
      printf("%s() error, line %d, Can't generate App private key\n",
             __func__,
             __LINE__);
      return false;
    }
  } else if (public_key_algorithm_ == Enc_method_rsa_4096) {
    if (!make_certifier_rsa_key(4096, &private_service_key_)) {
      printf("%s() error, line %d, Can't generate App private key\n",
             __func__,
             __LINE__);
      return false;
    }
  } else if (public_key_algorithm_ == Enc_method_ecc_384) {
    if (!make_certifier_ecc_key(384, &private_service_key_)) {
      printf("%s() error, line %d, Can't generate App private key\n",
             __func__,
             __LINE__);
      return false;
    }
  } else {
    printf("%s() error, line %d, Unsupported public key algorithm\n",
           __func__,
           __LINE__);
    return false;
  }

  private_service_key_.set_key_name("service-attest-key");
  if (!private_key_to_public_key(private_service_key_, &public_service_key_)) {
    printf("%s() error, line %d, Can't make public service key\n",
           __func__,
           __LINE__);
    return false;
  }

  return true;
}

//  public_key_alg can be rsa-2048, rsa-1024, rsa-3072, rsa-4096, ecc-384
//  symmetric_key_alg can be aes-256-cbc-hmac-sha256, aes-256-cbc-hmac-sha384 or
//  aes-256-gcm
bool certifier::framework::cc_trust_manager::cold_init(
    const string &public_key_alg,
    const string &symmetric_key_alg,
    const string &home_domain_name,
    const string &home_host,
    int           home_port,
    const string &service_host,
    int           service_port) {

  if (!cc_policy_info_initialized_) {
    printf("%s() error, line %d, policy key should have been initialized\n",
           __func__,
           __LINE__);
    return false;
  }

  string domain_cert;
  domain_cert.assign(serialized_policy_cert_.data(),
                     serialized_policy_cert_.size());
  if (num_certified_domains_ != 0) {
    printf("%s() error, line %d, there should be no certified domains yet\n",
           __func__,
           __LINE__);
    return false;
  }
  if (!add_or_update_new_domain(home_domain_name,
                                domain_cert,
                                home_host,
                                home_port,
                                service_host,
                                service_port)) {
    printf("%s() error, line %d, certifiers should be empty for cold init\n",
           __func__,
           __LINE__);
    return false;
  }

  public_key_algorithm_ = public_key_alg;
  symmetric_key_algorithm_ = symmetric_key_alg;

  // Make up symmetric keys (e.g.-for sealing)for app
  if (!generate_symmetric_key(true)) {
    printf("%s() error, line %d, Can't generate symmetric key\n",
           __func__,
           __LINE__);
    return false;
  }
  cc_symmetric_key_initialized_ = true;
  if (purpose_ == "attestation") {
    if (!generate_sealing_key(true)) {
      printf("%s() error, line %d, Can't generate sealing key\n",
             __func__,
             __LINE__);
      return false;
    }
  }
  cc_sealing_key_initialized_ = true;

  if (purpose_ == "authentication") {

    if (!generate_auth_key(true)) {
      printf("%s() error, line %d, Can't generate auth key\n",
             __func__,
             __LINE__);
      return false;
    }
    cc_auth_key_initialized_ = true;

  } else if (purpose_ == "attestation") {

    if (!generate_service_key(true)) {
      printf("%s() error, line %d, Can't generate service key\n",
             __func__,
             __LINE__);
      return false;
    }
    cc_service_key_initialized_ = true;

  } else {
    printf("%s() error, line %d, invalid cold_init purpose\n",
           __func__,
           __LINE__);
    return false;
  }

  if (!put_trust_data_in_store()) {
    printf("%s() error, line %d, Can't put trust data in store\n",
           __func__,
           __LINE__);
    return false;
  }

  if (!save_store()) {
    printf("%s() error, line %d, Can't save store\n", __func__, __LINE__);
    return false;
  }
  cc_policy_store_initialized_ = true;
  return true;
}

bool certifier::framework::cc_trust_manager::warm_restart() {

  // fetch store
  if (!cc_policy_store_initialized_) {
    if (!fetch_store()) {
      printf("%s() error, line %d, Can't fetch store\n", __func__, __LINE__);
      return false;
    }
  }
  cc_policy_store_initialized_ = true;

  if (!get_trust_data_from_store()) {
    printf("%s() error, line %d, Can't get trust data from store\n",
           __func__,
           __LINE__);
    return false;
  }

#if 0
  printf("\nRecovered trust data\n");
  print_trust_data();
  printf("\n");
  printf("End Recovered trust data\n");
#endif
  return true;
}

bool certifier::framework::cc_trust_manager::GetPlatformSaysAttestClaim(
    signed_claim_message *scm) {
  if (enclave_type_ == "simulated-enclave") {
    return simulated_GetAttestClaim(scm);
  }
  if (enclave_type_ == "application-enclave") {
    int  size_out = 8192;
    byte out[size_out];
    if (!application_GetPlatformStatement(&size_out, out)) {
      printf("%s() error, line %d, Can't get Platform Statement from parent\n",
             __func__,
             __LINE__);
      return false;
    }
    string sc_str;
    sc_str.assign((char *)out, size_out);
    if (!scm->ParseFromString(sc_str)) {
      printf("%s() error, line %d, Can't parse platform claim\n",
             __func__,
             __LINE__);
      return false;
    }
    return true;
  }
  return false;
}

bool certifier::framework::cc_trust_manager::add_or_update_new_domain(
    const string &domain_name,
    const string &cert,
    const string &host,
    int           port,
    const string &service_host,
    int           service_port) {

  // don't duplicate
  certifiers *found = nullptr;
  for (int i = 0; i < num_certified_domains_; i++) {
    certifiers *c = certified_domains_[i];
    if (c != nullptr && domain_name == c->domain_name_) {
      found = c;
      break;
    }
  }

  if (found == nullptr) {
    if (num_certified_domains_ >= max_num_certified_domains_) {
      return false;
    }

    found = new certifiers(this);
    certified_domains_[num_certified_domains_++] = found;
  }

#ifdef DEBUG
  printf("num_certified_domains_: %d\n", num_certified_domains_);
#endif

  return found->init_certifiers_data(domain_name,
                                     cert,
                                     host,
                                     port,
                                     service_host,
                                     service_port);
}

bool certifier::framework::cc_trust_manager::certify_primary_domain() {

  // already certified
  if (cc_is_certified_)
    return true;

  // primary domain should be entry 0
  // if not already certified, certify
  if (num_certified_domains_ <= 0) {
    printf("%s() error, line %d, primary domain\n", __func__, __LINE__);
    return false;
  }

#ifdef DEBUG
  // Debug: print primary certifier data
  printf("Certifying primary domain\n");
  certified_domains_[0]->print_certifiers_entry();
#endif

  if (!certified_domains_[0]->certify_domain(purpose_)) {
    printf("%s() error, line %d, can't certify primary domain\n",
           __func__,
           __LINE__);
    return false;
  }

  if (purpose_ == "authentication") {
    cc_auth_key_initialized_ = true;
    primary_admissions_cert_valid_ = true;
    serialized_primary_admissions_cert_ =
        certified_domains_[0]->admissions_cert_;
    cc_is_certified_ = true;
  } else if (purpose_ == "attestation") {
    cc_service_platform_rule_initialized_ = true;
    if (!platform_rule_.ParseFromString(certified_domains_[0]->signed_rule_)) {
      printf("%s():%d error, Can't parse platform rule\n", __func__, __LINE__);
    }
    cc_is_certified_ = true;
  } else {
    printf("%s():%d error, unknown purpose\n", __func__, __LINE__);
  }

  return true;
}

bool certifier::framework::cc_trust_manager::certify_secondary_domain(
    const string &domain_name) {

  // find it
  certifiers *found = nullptr;
  for (int i = 1; i < num_certified_domains_; i++) {
    if (certified_domains_[i] != nullptr
        && certified_domains_[i]->domain_name_ == domain_name) {
      found = certified_domains_[i];
      break;
    }
  }
  return (found ? found->certify_domain(purpose_) : false);
}

bool certifier::framework::cc_trust_manager::init_peer_certification_data(
    const string &public_key_alg) {
  // bool peer_data_initialized_;
  // key_message local_policy_key_;
  // string local_policy_cert_;
  return false;
}

bool certifier::framework::cc_trust_manager::recover_peer_certification_data() {
  return false;
}

bool certifier::framework::cc_trust_manager::get_peer_certification(
    const string &host_name,
    int           port) {
  return false;
}

bool certifier::framework::cc_trust_manager::run_peer_certification_service(
    const string &host_name,
    int           port) {
  return false;
}

bool certifier::framework::cc_trust_manager::get_certifiers_from_store() {

  int ent = store_.find_entry("all-certifiers", "certifiers_message");
  if (ent < 0) {
    printf("%s() error, line %d, no certifiers entries\n", __func__, __LINE__);
    return false;
  }

  certifiers_message cert_messages;
  string             serialized_cert_messages;
  if (!store_.get(ent, &serialized_cert_messages)) {
    printf("%s() error, line %d, can't get certifiers\n", __func__, __LINE__);
    return false;
  }
  if (!cert_messages.ParseFromString(serialized_cert_messages)) {
    printf("%s() error, line %d, can't parse certifiers\n", __func__, __LINE__);
    return false;
  }

  // empty existing certifiers and reinit
  for (int i = 0; i < num_certified_domains_; i++) {
    if (certified_domains_[i] != nullptr) {
      delete certified_domains_[i];
      certified_domains_[i] = nullptr;
    }
  }

  num_certified_domains_ = 0;
  if (cert_messages.my_certifiers_size() > max_num_certified_domains_) {
    printf("%s() error, line %d, too many certifiers\n", __func__, __LINE__);
    return false;
  }
  for (int i = 0; i < cert_messages.my_certifiers_size(); i++) {
    const certifier_entry &cm = cert_messages.my_certifiers(i);
    certifiers *           ce = new certifiers(this);
    certified_domains_[num_certified_domains_++] = ce;
    ce->domain_name_ = cm.domain_name();
    ce->purpose_ = cm.purpose();
    ce->domain_policy_cert_ = cm.domain_cert();
    ce->host_ = cm.domain_host();
    ce->port_ = cm.domain_port();
    ce->is_certified_ = cm.is_certified();
    ce->admissions_cert_ = cm.admissions_cert();
    ce->signed_rule_ = cm.platform_rule();
    ce->service_host_ = cm.service_host();
    ce->service_port_ = cm.service_port();
  }
  return true;
}

bool certifier::framework::cc_trust_manager::put_certifiers_in_store() {
  certifiers_message cert_messages;
  string             serialized_cert_messages;

  for (int i = 0; i < num_certified_domains_; i++) {
    certifier_entry *cm = cert_messages.add_my_certifiers();
    certifiers *     ce = certified_domains_[i];

    cm->set_domain_name(ce->domain_name_);
    cm->set_domain_cert(ce->domain_policy_cert_);
    cm->set_domain_host(ce->host_);
    cm->set_domain_port(ce->port_);
    cm->set_is_certified(ce->is_certified_);
    if (ce->is_certified_) {
      cm->set_admissions_cert(ce->admissions_cert_);
    }
    cm->set_service_host(ce->service_host_);
    cm->set_service_port(ce->service_port_);
  }

  if (!cert_messages.SerializeToString(&serialized_cert_messages)) {
    printf("%s() error, line %d, can't serialize\n", __func__, __LINE__);
    return false;
  }
  return store_.update_or_insert("all-certifiers",
                                 "certifiers_message",
                                 serialized_cert_messages);
}

bool certifier::framework::cc_trust_manager::write_private_key_to_file(
    const string &filename) {
  RSA *tmp_rsa = RSA_new();
  if (!key_to_RSA(private_auth_key_, tmp_rsa)) {
    printf("%s() error, line %d, Failed to convert private key to "
           "RSA format.\n",
           __func__,
           __LINE__);
    return false;
  }
  FILE *outfh = fopen(filename.c_str(), "wb");
  if (!outfh) {
    printf("%s() error, line %d, Failed to open output file: '%s'\n",
           __func__,
           __LINE__,
           filename.c_str());
    RSA_free(tmp_rsa);
    return false;
  }
  PEM_write_RSAPrivateKey(outfh,
                          tmp_rsa,
                          nullptr,
                          nullptr,
                          0,
                          nullptr,
                          nullptr);
  fclose(outfh);
  RSA_free(tmp_rsa);

#ifdef DEBUG
  printf("%s(): Wrote private key in PEM-format to file '%s'\n",
         __func__,
         filename.c_str());
#endif  // DEBUG
  return true;
}

certifier::framework::certifiers::certifiers(cc_trust_manager *owner) {
  owner_ = owner;
}

certifier::framework::certifiers::~certifiers() {}

bool certifier::framework::certifiers::init_certifiers_data(
    const string &domain_name,
    const string &cert,
    const string &host,
    int           port,
    const string &service_host,
    int           service_port) {

  domain_name_ = domain_name;
  domain_policy_cert_.assign(cert.data(), cert.size());
  host_ = host;
  port_ = port;
  is_certified_ = false;
  service_host_ = service_host;
  service_port_ = service_port;

  return true;
}

void certifier::framework::certifiers::print_certifiers_entry() {
  printf("\nDomain name: %s\n", domain_name_.c_str());
  printf("Domain policy cert: ");
  print_bytes((int)domain_policy_cert_.size(),
              (byte *)domain_policy_cert_.data());
  printf("\n");
  if (purpose_.size() > 0) {
    printf("Purpose: %s\n", purpose_.c_str());
  } else {
    printf("Purpose: not declared\n");
  }
  printf("Host: %s, port: %d\n", host_.c_str(), port_);

  if (is_certified_) {
    printf("Certified\n");
  } else {
    printf("Not certified\n");
  }

  if (admissions_cert_.size() > 0) {
    printf("Admissions cert: ");
    print_bytes((int)admissions_cert_.size(), (byte *)admissions_cert_.data());
    printf("\n");
  }
  if (signed_rule_.size() > 0) {
    printf("Signed_rule : ");
    print_bytes((int)signed_rule_.size(), (byte *)signed_rule_.data());
    printf("\n");
  }

  printf("Service host: %s, service port: %d\n",
         service_host_.c_str(),
         service_port_);
}

bool certifier::framework::certifiers::get_certified_status() {
  return is_certified_;
}

// add auth-key and symmetric key
bool certifier::framework::certifiers::certify_domain(const string &purpose) {

  purpose_ = purpose;

  // owner has enclave_type, keys, and store.
  if (owner_ == nullptr) {
    printf("%s():%d, no owner pointer\n", __func__, __LINE__);
    return false;
  }

  // Note: if you change the auth key, you must recertify in all domains

  evidence_list platform_evidence;
  printf("%s():%d: enclave_type_ = '%s', purpose_ = '%s'\n",
         __func__,
         __LINE__,
         owner_->enclave_type_.c_str(),
         owner_->purpose_.c_str());

  if (owner_->enclave_type_ == "simulated-enclave"
      || owner_->enclave_type_ == "application-enclave") {
    signed_claim_message signed_platform_says_attest_key_is_trusted;
    if (!owner_->GetPlatformSaysAttestClaim(
            &signed_platform_says_attest_key_is_trusted)) {
      printf("%s() error, line %d, Can't get signed attest claim\n",
             __func__,
             __LINE__);
      return false;
    }
    string str_s;
    if (!signed_platform_says_attest_key_is_trusted.SerializeToString(&str_s)) {
      printf("%s() error, line %d, Can't serialize signed attest claim\n",
             __func__,
             __LINE__);
      return false;
    }
    evidence *ev = platform_evidence.add_assertion();
    if (ev == nullptr) {
      printf("%s() error, line %d,: Can't add to platform evidence\n",
             __func__,
             __LINE__);
      return false;
    }
    ev->set_evidence_type("signed-claim");
    ev->set_serialized_evidence(str_s);

#ifdef GRAMINE_CERTIFIER
  } else if (owner_->enclave_type_ == "gramine-enclave") {
    if (!gramine_platform_cert_initialized) {
      printf("%s() error, line %d, gramine certs not initialized\n",
             __func__,
             __LINE__);
      return false;
    }
    evidence *ev = platform_evidence.add_assertion();
    if (ev == nullptr) {
      printf("%s() error, line %d, Can't add to gramine platform evidence\n",
             __func__,
             __LINE__);
      return false;
    }
    ev->set_evidence_type("cert");
    ev->set_serialized_evidence(gramine_platform_cert);
    // May add more certs later
#endif

#ifdef KEYSTONE_CERTIFIER
  } else if (owner_->enclave_type_ == "keystone-enclave") {
    // Todo: Add cert when it's available
#endif

#ifdef ISLET_CERTIFIER
  } else if (owner_->enclave_type_ == "islet-enclave") {

    // Add CCA certificate
#endif  // ISLET_CERTIFIER

#ifdef SEV_SNP
  } else if (owner_->enclave_type_ == "sev-enclave") {
    if (!plat_certs_initialized) {
      printf("%s() error, line: %d, sev certs not initialized\n",
             __func__,
             __LINE__);
      return false;
    }
    evidence *ev = platform_evidence.add_assertion();
    if (ev == nullptr) {
      printf("%s() error, line: %d, Can't add to platform evidence\n",
             __func__,
             __LINE__);
      return false;
    }
    ev->set_evidence_type("cert");
    ev->set_serialized_evidence(serialized_ark_cert);
    ev = platform_evidence.add_assertion();
    if (ev == nullptr) {
      printf("%s() error, line: %d, Can't add to platform evidence\n",
             __func__,
             __LINE__);
      return false;
    }
    ev->set_evidence_type("cert");
    ev->set_serialized_evidence(serialized_ask_cert);
    ev = platform_evidence.add_assertion();
    if (ev == nullptr) {
      printf("%s() error, line: %d, Can't add to platform evidence\n",
             __func__,
             __LINE__);
      return false;
    }
    ev->set_evidence_type("cert");
    ev->set_serialized_evidence(serialized_vcek_cert);
#endif
#ifdef OE_CERTIFIER
  } else if (owner_->enclave_type_ == "oe-enclave") {
    if (!owner_->cc_provider_provisioned_) {
      printf("%s() error, line: %d, Can't get pem-chain\n", __func__, __LINE__);
      return false;
    }
    if (pem_cert_chain != "") {
      evidence *ev = platform_evidence.add_assertion();
      if (ev == nullptr) {
        printf("%s() error, line: %d, Can't add to platform evidence\n",
               __func__,
               __LINE__);
        return false;
      }
      ev->set_evidence_type("pem-cert-chain");
      ev->set_serialized_evidence(pem_cert_chain);
    }
#endif
  } else {
    printf("%s() error, line: %d, Unknown enclave type\n", __func__, __LINE__);
    return false;
  }

  attestation_user_data ud;
  if (purpose == "authentication") {
#ifdef DEBUG
    printf("\n---In certify_domain\n");
    printf("Filling ud with public auth key:\n");
    print_key(owner_->public_auth_key_);
    printf("\n");
#endif

    if (!make_attestation_user_data(owner_->enclave_type_,
                                    owner_->public_auth_key_,
                                    &ud)) {
      printf("%s() error, line: %d, Can't make user data (1)\n",
             __func__,
             __LINE__);
      return false;
    }
#ifdef DEBUG
    printf("\n---In certify me\n");
    printf("key in attestation user data:\n");
    print_key(ud.enclave_key());
    printf("\nprivate auth key:\n");
    print_key(owner_->private_auth_key_);
    printf("\npublic auth key:\n");
    print_key(owner_->public_auth_key_);
    printf("\n");
    printf("User data:\n");
    print_user_data(ud);
    printf("\n");
#endif
  } else if (purpose == "attestation") {
    if (!make_attestation_user_data(owner_->enclave_type_,
                                    owner_->public_service_key_,
                                    &ud)) {
      printf("%s() error, line: %d, Can't make user data (1)\n",
             __func__,
             __LINE__);
      return false;
    }
  } else {
    printf("%s() error, line: %d, neither attestation or authorization\n",
           __func__,
           __LINE__);
    return false;
  }

  string serialized_ud;
  if (!ud.SerializeToString(&serialized_ud)) {
    printf("%s() error, line: %d, Can't serialize user data\n",
           __func__,
           __LINE__);
    return false;
  }

  int  size_out = 16000;
  byte out[size_out];
  if (!Attest(owner_->enclave_type_,
              serialized_ud.size(),
              (byte *)serialized_ud.data(),
              &size_out,
              out)) {
    printf("%s() error, line: %d,  Attest failed\n", __func__, __LINE__);
    return false;
  }
  string the_attestation_str;
  the_attestation_str.assign((char *)out, size_out);

  // Now, if there are accelerators, verify them.

  // Get certified
  trust_request_message  request;
  trust_response_message response;

  // Should trust_request_message should be signed by auth key
  //   to prevent MITM attacks?  Probably not.
  request.set_requesting_enclave_tag("requesting-enclave");
  request.set_providing_enclave_tag("providing-enclave");
  if (owner_->enclave_type_ == "application-enclave"
      || owner_->enclave_type_ == "simulated-enclave") {
    request.set_submitted_evidence_type("vse-attestation-package");
  } else if (owner_->enclave_type_ == "sev-enclave") {
    request.set_submitted_evidence_type("sev-platform-package");
  } else if (owner_->enclave_type_ == "gramine-enclave") {
    request.set_submitted_evidence_type("gramine-evidence");
  } else if (owner_->enclave_type_ == "keystone-enclave") {
    request.set_submitted_evidence_type("keystone-evidence");
  } else if (owner_->enclave_type_ == "islet-enclave") {
    request.set_submitted_evidence_type("islet-evidence");
  } else if (owner_->enclave_type_ == "oe-enclave") {
    request.set_submitted_evidence_type("oe-evidence");
  } else {
    request.set_submitted_evidence_type("vse-attestation-package");
  }
  request.set_purpose(purpose);

  // Construct the evidence package
  // Put initialized platform evidence and attestation in the following order:
  //  platform_says_attest_key_is_trusted, the_attestation
  evidence_package *ep = new (evidence_package);
  if (!construct_platform_evidence_package(owner_->enclave_type_,
                                           owner_->purpose_,
                                           platform_evidence,
                                           the_attestation_str,
                                           ep)) {
    printf("%s() error, line: %d, construct_platform_evidence_package failed\n",
           __func__,
           __LINE__);
    return false;
  }
  request.set_allocated_support(ep);

  // Serialize request
  string serialized_request;
  if (!request.SerializeToString(&serialized_request)) {
    printf("%s() error, line: %d, Can't serialize request\n",
           __func__,
           __LINE__);
    return false;
  }

#ifdef DEBUG
  printf("\nRequest:\n");
  print_trust_request_message(request);
#endif

  // Open socket and send request.
  int sock = -1;
  if (!open_client_socket(host_, port_, &sock)) {
    printf("%s() error, line: %d, Can't open request socket\n",
           __func__,
           __LINE__);
    return false;
  }

  int sized_write_len = sized_socket_write(sock,
                                           serialized_request.size(),
                                           (byte *)serialized_request.data());
  if (sized_write_len < (int)serialized_request.size()) {
    printf("%s() error, line: %d sized_socket_write() len=%d is "
           "< requested size, %d\n",
           __func__,
           __LINE__,
           sized_write_len,
           (int)serialized_request.size());
    return false;
  }

  // Read response from Certifier Service.
  string serialized_response;
  int    resp_size = sized_socket_read(sock, &serialized_response);
  if (resp_size < 0) {
    printf("%s() error, line: %d, Can't read response\n", __func__, __LINE__);
    return false;
  }
  if (!response.ParseFromString(serialized_response)) {
    printf("%s() error, line: %d, Can't parse response\n", __func__, __LINE__);
    return false;
  }
  close(sock);

#ifdef DEBUG
  printf("\nResponse:\n");
  print_trust_response_message(response);
#endif

  if (response.status() != "succeeded") {
    printf("%s() error, line: %d, Certification failed, status='%s'\n",
           __func__,
           __LINE__,
           response.status().c_str());
    printf("\nResponse:\n");
    print_trust_response_message(response);
    return false;
  }

  is_certified_ = true;

  // Store the admissions certificate cert or platform rule
  if (owner_->purpose_ == "authentication") {

    admissions_cert_.assign((char *)response.artifact().data(),
                            response.artifact().size());
    owner_->primary_admissions_cert_valid_ = true;
    owner_->serialized_primary_admissions_cert_ = admissions_cert_;

  } else if (owner_->purpose_ == "attestation") {

    signed_rule_.assign((char *)response.artifact().data(),
                        response.artifact().size());
    if (!owner_->platform_rule_.ParseFromString(signed_rule_)) {
      printf("%s() error, line: %d, Can't parse platform rule\n",
             __func__,
             __LINE__);
      return false;
    }
    owner_->cc_service_platform_rule_initialized_ = true;

  } else {
    printf("%s() error, line: %d, Unknown purpose\n", __func__, __LINE__);
    return false;
  }

  if (!owner_->put_trust_data_in_store()) {
    printf("%s() error, line: %d, Can't put trust data in store\n",
           __func__,
           __LINE__);
    return false;
  }
  return owner_->save_store();
}

// --------------------------------------------------------------------------------------
// helpers for proofs

bool construct_platform_evidence_package(string &       attesting_enclave_type,
                                         const string & purpose,
                                         evidence_list &platform_assertions,
                                         string &       serialized_attestation,
                                         evidence_package *ep) {

  string pt("vse-verifier");
  string et("signed-claim");
  ep->set_prover_type(pt);
  ep->set_enclave_type(attesting_enclave_type);

#ifdef DEBUG
  printf("construct_platform_evidence_package %d existing assertions\n",
         platform_assertions.assertion_size());
  for (int i = 0; i < platform_assertions.assertion_size(); i++) {
    print_evidence(platform_assertions.assertion(i));
    printf("\n");
  }
#endif
  for (int i = 0; i < platform_assertions.assertion_size(); i++) {
    const evidence &ev_from = platform_assertions.assertion(i);
    evidence *      ev_to = ep->add_fact_assertion();
    ev_to->CopyFrom(ev_from);
  }

  // add attestation
  evidence *ev2 = ep->add_fact_assertion();
  if ("simulated-enclave" == attesting_enclave_type
      || "application-enclave" == attesting_enclave_type) {
    string et2("signed-vse-attestation-report");
    ev2->set_evidence_type(et2);
  } else if ("oe-enclave" == attesting_enclave_type) {
    string et2("oe-attestation-report");
    ev2->set_evidence_type(et2);
  } else if ("asylo-enclave" == attesting_enclave_type) {
    string et2("asylo-attestation-report");
    ev2->set_evidence_type(et2);
  } else if ("gramine-enclave" == attesting_enclave_type) {
    string et2("gramine-attestation");
    ev2->set_evidence_type(et2);
  } else if ("keystone-enclave" == attesting_enclave_type) {
    string et2("keystone-attestation");
    ev2->set_evidence_type(et2);
  } else if ("sev-enclave" == attesting_enclave_type) {
    string et2("sev-attestation");
    ev2->set_evidence_type(et2);
  } else if ("islet-enclave" == attesting_enclave_type) {
    string et2("islet-attestation");
    ev2->set_evidence_type(et2);
  } else {
    printf("%s:%d:%s: - can't add attestation\n", __FILE__, __LINE__, __func__);
    return false;
  }

  ev2->set_serialized_evidence(serialized_attestation);
  return true;
}

// Todo: This isn't used
bool add_policy_key_says_platform_key_is_trusted(
    signed_claim_message &platform_key_is_trusted,
    evidence_package *    ep) {

  string et("signed-claim");

  evidence *ev = ep->add_fact_assertion();
  ev->set_evidence_type(et);
  signed_claim_message sc;
  sc.CopyFrom(platform_key_is_trusted);
  string serialized_sc;
  if (!sc.SerializeToString(&serialized_sc))
    return false;
  ev->set_serialized_evidence((byte *)serialized_sc.data(),
                              serialized_sc.size());
  return true;
}

// ----------------------------------------------------------------------------------------------
// Socket and SSL support

void print_cn_name(X509_NAME *name) {
  int len = X509_NAME_get_text_by_NID(name, NID_commonName, nullptr, 0);
  if (len <= 0)
    return;
  len++;

  char name_buf[len];
  if (X509_NAME_get_text_by_NID(name, NID_commonName, name_buf, len) > 0) {
    printf(" %s", name_buf);
  }
  printf("\n");
}

void print_org_name(X509_NAME *name) {
  int len = X509_NAME_get_text_by_NID(name, NID_organizationName, nullptr, 0);
  if (len <= 0)
    return;
  len++;

  char name_buf[len];
  if (X509_NAME_get_text_by_NID(name, NID_organizationName, name_buf, len)
      > 0) {
    printf(" %s", name_buf);
  }
  printf("\n");
}

/* Declare an array of SSL Error codes mapped to an error description */
optlookup Ssl_errors[] = {
    DCL_OPTLOOKUP(SSL_ERROR_NONE, "No ssl error"),
    DCL_OPTLOOKUP(SSL_ERROR_WANT_READ, "want read error"),
    DCL_OPTLOOKUP(SSL_ERROR_WANT_WRITE, "want write error")
#ifndef BORING_SSL
        ,
    DCL_OPTLOOKUP(SSL_ERROR_WANT_CONNECT, "want connect error"),
    DCL_OPTLOOKUP(SSL_ERROR_WANT_ASYNC, "want async error"),
    DCL_OPTLOOKUP(SSL_ERROR_WANT_CLIENT_HELLO_CB, "want client hello error")
#endif  // BORING_SSL
        ,
    DCL_OPTLOOKUP(SSL_ERROR_WANT_ACCEPT, "want accept error"),
    DCL_OPTLOOKUP(SSL_ERROR_WANT_X509_LOOKUP, "want X509 lookup error"),
    DCL_OPTLOOKUP(SSL_ERROR_SSL, "generic ssl error"),
    DCL_OPTLOOKUP(SSL_ERROR_SYSCALL, "syscall error"),
    DCL_OPTLOOKUP(SSL_ERROR_ZERO_RETURN, "zero return error"),
    DCL_OPTLOOKUP_TERM()};

// Method to convert SSL error-code to human-readable string, a la' strerror()
static inline const char *ssl_strerror(int code) {
  const char *msg = optbyid(Ssl_errors, code);
  return (msg ? msg : "Unknown ssl error, " CC_TO_STR(code));
}

void print_ssl_error(int code) {
  printf("%s\n", ssl_strerror(code));
}

// Socket and SSL support

bool open_client_socket(const string &host_name, int port, int *soc) {
  struct addrinfo  hints;
  struct addrinfo *result, *rp;
  int              sfd, s;

  // Obtain address(es) matching host/port
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = 0;
  hints.ai_protocol = 0;

  char port_str[16] = {};
  sprintf(port_str, "%d", port);

  s = getaddrinfo(host_name.c_str(), port_str, &hints, &result);
  if (s != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
    return false;
  }

  // getaddrinfo() returns a list of address structures.
  // Try each address until we successfully connect(2).
  // If socket(2) (or connect(2)) fails, we (close the socket
  // and) try the next address.
  for (rp = result; rp != NULL; rp = rp->ai_next) {
    sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (sfd == -1)
      continue;

    if (connect(sfd, rp->ai_addr, rp->ai_addrlen) != -1)
      break;

    close(sfd);
  }

  if (rp == NULL) {
    fprintf(stderr, "Could not connect to %s:%d\n", host_name.c_str(), port);
    return false;
  }

  freeaddrinfo(result);

  *soc = sfd;
  return true;
}

bool open_server_socket(const string &host_name, int port, int *soc) {
  struct addrinfo  hints;
  struct addrinfo *result, *rp;
  int              sfd, s;

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;
  hints.ai_protocol = 0;
  hints.ai_canonname = NULL;
  hints.ai_addr = NULL;
  hints.ai_next = NULL;

  char port_str[16] = {};
  sprintf(port_str, "%d", port);

  s = getaddrinfo(host_name.c_str(), port_str, &hints, &result);
  if (s != 0) {
    fprintf(stderr, "%s: getaddrinfo: %s\n", __func__, gai_strerror(s));
    return false;
  }

  // getaddrinfo() returns a list of address structures.
  // Try each address until we successfully bind(2).
  // If socket(2) (or bind(2)) fails, we (close the socket
  // and) try the next address.
  for (rp = result; rp != NULL; rp = rp->ai_next) {
    sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (sfd == -1)
      continue;

      // Reuse addresses and ports
#define REUSE_SOCKETS_AND_PORTS
#ifdef REUSE_SOCKETS_AND_PORTS
    int reuse = 1;
    if (setsockopt(sfd,
                   SOL_SOCKET,
                   SO_REUSEADDR,
                   (const char *)&reuse,
                   sizeof(reuse))
        < 0) {
      fprintf(stderr, "Can't reuse socket %s\n", __func__);
      return false;
    }

    if (setsockopt(sfd,
                   SOL_SOCKET,
                   SO_REUSEPORT,
                   (const char *)&reuse,
                   sizeof(reuse))
        < 0) {
      fprintf(stderr, "Can't reuse port %s\n", __func__);
      return false;
    }
#endif

    if (bind(sfd, rp->ai_addr, rp->ai_addrlen) == 0)
      break;

    close(sfd);
  }

  if (rp == NULL) {
    fprintf(stderr,
            "%s: Could not bind to %s:%d\n",
            __func__,
            host_name.c_str(),
            port);
    return false;
  }

  freeaddrinfo(result);

  if (listen(sfd, 10) != 0) {
    printf("%s: cant listen\n", __func__);
    return false;
  }

  *soc = sfd;
  return true;
}

// This is only for debugging.
int SSL_my_client_callback(SSL *s, int *al, void *arg) {
  printf("callback\n");
  return 1;
}

// This is used to test the signature chain is verified properly
int verify_callback(int preverify, X509_STORE_CTX *x509_ctx) {
  int depth = X509_STORE_CTX_get_error_depth(x509_ctx);
  int err = X509_STORE_CTX_get_error(x509_ctx);

  X509 *     cert = X509_STORE_CTX_get_current_cert(x509_ctx);
  X509_NAME *iname = cert ? X509_get_issuer_name(cert) : NULL;
  X509_NAME *sname = cert ? X509_get_subject_name(cert) : NULL;

  printf("Depth %d, Preverify: %d\n", depth, preverify);
  printf("Issuer CN : ");
  print_cn_name(iname);
  printf("Subject CN: ");
  print_cn_name(sname);

  if (depth == 0) {
    /* If depth is 0, its the server's certificate. Print the SANs too */
    printf("Subject ORG: ");
    print_org_name(sname);
  }

  return preverify;
}

// ----------------------------------------------------------------------------------

bool extract_id_from_cert(X509 *in, string *out) {
  if (in == nullptr)
    return false;
  X509_NAME *sname = X509_get_subject_name(in);
  if (sname == nullptr)
    return false;
  int len = X509_NAME_get_text_by_NID(sname, NID_organizationName, nullptr, 0);
  if (len <= 0)
    return false;
  len++;
  char name_buf[len];
  int n = X509_NAME_get_text_by_NID(sname, NID_organizationName, name_buf, len);
  if (n <= 0)
    return false;
  out->assign((char *)name_buf, strlen(name_buf) + 1);
  return true;
}

// Loads server side certs and keys.
bool load_server_certs_and_key(X509 *        root_cert,
                               key_message & private_key,
                               const string &private_key_cert,
                               SSL_CTX *     ctx) {

  // load auth key, policy_cert and certificate chain
  // Todo: Add other key types
  RSA *r = RSA_new();
  if (!key_to_RSA(private_key, r)) {
    printf("%s() error, line %d, key_to_RSA failed\n", __func__, __LINE__);
    return false;
  }
  EVP_PKEY *auth_private_key = EVP_PKEY_new();
  EVP_PKEY_set1_RSA(auth_private_key, r);

  X509 *x509_auth_key_cert = X509_new();
  if (!asn1_to_x509(private_key_cert, x509_auth_key_cert)) {
    printf("%s() error, line %d, asn1_to_x509 failed %d\n",
           __func__,
           __LINE__,
           (int)private_key_cert.size());
    return false;
  }

  STACK_OF(X509) *stack = sk_X509_new_null();
  if (sk_X509_push(stack, root_cert) == 0) {
    printf("%s() error, line %d, sk_X509_push failed\n", __func__, __LINE__);
    return false;
  }

#ifdef BORING_SSL
  if (!SSL_CTX_use_certificate(ctx, x509_auth_key_cert)) {
    printf("%s() error, line %d, use cert failed\n", __func__, __LINE__);
    return false;
  }
  if (!SSL_CTX_use_PrivateKey(ctx, auth_private_key)) {
    printf("%s() error, line %d, use priv key failed\n", __func__, __LINE__);
    return false;
  }

  if (!SSL_CTX_set1_chain(ctx, stack)) {
    printf("%s() error, line %d, set1 chain error\n", __func__, __LINE__);
    return false;
  }
#else
  if (SSL_CTX_use_cert_and_key(ctx,
                               x509_auth_key_cert,
                               auth_private_key,
                               stack,
                               1)
      <= 0) {
    printf("%s() error, line %d, SSL_CTX_use_cert_and_key failed\n",
           __func__,
           __LINE__);
#  ifdef DEBUG
    printf("cert:\n");
    X509_print_fp(stdout, x509_auth_key_cert);
    printf("key:\n");
    print_key(private_key);
    printf("\n");
#  endif
    return false;
  }
#endif

  if (!SSL_CTX_check_private_key(ctx)) {
    printf("%s() error, line %d, SSL_CTX_check_private_key failed\n",
           __func__,
           __LINE__);
    return false;
  }
  SSL_CTX_add_client_CA(ctx, root_cert);

#ifdef BORING_SSL
  SSL_CTX_add1_chain_cert(ctx, root_cert);
#else
  SSL_CTX_add1_to_CA_list(ctx, root_cert);

#  ifdef DEBUG
  const STACK_OF(X509_NAME) *ca_list = SSL_CTX_get0_CA_list(ctx);
  printf("CA names to offer\n");
  if (ca_list != nullptr) {
    for (int i = 0; i < sk_X509_NAME_num(ca_list); i++) {
      X509_NAME *name = sk_X509_NAME_value(ca_list, i);
      print_cn_name(name);
    }
  }
#  endif
#endif  // BORING_SSL

  return true;
}

// Loads server side certs and keys.
bool load_server_certs_and_key(X509 *        root_cert,
                               X509 *        peer_root_cert,
                               int           cert_chain_length,
                               string *      cert_chain,
                               key_message & private_key,
                               const string &private_key_cert,
                               SSL_CTX *     ctx) {

  private_key.set_certificate(private_key_cert);  // new

  // load auth key, policy_cert and certificate chain
  // Todo: Add other key types
  RSA *r = RSA_new();
  if (r == nullptr) {
    printf("%s() error, line %d, Can't allocate RSA key\n", __func__, __LINE__);
    return false;
  }

  bool      ret = true;
  EVP_PKEY *auth_private_key = nullptr;
  X509 *    x509_auth_key_cert = nullptr;
  STACK_OF(X509) *stack = nullptr;


  if (!key_to_RSA(private_key, r)) {
    printf("%s() error, line %d, key_to_RSA failed\n", __func__, __LINE__);
    ret = false;
    goto done;
  }
  auth_private_key = EVP_PKEY_new();
  EVP_PKEY_set1_RSA(auth_private_key, r);

  x509_auth_key_cert = X509_new();
  if (!asn1_to_x509(private_key_cert, x509_auth_key_cert)) {
    printf("%s() error, line %d, asn1_to_x509 failed %d\n",
           __func__,
           __LINE__,
           (int)private_key_cert.size());
    ret = false;
    goto done;
  }

  stack = sk_X509_new_null();
  if (sk_X509_push(stack, peer_root_cert) == 0) {
    printf("%s() error, line %d, sk_X509_push failed\n", __func__, __LINE__);
    ret = false;
    goto done;
  }

  SSL_CTX_add_client_CA(ctx, peer_root_cert);
  SSL_CTX_add1_chain_cert(ctx, peer_root_cert);

// When intermediate certs exist
#if 0
  X509* X509_chain_certs[cert_chain_length];
  for (int i = 0; i < cert_chain_length; i++) {
    X509_chain_certs[i] = X509_new();
    if (!asn1_to_x509(cert_chain[i], X509_chain_certs[i])) {
      printf("%s() error, line %d, cert chain\n", __func__, __LINE__);
      return false;
    }
    X509_STORE_add_cert(cs, X509_cert_chains[i]);
  }
#endif

#ifdef DEBUG
  printf("load_server_certs_and_key, peer_root_cert:\n");
  X509_print_fp(stdout, peer_root_cert);
  printf("load_server_certs_and_key, root_cert:\n");
  X509_print_fp(stdout, root_cert);
  printf("\nload_server_certs_and_key, auth cert:\n");
  X509_print_fp(stdout, x509_auth_key_cert);
  printf("\n");
#endif

#ifdef BORING_SSL
  if (!SSL_CTX_use_certificate(ctx, x509_auth_key_cert)) {
    printf("%s() error, line %d, use cert failed\n", __func__, __LINE__);
    ret = false;
    goto done;
  }
  if (!SSL_CTX_use_PrivateKey(ctx, auth_private_key)) {
    printf("%s() error, line %d, use priv key failed\n", __func__, __LINE__);
    ret = false;
    goto done;
  }

  if (!SSL_CTX_set1_chain(ctx, stack)) {
    printf("%s() error, line %d, set1 chain error\n", __func__, __LINE__);
    ret = false;
    goto done;
  }
#else
  if (SSL_CTX_use_cert_and_key(ctx,
                               x509_auth_key_cert,
                               auth_private_key,
                               stack,
                               1)
      <= 0) {
    printf("%s() error, line %d, SSL_CTX_use_cert_and_key failed\n",
           __func__,
           __LINE__);
#  ifdef DEBUG
    printf("auth cert:\n");
    X509_print_fp(stdout, x509_auth_key_cert);
    printf("key:\n");
    print_key(private_key);
    printf("\n");
#  endif
    ret = false;
    goto done;
  }
#endif

  if (!SSL_CTX_check_private_key(ctx)) {
    printf("%s() error, line %d, SSL_CTX_check_private_key failed\n",
           __func__,
           __LINE__);
    ret = false;
    goto done;
  }

#ifdef DEBUG
  {
    const STACK_OF(X509_NAME) *ca_list = SSL_CTX_get0_CA_list(ctx);
    printf("CA names to offer\n");
    if (ca_list != nullptr) {
      for (int i = 0; i < sk_X509_NAME_num(ca_list); i++) {
        X509_NAME *name = sk_X509_NAME_value(ca_list, i);
        print_cn_name(name);
      }
    }
  }
#endif

done:
  if (r != nullptr) {
    RSA_free(r);
    r = nullptr;
  }
  if (auth_private_key != nullptr) {
    EVP_PKEY_free(auth_private_key);
    auth_private_key = nullptr;
  }
  return ret;
}

bool certifier::framework::server_dispatch(
    const string &host_name,
    int           port,
    const string &asn1_root_cert,
    const string &asn1_peer_root_cert,
    int           num_certs,
    string *      cert_chain,
    key_message & private_key,
    const string &private_key_cert,
    void (*func)(secure_authenticated_channel &)) {

#ifdef DEBUG
  printf("\nserver_dispatch\n");
  printf("ans1_root_cert: ");
  print_bytes(asn1_root_cert.size(), (byte *)asn1_root_cert.data());
  printf("\n");
  printf("ans1_peer_root_cert: ");
  print_bytes(asn1_peer_root_cert.size(), (byte *)asn1_peer_root_cert.data());
  printf("\n");
  printf("private_key_cert: ");
  print_bytes(private_key_cert.size(), (byte *)private_key_cert.data());
  printf("\n");
  printf("private_key: ");
  print_key(private_key);
  printf("\n");
#endif

  OPENSSL_init_ssl(0, NULL);
  SSL_load_error_strings();

  X509 *root_cert = X509_new();
  if (!asn1_to_x509(asn1_root_cert, root_cert)) {
    printf("%s() error, line %d, Can't convert cert\n", __func__, __LINE__);
    return false;
  }
  X509 *peer_root_cert = X509_new();
  if (!asn1_to_x509(asn1_peer_root_cert, peer_root_cert)) {
    printf("%s() error, line %d, Can't convert cert\n", __func__, __LINE__);
    return false;
  }

  // Get a socket.
  int sock = -1;
  if (!open_server_socket(host_name, port, &sock)) {
    printf("%s() error, line %d, Can't open server socket to %s:%d\n",
           __func__,
           __LINE__,
           host_name.c_str(),
           port);
    return false;
  }

  // Set up TLS handshake data.
  SSL_METHOD *method = (SSL_METHOD *)TLS_server_method();
  SSL_CTX *   ctx = SSL_CTX_new(method);
  if (ctx == NULL) {
    printf("%s() error, line %d, SSL_CTX_new failed (1)\n", __func__, __LINE__);
    return false;
  }
  X509_STORE *cs = SSL_CTX_get_cert_store(ctx);
  X509_STORE_add_cert(cs, peer_root_cert);

  X509 *x509_auth_cert = X509_new();
  if (asn1_to_x509(private_key_cert, x509_auth_cert)) {
    X509_STORE_add_cert(cs, x509_auth_cert);
  } else {
    printf("DIDNT ADD AUTH CERT\n");
  }

  if (!load_server_certs_and_key(root_cert,
                                 peer_root_cert,
                                 num_certs,
                                 cert_chain,
                                 private_key,
                                 private_key_cert,
                                 ctx)) {
    printf("%s() error, line %d, SSL_CTX_new failed (2)\n", __func__, __LINE__);
    return false;
  }

  const long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
  SSL_CTX_set_options(ctx, flags);

#if 0
  // This is unnecessary usually.
  if(!isRoot()) {
    printf("server_dispatch: This program must be run as root/sudo user!!");
    return false;
  }
#endif

  // Verify peer
  SSL_CTX_set_verify(ctx,
                     SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                     nullptr);
#ifdef DEBUG
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
#endif

  // Testing hook: Allow pytests to invoke with NULL 'func' hdlr.
  // Close socket before exiting, so we don't have unpredictable
  // behaviour when tests are run on CI machines.
  if (!func) {
    close(sock);
    return true;
  }

  while (1) {
#ifdef DEBUG
    printf("at accept\n");
#endif
    struct sockaddr_in addr;
    unsigned int       len = sizeof(sockaddr_in);
    int                client = accept(sock, (struct sockaddr *)&addr, &len);
    string             my_role("server");
    secure_authenticated_channel nc(my_role);
    if (!nc.init_server_ssl(host_name,
                            port,
                            asn1_root_cert,
                            asn1_peer_root_cert,
                            num_certs,
                            cert_chain,
                            private_key,
                            private_key_cert)) {
      continue;
    }
    nc.ssl_ = SSL_new(ctx);
    SSL_set_fd(nc.ssl_, client);
    nc.sock_ = client;
    nc.server_channel_accept_and_auth(func);
  }
  return true;
}

bool certifier::framework::server_dispatch(
    const string &host_name,
    int           port,
    const string &asn1_root_cert,
    key_message & private_key,
    const string &private_key_cert,
    void (*func)(secure_authenticated_channel &)) {

#ifdef DEBUG
  printf("\nserver_dispatch\n");
  printf("ans1_root_cert: ");
  print_bytes(asn1_root_cert.size(), (byte *)asn1_root_cert.data());
  printf("\n");
  printf("private_key_cert: ");
  print_bytes(private_key_cert.size(), (byte *)private_key_cert.data());
  printf("\n");
  printf("private_key: ");
  print_key(private_key);
  printf("\n");
#endif

  OPENSSL_init_ssl(0, NULL);
  SSL_load_error_strings();

  X509 *root_cert = X509_new();
  if (!asn1_to_x509(asn1_root_cert, root_cert)) {
    printf("%s() error, line %d, Can't convert cert\n", __func__, __LINE__);
    return false;
  }

  // Get a socket.
  int sock = -1;
  if (!open_server_socket(host_name, port, &sock)) {
    printf("%s() error, line %d, Can't open server socket to %s:%d\n",
           __func__,
           __LINE__,
           host_name.c_str(),
           port);
    return false;
  }

  // Set up TLS handshake data.
  SSL_METHOD *method = (SSL_METHOD *)TLS_server_method();
  SSL_CTX *   ctx = SSL_CTX_new(method);
  if (ctx == NULL) {
    printf("%s() error, line %d, SSL_CTX_new failed (1)\n", __func__, __LINE__);
    return false;
  }
  X509_STORE *cs = SSL_CTX_get_cert_store(ctx);
  X509_STORE_add_cert(cs, root_cert);

  X509 *x509_auth_cert = X509_new();
  if (asn1_to_x509(private_key_cert, x509_auth_cert)) {
    X509_STORE_add_cert(cs, x509_auth_cert);
  }

  if (!load_server_certs_and_key(root_cert,
                                 private_key,
                                 private_key_cert,
                                 ctx)) {
    printf("%s() error, line %d, SSL_CTX_new failed (2)\n", __func__, __LINE__);
    return false;
  }

  const long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
  SSL_CTX_set_options(ctx, flags);

#if 0
  // This is unnecessary usually.
  if(!isRoot()) {
    printf("server_dispatch: This program must be run as root/sudo user!!");
    return false;
  }
#endif

  // Verify peer
  SSL_CTX_set_verify(ctx,
                     SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                     nullptr);
#ifdef DEBUG
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
#endif

  // Testing hook: Allow pytests to invoke with NULL 'func' hdlr.
  // Close socket before exiting, so we don't have unpredictable
  // behaviour when tests are run on CI machines.
  if (!func) {
    close(sock);
    return true;
  }

  while (1) {
#ifdef DEBUG
    printf("at accept\n");
#endif
    struct sockaddr_in addr;
    unsigned int       len = sizeof(sockaddr_in);
    int                client = accept(sock, (struct sockaddr *)&addr, &len);
    string             my_role("server");
    secure_authenticated_channel nc(my_role);
    if (!nc.init_server_ssl(host_name,
                            port,
                            asn1_root_cert,
                            private_key,
                            private_key_cert)) {
      continue;
    }
    nc.ssl_ = SSL_new(ctx);
    SSL_set_fd(nc.ssl_, client);
    nc.sock_ = client;
    nc.server_channel_accept_and_auth(func);
  }
  return true;
}

bool certifier::framework::server_dispatch(
    const string &          host_name,
    int                     port,
    const cc_trust_manager &mgr,
    void (*func)(secure_authenticated_channel &)) {

  return server_dispatch(
      host_name,
      port,
      (string &)mgr.serialized_policy_cert_,  // Policy-certificate / Root cert
      (key_message &)mgr.private_auth_key_,  // Private key (whose public key is
                                             // named in the admission cert)

      // Admission cert
      (const string &)mgr.serialized_primary_admissions_cert_,
      func);
}

certifier::framework::secure_authenticated_channel::
    secure_authenticated_channel(string &role) {
  role_ = role;
  channel_initialized_ = false;
  ssl_ctx_ = nullptr;
  store_ctx_ = nullptr;
  ssl_ = nullptr;
  sock_ = -1;
  my_cert_ = nullptr;
  root_cert_ = nullptr;
  peer_root_cert_ = nullptr;
  peer_cert_ = nullptr;
  num_cert_chain_ = 0;
  cert_chain_ = nullptr;
  peer_id_.clear();
}

certifier::framework::secure_authenticated_channel::
    ~secure_authenticated_channel() {
  role_.clear();
  channel_initialized_ = false;

  // ? FIXME - Seems to cause a memory leak detected in pytests
  // private_key_

  if (ssl_ctx_ != nullptr)
    SSL_CTX_free(ssl_ctx_);
  ssl_ctx_ = nullptr;

  if (store_ctx_ != nullptr)
    X509_STORE_CTX_free(store_ctx_);
  store_ctx_ = nullptr;

  ssl_ = nullptr;
  if (sock_ > 0)
    ::close(sock_);
  sock_ = -1;

  if (my_cert_ != nullptr)
    X509_free(my_cert_);
  my_cert_ = nullptr;

  if (peer_cert_ != nullptr)
    X509_free(peer_cert_);
  peer_cert_ = nullptr;

  if (root_cert_ != nullptr)
    X509_free(root_cert_);
  root_cert_ = nullptr;
  if (peer_root_cert_ != nullptr)
    X509_free(peer_root_cert_);
  peer_root_cert_ = nullptr;

  peer_id_.clear();
  if (cert_chain_ != nullptr) {
    delete[] cert_chain_;
    cert_chain_ = nullptr;
  }
  num_cert_chain_ = 0;
}

bool certifier::framework::secure_authenticated_channel::init_client_ssl(
    const string &host_name,
    int           port,
    const string &asn1_root_cert,
    const string &peer_asn1_root_cert,
    int           cert_chain_length,
    string *      der_certs,
    key_message & private_key,
    const string &auth_cert) {

  OPENSSL_init_ssl(0, NULL);
  SSL_load_error_strings();

  private_key_.CopyFrom(private_key);
  private_key_.set_certificate(auth_cert);  // NEW

  asn1_root_cert_.assign((char *)asn1_root_cert.data(), asn1_root_cert.size());
  asn1_peer_root_cert_.assign((char *)peer_asn1_root_cert.data(),
                              peer_asn1_root_cert.size());

  root_cert_ = X509_new();
  if (!asn1_to_x509(asn1_root_cert_, root_cert_)) {
    printf("%s() error, line %d, init_client_ssl: root invalid\n",
           __func__,
           __LINE__);
    if (asn1_root_cert_.size() == 0) {
      printf("root cert empty\n");
    } else {
      print_bytes(asn1_root_cert_.size(), (byte *)asn1_root_cert_.data());
      printf("\n");
    }
    return false;
  }

  peer_root_cert_ = X509_new();
  if (!asn1_to_x509(asn1_peer_root_cert_, peer_root_cert_)) {
    printf("%s() error, line %d, init_client_ssl: peer root cert invalid\n",
           __func__,
           __LINE__);
    if (asn1_peer_root_cert_.size() == 0) {
      printf("peer root cert empty\n");
    } else {
      print_bytes(asn1_peer_root_cert_.size(),
                  (byte *)asn1_peer_root_cert_.data());
      printf("\n");
    }
    return false;
  }

  num_cert_chain_ = cert_chain_length;
  cert_chain_ = new string[cert_chain_length];
  for (int i = 0; i < cert_chain_length; i++) {
    cert_chain_[i] = der_certs[i];
  }

  const SSL_METHOD *method = TLS_client_method();
  if (method == nullptr) {
    printf("%s() error, line %d, Can't get method\n", __func__, __LINE__);
    return false;
  }

  ssl_ctx_ = SSL_CTX_new(method);
  if (ssl_ctx_ == nullptr) {
    printf("%s() error, line %d, Can't get SSL_CTX\n", __func__, __LINE__);
    return false;
  }

  asn1_my_cert_.assign(auth_cert.data(), auth_cert.size());
  X509_STORE *cs = SSL_CTX_get_cert_store(ssl_ctx_);
  X509_STORE_add_cert(cs, peer_root_cert_);

// When intermediate certs exist
#if 0
  X509* X509_chain_certs[cert_chain_length];
  for (int i = 0; i < cert_chain_length; i++) {
    X509_chain_certs[i] = X509_new();
    if (!asn1_to_x509(cert_chain_[i], X509_cert_chains[i])) {
      printf("%s() error, line %d, cert chain\n", __func__, __LINE__);
      return false;
    }
    X509_STORE_add_cert(cs, X509_cert_chains[i]);
  }
#endif

  X509 *x509_auth_cert = X509_new();
  if (asn1_to_x509(auth_cert, x509_auth_cert)) {
    X509_STORE_add_cert(cs, x509_auth_cert);
  } else {
    printf("COULDNT ADD\n");
  }

#ifdef DEBUG
  printf("init_client_ssl, peer root cert:\n");
  X509_print_fp(stdout, peer_root_cert_);
  printf("init_client_ssl, auth cert:\n");
  X509_print_fp(stdout, x509_auth_cert);
  printf("\n");
#endif

  // For debugging: SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
  SSL_CTX_set_verify(ssl_ctx_, SSL_VERIFY_PEER, nullptr);

  SSL_CTX_set_verify_depth(ssl_ctx_, 4);
  const long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
  SSL_CTX_set_options(ssl_ctx_, flags);

  if (!load_client_certs_and_key()) {
    printf("%s() error, line %d, load_client_certs_and_key failed\n",
           __func__,
           __LINE__);
    return false;
  }

  if (!open_client_socket(host_name, port, &sock_)) {
    printf(
        "%s() error, line %d, Can't open client socket: host='%s', port=%d\n",
        __func__,
        __LINE__,
        host_name.c_str(),
        port);
    return false;
  }

  ssl_ = SSL_new(ssl_ctx_);
  SSL_set_fd(ssl_, sock_);
  int res = SSL_set_cipher_list(ssl_, "TLS_AES_256_GCM_SHA384");  // Change?

  // SSL_connect - initiate the TLS/SSL handshake with an TLS/SSL server
  int ret = SSL_connect(ssl_);
  if (ret <= 0) {
    int err = SSL_get_error(ssl_, ret);
    printf("%s() error, line %d, ssl_connect failed, ret=%d, err=%d: %s\n",
           __func__,
           __LINE__,
           ret,
           err,
           ssl_strerror(err));
    return false;
  }

  // Verify a server certificate was presented during the negotiation
  peer_cert_ = SSL_get_peer_certificate(ssl_);
  if (peer_cert_ != nullptr) {
    peer_id_.clear();
    if (!extract_id_from_cert(peer_cert_, &peer_id_)) {
      printf("%s() error, line %d, Can't extract id\n", __func__, __LINE__);
    }
  }

#ifdef DEBUG
  if (peer_cert_) {
    printf("Client: Peer cert presented in nego\n");
  } else {
    printf("Client: No peer cert presented in nego\n");
  }
#endif
  channel_initialized_ = true;
  return true;
}

bool certifier::framework::secure_authenticated_channel::init_server_ssl(
    const string &host_name,
    int           port,
    const string &asn1_root_cert,
    const string &peer_asn1_root_cert,
    int           cert_chain_length,
    string *      der_certs,
    key_message & private_key,
    const string &auth_cert) {

  OPENSSL_init_ssl(0, NULL);
  SSL_load_error_strings();

  // set keys and cert
  private_key_.CopyFrom(private_key);
  private_key_.set_certificate(auth_cert);  // NEW

  asn1_root_cert_.assign((char *)asn1_root_cert.data(), asn1_root_cert.size());
  asn1_peer_root_cert_.assign((char *)peer_asn1_root_cert.data(),
                              peer_asn1_root_cert.size());

  root_cert_ = X509_new();
  if (!asn1_to_x509(asn1_root_cert, root_cert_)) {
    printf("%s() error, line %d, Can't translate der to X509\n",
           __func__,
           __LINE__);
    return false;
  }

  peer_root_cert_ = X509_new();
  if (!asn1_to_x509(peer_asn1_root_cert, peer_root_cert_)) {
    printf("%s() error, line %d, Can't translate der to X509\n",
           __func__,
           __LINE__);
    return false;
  }

  num_cert_chain_ = cert_chain_length;
  cert_chain_ = new string[cert_chain_length];
  for (int i = 0; i < cert_chain_length; i++) {
    cert_chain_[i] = der_certs[i];
  }
  return true;
}

bool certifier::framework::secure_authenticated_channel::init_client_ssl(
    const string &host_name,
    int           port,
    const string &asn1_root_cert,
    key_message & private_key,
    const string &auth_cert) {

  OPENSSL_init_ssl(0, NULL);
  SSL_load_error_strings();

  private_key_.CopyFrom(private_key);

  asn1_root_cert_.assign((char *)asn1_root_cert.data(), asn1_root_cert.size());

  root_cert_ = X509_new();
  if (!asn1_to_x509(asn1_root_cert_, root_cert_)) {
    printf("%s() error, line %d, init_client_ssl: root cert invalid\n",
           __func__,
           __LINE__);
    if (asn1_root_cert_.size() == 0) {
      printf("root cert empty\n");
    } else {
      print_bytes(asn1_root_cert_.size(), (byte *)asn1_root_cert_.data());
      printf("\n");
    }
    return false;
  }

  // Root cert is also peer root cert
  asn1_peer_root_cert_.assign((char *)asn1_root_cert.data(),
                              asn1_root_cert.size());

  peer_root_cert_ = X509_new();
  if (!asn1_to_x509(asn1_peer_root_cert_, peer_root_cert_)) {
    printf("%s() error, line %d, init_client_ssl: peer root cert invalid\n",
           __func__,
           __LINE__);
    if (asn1_peer_root_cert_.size() == 0) {
      printf("root cert empty\n");
    } else {
      print_bytes(asn1_peer_root_cert_.size(),
                  (byte *)asn1_peer_root_cert_.data());
      printf("\n");
    }
    return false;
  }

  const SSL_METHOD *method = TLS_client_method();
  if (method == nullptr) {
    printf("%s() error, line %d, Can't get method\n", __func__, __LINE__);
    return false;
  }

  ssl_ctx_ = SSL_CTX_new(method);
  if (ssl_ctx_ == nullptr) {
    printf("%s() error, line %d, Can't get SSL_CTX\n", __func__, __LINE__);
    return false;
  }

  X509_STORE *cs = SSL_CTX_get_cert_store(ssl_ctx_);
  asn1_my_cert_ = auth_cert;

  X509_STORE_add_cert(cs, peer_root_cert_);

  X509 *x509_auth_cert = X509_new();
  if (asn1_to_x509(auth_cert, x509_auth_cert)) {
    X509_STORE_add_cert(cs, x509_auth_cert);
  }

  // For debugging: SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
  SSL_CTX_set_verify(ssl_ctx_, SSL_VERIFY_PEER, nullptr);

  SSL_CTX_set_verify_depth(ssl_ctx_, 4);
  const long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
  SSL_CTX_set_options(ssl_ctx_, flags);

  if (!load_client_certs_and_key()) {
    printf("%s() error, line %d, load_client_certs_and_key failed\n",
           __func__,
           __LINE__);
    return false;
  }

  if (!open_client_socket(host_name, port, &sock_)) {
    printf(
        "%s() error, line %d, Can't open client socket: host='%s', port=%d\n",
        __func__,
        __LINE__,
        host_name.c_str(),
        port);
    return false;
  }

  ssl_ = SSL_new(ssl_ctx_);
  SSL_set_fd(ssl_, sock_);
  int res = SSL_set_cipher_list(ssl_, "TLS_AES_256_GCM_SHA384");  // Change?

  // SSL_connect - initiate the TLS/SSL handshake with an TLS/SSL server
  int ret = SSL_connect(ssl_);
  if (ret <= 0) {
    int err = SSL_get_error(ssl_, ret);
    printf("%s() error, line %d, ssl_connect failed, ret=%d, err=%d: %s\n",
           __func__,
           __LINE__,
           ret,
           err,
           ssl_strerror(err));
    return false;
  }

  // Verify a server certificate was presented during the negotiation
  peer_cert_ = SSL_get_peer_certificate(ssl_);
  if (peer_cert_ != nullptr) {
    peer_id_.clear();
    if (!extract_id_from_cert(peer_cert_, &peer_id_)) {
      printf("%s() error, line %d, Can't extract id\n", __func__, __LINE__);
    }
  }

#ifdef DEBUG
  if (peer_cert_) {
    printf("Client: Peer cert presented in nego\n");
  } else {
    printf("Client: No peer cert presented in nego\n");
  }
#endif
  channel_initialized_ = true;
  return true;
}

bool certifier::framework::secure_authenticated_channel::init_client_ssl(
    const string &          host_name,
    int                     port,
    const cc_trust_manager &mgr) {

  return secure_authenticated_channel::init_client_ssl(
      host_name,
      port,
      (string &)mgr.serialized_policy_cert_,
      (key_message &)mgr.private_auth_key_,
      (const string &)mgr.serialized_primary_admissions_cert_);
}

// Loads client side certs and keys.  Note: key for private_key is in
//    the key.
bool certifier::framework::secure_authenticated_channel::
    load_client_certs_and_key() {
  // Todo: Add other key types
  RSA *r = RSA_new();
  if (!key_to_RSA(private_key_, r)) {
    printf("%s() error, line %d, Can't convert to RSA key\n",
           __func__,
           __LINE__);
    return false;
  }
  EVP_PKEY *auth_private_key = EVP_PKEY_new();
  EVP_PKEY_set1_RSA(auth_private_key, r);

  X509 *x509_auth_key_cert = X509_new();
  if (!asn1_to_x509(asn1_my_cert_, x509_auth_key_cert)) {
    printf("%s() error, line %d, can't translate der to X509 %d\n",
           __func__,
           __LINE__,
           (int)asn1_my_cert_.size());
    return false;
  }

  STACK_OF(X509) *stack = sk_X509_new_null();
#if 0
  if (sk_X509_push(stack, peer_root_cert_) == 0) {
    printf("load_client_certs_and_key, error 3\n");
    return false;
  }
#endif

  if (!SSL_CTX_use_certificate(ssl_ctx_, x509_auth_key_cert)) {
    printf("%s() error, line %d, use cert failed\n", __func__, __LINE__);
    return false;
  }
  if (!SSL_CTX_use_PrivateKey(ssl_ctx_, auth_private_key)) {
    printf("%s() error, line %d, use priv key failed\n", __func__, __LINE__);
    return false;
  }

  if (!SSL_CTX_check_private_key(ssl_ctx_)) {
    printf("%s() error, line %d, private key check failed\n",
           __func__,
           __LINE__);
    return false;
  }

#ifdef BORING_SSL
  SSL_CTX_add1_chain_cert(ssl_ctx_, peer_root_cert_);
#else
  if (SSL_CTX_use_cert_and_key(ssl_ctx_,
                               x509_auth_key_cert,
                               auth_private_key,
                               stack,
                               1)
      <= 0) {
    printf("%s() error, line %d, use_cert_and_key failed\n",
           __func__,
           __LINE__);
    return false;
  }

  SSL_CTX_add1_to_CA_list(ssl_ctx_, peer_root_cert_);

#  ifdef DEBUG
  const STACK_OF(X509_NAME) *ca_list = SSL_CTX_get0_CA_list(ssl_ctx_);
  printf("CA names to offer\n");
  if (ca_list != nullptr) {
    for (int i = 0; i < sk_X509_NAME_num(ca_list); i++) {
      X509_NAME *name = sk_X509_NAME_value(ca_list, i);
      print_cn_name(name);
    }
  }
#  endif  // DEBUG
#endif    // BORING_SSL
  return true;
}

void certifier::framework::secure_authenticated_channel::
    server_channel_accept_and_auth(
        void (*func)(secure_authenticated_channel &)) {

  // accept and carry out auth
  int res = SSL_accept(ssl_);
  if (res != 1) {
    printf("%s() error, line %d, Can't SSL_accept connection"
           ", res=%d\n",
           __func__,
           __LINE__,
           res);
    unsigned long code = ERR_get_error();
    printf("Accept error(%lx, %ld): %s\n",
           code,
           code & 0xffffff,
           ERR_lib_error_string(code));
    print_ssl_error(SSL_get_error(ssl_, res));
    if (ssl_ != nullptr) {
      SSL_free(ssl_);
      ssl_ = nullptr;
    }
    return;
  }
  sock_ = SSL_get_fd(ssl_);

#ifdef DEBUG
  printf("Accepted ssl connection using %s \n", SSL_get_cipher(ssl_));
#endif

  // Verify a client certificate was presented during the negotiation
  peer_cert_ = SSL_get_peer_certificate(ssl_);
  if (peer_cert_ != nullptr) {
    if (!extract_id_from_cert(peer_cert_, &peer_id_)) {
      printf("%s() error, line %d, Can't extract id\n", __func__, __LINE__);
    }
  }

#ifdef DEBUG
  if (peer_cert_) {
    printf("server_channel_accept_and_auth: Peer cert presented in nego\n");
  } else {
    printf("server_channel_accept_and_auth: No peer cert presented in nego\n");
  }
#endif

  channel_initialized_ = true;
  func(*this);
  return;
}

bool certifier::framework::secure_authenticated_channel::init_server_ssl(
    const string &host_name,
    int           port,
    const string &asn1_root_cert,
    key_message & private_key,
    const string &auth_cert) {

  SSL_load_error_strings();

  // set keys and cert
  private_key_.CopyFrom(private_key);

  asn1_root_cert_.assign((char *)asn1_root_cert.data(), asn1_root_cert.size());
  asn1_peer_root_cert_.assign((char *)asn1_root_cert.data(),
                              asn1_root_cert.size());

  root_cert_ = X509_new();
  if (!asn1_to_x509(asn1_root_cert, root_cert_)) {
    printf("%s() error, line %d, Can't translate der to X509\n",
           __func__,
           __LINE__);
    return false;
  }
  peer_root_cert_ = X509_new();
  if (!asn1_to_x509(asn1_peer_root_cert_, peer_root_cert_)) {
    printf("%s() error, line %d, Can't translate der to X509\n",
           __func__,
           __LINE__);
    return false;
  }
  return true;
}

bool certifier::framework::secure_authenticated_channel::init_server_ssl(
    const string &          host_name,
    int                     port,
    const cc_trust_manager &mgr) {
  return secure_authenticated_channel::init_server_ssl(
      host_name,
      port,
      (string &)mgr.serialized_policy_cert_,
      (key_message &)mgr.private_auth_key_,
      mgr.serialized_primary_admissions_cert_);
}

int certifier::framework::secure_authenticated_channel::read(int   size,
                                                             byte *b) {
  return SSL_read(ssl_, b, size);
}

int certifier::framework::secure_authenticated_channel::read(string *out) {
  return sized_ssl_read(ssl_, out);
}

int certifier::framework::secure_authenticated_channel::write(int   size,
                                                              byte *b) {
  return sized_ssl_write(ssl_, size, b);
}

void certifier::framework::secure_authenticated_channel::close() {
  ::close(sock_);
  if (ssl_ != nullptr) {
    SSL_free(ssl_);
    ssl_ = nullptr;
  }
}

bool certifier::framework::secure_authenticated_channel::get_peer_id(
    string *out_peer_id) {
  out_peer_id->assign((char *)peer_id_.data(), peer_id_.size());
  return true;
}
