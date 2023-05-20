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
#include "gramine_api.h"
#endif
#include "cc_useful.h"

using namespace certifier::framework;
using namespace certifier::utilities;

#ifdef SEV_SNP
extern bool sev_Init(const string& platform_ark_der_file,
    const string& platform_ask_der_file,
    const string& platform_vcek_der_file);
extern bool plat_certs_initialized;
extern string platform_certs;
extern string serialized_ark_cert;
extern string serialized_ask_cert;
extern string serialized_vcek_cert;
#endif

#if OE_CERTIFIER
extern bool oe_Init(const string& pem_cert_chain_file);
extern string pem_cert_chain;
#endif

#ifdef GRAMINE_CERTIFIER
extern bool gramine_platform_cert_initialized;
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
//  You may want to augment these or write replacements if your needs are fancier.

//#define DEBUG

certifier::framework::cc_trust_data::cc_trust_data(const string& enclave_type, const string& purpose,
    const string& policy_store_name) {

  if (purpose == "authentication" || purpose == "attestation") {
    purpose_= purpose;
    cc_basic_data_initialized_ = true;
  } else {
    cc_basic_data_initialized_ = false;
    purpose_ = "unknown";
  }
  enclave_type_ = enclave_type;
  store_file_name_ = policy_store_name;
  cc_policy_info_initialized_= false;
  cc_policy_store_initialized_ = false;
  cc_service_key_initialized_ = false;
  cc_service_cert_initialized_ = false;
  cc_service_platform_rule_initialized_ = false;
  cc_sealing_key_initialized_ = false;
  cc_provider_provisioned_ = false;
  x509_policy_cert_ = nullptr;
  cc_is_certified_ = false;
  peer_data_initialized_ = false;
}

certifier::framework::cc_trust_data::cc_trust_data() {
  cc_basic_data_initialized_ = false;
  cc_policy_info_initialized_= false;
  cc_policy_store_initialized_ = false;
  cc_service_key_initialized_ = false;
  cc_service_cert_initialized_ = false;
  cc_service_platform_rule_initialized_ = false;
  cc_sealing_key_initialized_ = false;
  cc_provider_provisioned_ = false;
  x509_policy_cert_ = nullptr;
  cc_is_certified_ = false;
}

certifier::framework::cc_trust_data::~cc_trust_data() {
}

bool certifier::framework::cc_trust_data::cc_all_initialized() {
  if (purpose_ == "authentication") {
    return cc_basic_data_initialized_ & cc_auth_key_initialized_ &
           cc_symmetric_key_initialized_& cc_policy_info_initialized_ &
           cc_provider_provisioned_ & cc_policy_store_initialized_;
  } else if (purpose_ == "attestation") {
    return cc_basic_data_initialized_ & cc_service_key_initialized_ &
           cc_sealing_key_initialized_ & cc_policy_info_initialized_ &
           cc_service_platform_rule_initialized_ &
           cc_provider_provisioned_ & cc_policy_store_initialized_;
  } else {
    return false;
  }
}

bool certifier::framework::cc_trust_data::initialize_application_enclave_data(const string& parent_enclave_type,
    int in_fd, int out_fd) {

   if (!cc_policy_info_initialized_) {
      printf("initialize_application_enclave_data: Policy key must be initialized first\n");
      return false;
    }

    if (enclave_type_ != "application-enclave") {
      printf("initialize_application_enclave_data: Not a application enclave\n");
      return false;
    }
    if (!application_Init(parent_enclave_type, in_fd, out_fd)) {
      printf("initialize_application_enclave_data: Can't init application-enclave\n");
      return false;
    }
  cc_provider_provisioned_ = true;
  return true;
}

bool certifier::framework::cc_trust_data::initialize_simulated_enclave_data(const string& attest_key_file_name,
      const string& measurement_file_name, const string& attest_endorsement_file_name) {

    if (!cc_policy_info_initialized_) {
      printf("initialize_simulated_enclave_data: Policy key must be initialized first\n");
      return false;
    }

    if (enclave_type_ != "simulated-enclave") {
      printf("initialize_simulated_enclave_data: Not a simulated enclave\n");
      return false;
    }
    if (!simulated_Init(serialized_policy_cert_, attest_key_file_name, measurement_file_name,
           attest_endorsement_file_name)) {
      printf("initialize_simulated_enclave_data: simulated_init failed\n");
      return false;
    }
  cc_provider_provisioned_ = true;
  return true;
}

bool certifier::framework::cc_trust_data::initialize_gramine_enclave_data(const int size, byte* cert) {
#ifdef GRAMINE_CERTIFIER
  return gramine_Init(size, cert);
#endif
  return true;
}

bool certifier::framework::cc_trust_data::initialize_sev_enclave_data(const string& platform_ark_der_file,
      const string& platform_ask_der_file,
      const string& platform_vcek_der_file) {

#ifdef SEV_SNP
  if (!sev_Init(platform_ark_der_file, platform_ask_der_file,
        platform_vcek_der_file)) {
    printf("initialize_sev_enclave_data: sev_Init failed\n");
    return false;
  }

  cc_provider_provisioned_ = true;
  return true;
#else
  return false;
#endif
}

bool certifier::framework::cc_trust_data::initialize_oe_enclave_data(const string& pem_cert_chain_file) {
#if OE_CERTIFIER
  cc_provider_provisioned_ = true;

  if (!oe_Init(pem_cert_chain_file)) {
    printf("initialize_oe_enclave_data: oe_Init failed\n");
    return false;
  }
  cc_provider_provisioned_ = true;
  return true;
#else
  return false;
#endif
}

bool certifier::framework::cc_trust_data::init_policy_key(int asn1_cert_size, byte* asn1_cert) {
  serialized_policy_cert_.assign((char*)asn1_cert, asn1_cert_size);

  x509_policy_cert_ = X509_new();
  if (x509_policy_cert_ == nullptr)
    return false;
  if (!asn1_to_x509(serialized_policy_cert_, x509_policy_cert_)) {
    printf("init_policy_key: Can't translate cert\n");
    return false;
  }
  if (!PublicKeyFromCert(serialized_policy_cert_, &public_policy_key_)) {
    printf("init_policy_key: Can't get public policy key\n");
    return false;
  }
  cc_policy_info_initialized_ = true;
  return true;
}

void certifier::framework::cc_trust_data::print_trust_data() {
  if (!cc_basic_data_initialized_) {
    printf("print_trust_data: No trust info initialized\n");
    return;
  }
  printf("\nTrust data, enclave_type: %s, purpose: %s, policy file: %s\n",
      enclave_type_.c_str(), purpose_.c_str(), store_file_name_.c_str());

  if (cc_policy_info_initialized_) {
    printf("\nPolicy key\n");
    print_key(public_policy_key_);
    printf("\nPolicy cert\n");
    print_bytes(serialized_policy_cert_.size(),
          (byte*)serialized_policy_cert_.data());
    printf("\n");
  }

  if (cc_auth_key_initialized_) {
    printf("\nPrivate auth key\n");
    print_key(private_auth_key_);
    printf("\nPublic auth key\n");
    print_key(private_auth_key_);
    printf("\n\n");
  }
  if (cc_symmetric_key_initialized_) {
    printf("\nSymmetric key\n");
    print_key(symmetric_key_);
    printf("\n\n");
  }

  if (cc_service_key_initialized_) {
    printf("\nPrivate service key\n");
    print_key(private_service_key_);
    printf("\nPublic service key\n");
    print_key(public_service_key_);
    printf("\n\n");
  }
  if (cc_sealing_key_initialized_) {
    printf("\nSealing key\n");
    print_key(service_sealing_key_);
    printf("\n\n");
  }

  if (cc_service_cert_initialized_) {
    printf("Serialised service cert:\n");
    print_bytes(serialized_service_cert_.size(), (byte*)serialized_service_cert_.data());
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
}

const int max_pad_size_for_store = 1024;

bool certifier::framework::cc_trust_data::save_store() {

  string serialized_store;
  if (!store_.Serialize(&serialized_store)) {
    printf("save_store() can't serialize store\n");
    return false;
  }

  int size_protected_blob= serialized_store.size() + max_pad_size_for_store;
  byte protected_blob[size_protected_blob];

  byte pkb[max_symmetric_key_size_];
  memset(pkb, 0, max_symmetric_key_size_);

  int num_key_bytes = cipher_key_byte_size(symmetric_key_algorithm_.c_str());
  if (num_key_bytes <=0) {
    printf("save_store: can't get key size\n");
    return false;
  }
  if (!get_random(8 * num_key_bytes, pkb)) {
    printf("save_store: can't generate key\n");
    return false;
  }
  key_message pk;
  pk.set_key_name("protect-key");
  pk.set_key_type(symmetric_key_algorithm_);
  pk.set_key_format("vse-key");
  pk.set_secret_key_bits(pkb, num_key_bytes);

  if (!Protect_Blob(enclave_type_, pk, serialized_store.size(),
          (byte*)serialized_store.data(), &size_protected_blob, protected_blob)) {
    printf("save_store: can't protect blob\n");
    return false;
  }

  if (!write_file(store_file_name_, size_protected_blob, protected_blob)) {
    printf("Save_store can't write %s\n", store_file_name_.c_str());
    return false;
  }
  return true;
}

bool certifier::framework::cc_trust_data::fetch_store() {

  int size_protected_blob = file_size(store_file_name_);
  if (size_protected_blob < 0) {
    return false;
  }
  byte protected_blob[size_protected_blob];
  int size_unprotected_blob = size_protected_blob;
  byte unprotected_blob[size_unprotected_blob];

  memset(protected_blob, 0, size_protected_blob);
  memset(unprotected_blob, 0, size_unprotected_blob);

  if (!read_file(store_file_name_, &size_protected_blob, protected_blob)) {
    printf("fetch_store can't read %s\n", store_file_name_.c_str());
    return false;
  }

  key_message pk;
  pk.set_key_name("protect-key");
  pk.set_key_type("aes-256-cbc-hmac-sha256");
  pk.set_key_format("vse-key");

  if (!Unprotect_Blob(enclave_type_, size_protected_blob, protected_blob,
        &pk, &size_unprotected_blob, unprotected_blob)) {
    printf("fetch_store: can't Unprotect\n");
    return false;
  }

  // read policy store
  string serialized_store;
  serialized_store.assign((char*)unprotected_blob, size_unprotected_blob);
  if (!store_.Deserialize(serialized_store)) {
    printf("fetch_store: can't deserialize store\n");
    return false;
  }

  return true;
}

void certifier::framework::cc_trust_data::clear_sensitive_data() {
  // Clear symmetric and private keys.
  // Not necessary on most platforms.
}

bool certifier::framework::cc_trust_data::put_trust_data_in_store() {

  if (!store_.replace_policy_key(public_policy_key_)) {
    printf("put_trust_data_in_store: Can't store policy key\n");
    return false;
  }

  if (purpose_ == "attestation") {

    // put private service key and symmetric keys in store
    string service_key_tag("service-attest-key");
    if (!store_.add_authentication_key(service_key_tag, private_service_key_)) {
      printf("Can't store service key\n");
      return false;
    }
    string sealing_key_tag("sealing-key");
    storage_info_message sm;
    sm.set_storage_type("key");
    sm.set_tag(sealing_key_tag);
    key_message* sk = new(key_message);
    sk->CopyFrom(service_sealing_key_);
    sm.set_allocated_storage_key(sk);
    if (!store_.add_storage_info(sm)) {
      printf("put_trust_data_in_store: Can't store sealing keys\n");
      return false;
    }

    if (cc_service_platform_rule_initialized_) {
      string rule_tag("platform-rule");
      if (!store_.add_signed_claim(rule_tag, platform_rule_)) {
        printf("put_trust_data_in_store: Can't add platform rule\n");
      }
    }
    return true;
  }

  if (purpose_ == "authentication") {

    string auth_tag("auth-key");
    if (!store_.add_authentication_key(auth_tag, private_auth_key_)) {
      printf("put_trust_data_in_store: Can't store auth key\n");
      return false;
    }
    string symmetric_key_tag("app-symmetric-key");
    storage_info_message sm;
    sm.set_storage_type("symmetric-key");
    sm.set_tag(symmetric_key_tag);
    key_message* sk = new(key_message);
    sk->CopyFrom(symmetric_key_);
    sm.set_allocated_storage_key(sk);
    if (!store_.add_storage_info(sm)) {
      printf("put_trust_data_in_store: Can't store app symmetric key\n");
      return false;
    }
    return true;
  }
  return false;
}

bool certifier::framework::cc_trust_data::get_trust_data_from_store() {

  if (purpose_ == "attestation") {

    // put private service key and symmetric keys in store
    string service_key_tag("service-attest-key");
    int index = store_.get_authentication_key_index_by_tag(service_key_tag);
    if (index < 0) {
      return false;
    }
    const key_message* sk = store_.get_authentication_key_by_index(index);
    private_service_key_.CopyFrom(*sk);
    if (!private_key_to_public_key(private_service_key_, &public_service_key_)) {
      printf("get_trust_data_from_store: Can't transform to public key\n");
      return false;
    }
    cc_service_key_initialized_ = true;

    string sealing_key_tag("sealing-key");
    index = store_.get_storage_info_index_by_tag(sealing_key_tag);
    if (index < 0) {
      printf("get_trust_data_from_store: Can't get sealing-key\n");
      return false;
    }
    const storage_info_message* skm = store_.get_storage_info_by_index(index);
    if (skm == nullptr)
      return false;
    service_sealing_key_.CopyFrom(skm->storage_key());
    cc_symmetric_key_initialized_ = true;

    // platform rule?
    string rule_tag("platform-rule");
    index = store_.get_signed_claim_index_by_tag(rule_tag);
    if (index >= 0) {
      const signed_claim_message* psm = store_.get_signed_claim_by_index(index);
      if (psm != nullptr) {
        platform_rule_.CopyFrom(*psm);
      }
      cc_service_platform_rule_initialized_ = true;
      cc_is_certified_ = true;
    }
    return true;
  }

  if (purpose_ == "authentication") {

    string auth_key_tag("auth-key");
    int index = store_.get_authentication_key_index_by_tag(auth_key_tag);
    if (index < 0) {
      printf("get_trust_data_from_store: Can't find authentication key\n");
      return false;
    }
    const key_message* ak = store_.get_authentication_key_by_index(index);
    if (ak == nullptr) {
      printf("get_trust_data_from_store: Can't retrieve authentication key\n");
      return false;
    }
    private_auth_key_.CopyFrom(*ak);
    if (!private_key_to_public_key(private_auth_key_, &public_auth_key_)) {
      printf("get_trust_data_from_store: Can't transform to public key\n");
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
      X509* x = X509_new();
      if (asn1_to_x509(private_auth_key_.certificate(), x)) {
        X509_print_fp(stdout, x);
      }
      X509_free(x);
#endif
    }

    string symmetric_key_tag("app-symmetric-key");
    index = store_.get_storage_info_index_by_tag(symmetric_key_tag);
    if (index < 0) {
      printf("get_trust_data_from_store: Can't get app-symmetric-key\n");
      return false;
    }
    const storage_info_message* skm = store_.get_storage_info_by_index(index);
    if (skm == nullptr)
      return false;
    symmetric_key_.CopyFrom(skm->storage_key());
    cc_symmetric_key_initialized_ = true;

    return true;
  }

  return false;
}

//  public_key_alg can be rsa-2048 (soon: rsa-1024, rsa-4096, ecc-384)
//  symmetric_key_alg can be aes-256
//  hash_alg can be sha-256 (soon: sha-384, sha-512)
//  hmac-alg can be sha-256-hmac (soon: sha-384-hmac, sha-512-hmac)
bool certifier::framework::cc_trust_data::cold_init(const string& public_key_alg,
        const string& symmetric_key_alg) {

  if (!cc_policy_info_initialized_) {
      printf("cold_init: policy key should have been initialized\n");
      return false;
  }

  public_key_algorithm_ = public_key_alg;
  symmetric_key_algorithm_ = symmetric_key_alg;

  // Make up symmetric keys (e.g.-for sealing)for app
  int num_key_bytes;
  if (symmetric_key_alg == "aes-256-cbc-hmac-sha256" ||
      symmetric_key_alg == "aes-256-cbc-hmac-sha384" ||
      symmetric_key_alg == "aes-256-gcm") {
    num_key_bytes = cipher_key_byte_size(symmetric_key_alg.c_str());
    if (num_key_bytes <= 0) {
      printf("cold_init: Can't recover symmetric alg key size\n");
      return false;
    }
  } else {
    printf("cold_init: unsupported encryption algorithm\n");
    return false;
  }
  memset(symmetric_key_bytes_, 0, max_symmetric_key_size_);

  if (purpose_ == "authentication") {

    // put private auth key and symmetric keys in store
    if (!store_.replace_policy_key(public_policy_key_)) {
      printf("cold_init: Can't store policy key\n");
      return false;
    }
    if (!get_random(num_key_bytes, symmetric_key_bytes_)) {
      printf("cold_init: Can't get random bytes for app key\n");
      return false;
    }
    symmetric_key_.set_key_name("app-symmetric-key");
    symmetric_key_.set_key_type(symmetric_key_alg);
    symmetric_key_.set_key_format("vse-key");
    symmetric_key_.set_secret_key_bits(symmetric_key_bytes_, 8 * num_key_bytes);
    cc_symmetric_key_initialized_ = true;

    // make app auth private and public key
    if (public_key_alg == "rsa-2048") {
      if (!make_certifier_rsa_key(2048,  &private_auth_key_)) {
        printf("cold_init: Can't generate App private key\n");
        return false;
      }
    } else if (public_key_alg == "rsa-4096") {
      if (!make_certifier_rsa_key(4096,  &private_auth_key_)) {
        printf("cold_init: Can't generate App private key\n");
        return false;
      }
    } else if (public_key_alg == "ecc-384") {
      if (!make_certifier_ecc_key(384,  &private_auth_key_)) {
        printf("cold_init: Can't generate App private key\n");
        return false;
      }
    } else {
        printf("cold_init: Unsupported public key algorithm\n");
        return false;
    }

    private_auth_key_.set_key_name("auth-key");
    if (!private_key_to_public_key(private_auth_key_, &public_auth_key_)) {
      printf("cold_init: Can't make public Auth key\n");
      return false;
    }

    cc_symmetric_key_initialized_ = true;
    cc_auth_key_initialized_ = true;

  } else if (purpose_ == "attestation") {

    if (!get_random(num_key_bytes, symmetric_key_bytes_)) {
      printf("cold_init: Can't get random bytes for app key\n");
      return false;
    }
    symmetric_key_.set_key_name("sealing-key");
    symmetric_key_.set_key_type(symmetric_key_alg);
    symmetric_key_.set_key_format("vse-key");
    symmetric_key_.set_secret_key_bits(service_symmetric_key_, 8 * num_key_bytes);
    cc_sealing_key_initialized_= true;

    // make app service private and public key
    if (public_key_alg == "rsa-2048") {
      if (!make_certifier_rsa_key(2048,  &private_service_key_)) {
        printf("cold_init: Can't generate App private key\n");
        return false;
      }
    } else if (public_key_alg == "rsa-4096") {
      if (!make_certifier_rsa_key(4096,  &private_service_key_)) {
        printf("cold_init: Can't generate App private key\n");
        return false;
      }
    } else if (public_key_alg == "ecc-384") {
      if (!make_certifier_ecc_key(384,  &private_service_key_)) {
        printf("cold_init: Can't generate App private key\n");
        return false;
      }
    } else {
        printf("cold_init: Unsupported public key algorithm\n");
        return false;
    }

    private_service_key_.set_key_name("service-attest-key");
    if (!private_key_to_public_key(private_service_key_, &public_service_key_)) {
      printf("cold_init: Can't make public service key\n");
      return false;
    }

    string service_tag("service-attest-key");
    if (!store_.add_authentication_key(service_tag, private_service_key_)) {
      printf("cold_init: Can't store auth key\n");
      return false;
    }

    cc_sealing_key_initialized_= true;
    cc_service_key_initialized_= true;

  } else {
    printf("cold_init: invalid cold_init purpose\n");
    return false;
  }

  if (!put_trust_data_in_store()) {
    printf("cold_init: Can't put trust data in store\n");
    return false;
  }

  if (!save_store()) {
    printf("cold_init: Can't save store\n");
    return false;
  }
  cc_policy_store_initialized_ = true;
  return true;
}

bool certifier::framework::cc_trust_data::warm_restart() {

  // fetch store
  if (!cc_policy_store_initialized_) {
    if (!fetch_store()) {
      printf("certifier::framework::cc_trust_data::warm_restart: Can't fetch store\n");
      return false;
    }
  }
  cc_policy_store_initialized_ = true;

  if (!get_trust_data_from_store()) {
    printf("certifier::framework::cc_trust_data::warm_restart: Can't get trust data from store\n");
    return false;
  }
  return true;
}

bool certifier::framework::cc_trust_data::GetPlatformSaysAttestClaim(signed_claim_message* scm) {
  if (enclave_type_ == "simulated-enclave") {
     return simulated_GetAttestClaim(scm);
  }
  if (enclave_type_ == "application-enclave") {
    int size_out = 8192;
    byte out[size_out];
    if (!application_GetPlatformStatement(&size_out, out)) {
      printf("certifier::framework::cc_trust_data::GetPlatformSaysAttestClaim: Can't get PlatformStatement from parent\n");
      return false;
    }
    string sc_str;
    sc_str.assign((char*)out, size_out);
    if (!scm->ParseFromString(sc_str)) {
      printf("certifier::framework::cc_trust_data::GetPlatformSaysAttestClaim: Can't parse platform claim\n");
      return false;
    }
    return true;
  }
  return false;
}

bool certifier::framework::cc_trust_data::recertify_me(const string& host_name, int port, bool generate_new_key) {

  if (generate_new_key) {

    if (purpose_ == "authentication") {

    // make app auth private and public key
      if (public_key_algorithm_ == "rsa-2048") {
        if (!make_certifier_rsa_key(2048,  &private_auth_key_)) {
          printf("recertify_me: Can't generate App private key\n");
          return false;
        }
      } else if (public_key_algorithm_ == "rsa-4096") {
        if (!make_certifier_rsa_key(4096,  &private_auth_key_)) {
          printf("recertify_me: Can't generate App private key\n");
          return false;
        }
      } else if (public_key_algorithm_ == "ecc-384") {
        if (!make_certifier_ecc_key(384,  &private_auth_key_)) {
          printf("recertify_me: Can't generate App private key\n");
          return false;
        }
      } else {
          printf("recertify_me: Unsupported public key algorithm\n");
          return false;
      }

      private_auth_key_.set_key_name("auth-key");
      if (!private_key_to_public_key(private_auth_key_, &public_auth_key_)) {
        printf("recertify_me: Can't make public Auth key\n");
        return false;
      }

      cc_auth_key_initialized_ = true;

    } else if (purpose_ == "attestation") {

      // make app service private and public key
      if (public_key_algorithm_ == "rsa-2048") {
        if (!make_certifier_rsa_key(2048,  &private_service_key_)) {
          printf("recertify_me: Can't generate App private key\n");
          return false;
        }
      } else if (public_key_algorithm_ == "rsa-4096") {
        if (!make_certifier_rsa_key(4096,  &private_service_key_)) {
          printf("recertify_me: Can't generate App private key\n");
          return false;
        }
      } else if (public_key_algorithm_ == "ecc-384") {
        if (!make_certifier_ecc_key(384,  &private_service_key_)) {
          printf("recertify_me: Can't generate App private key\n");
          return false;
        }
      } else {
          printf("recertify_me: Unsupported public key algorithm\n");
          return false;
      }

      private_service_key_.set_key_name("service-attest-key");
      if (!private_key_to_public_key(private_service_key_, &public_service_key_)) {
        printf("recertify_me: Can't make public service key\n");
        return false;
      }

      string service_tag("service-attest-key");
      if (!store_.add_authentication_key(service_tag, private_service_key_)) {
        printf("recertify_me: Can't store auth key\n");
        return false;
      }

      cc_service_key_initialized_= true;

    } else {
      printf("recertify_me: invalid recertify_me purpose\n");
      return false;
    }
  }

  if (!certify_me(host_name, port)) {
      printf("recertify_me: certify_me failed\n");
      return false;
  }

  if (!put_trust_data_in_store()) {
    printf("recertify_me: Can't put trust data in store\n");
    return false;
  }

  if (!save_store()) {
    printf("recertify_me: Can't save store\n");
    return false;
  }
  cc_policy_store_initialized_ = true;
  return true;
}

bool certifier::framework::cc_trust_data::certify_me(const string& host_name, int port) {

  if (!cc_all_initialized()) {
    if (!warm_restart()) {
      printf("warm restart failed\n");
      return false;
    }
  }

  evidence_list platform_evidence;
  if (enclave_type_ == "simulated-enclave" || enclave_type_ == "application-enclave") {
    signed_claim_message signed_platform_says_attest_key_is_trusted;
    if (!GetPlatformSaysAttestClaim(&signed_platform_says_attest_key_is_trusted)) {
      printf("certifier::framework::cc_trust_data::certify_me: Can't get signed attest claim\n");
      return false;
    }
    string str_s;
    if (!signed_platform_says_attest_key_is_trusted.SerializeToString(&str_s)) {
      printf("certifier::framework::cc_trust_data::certify_me: Can't serialize signed attest claim\n");
      return false;
    }
    evidence* ev = platform_evidence.add_assertion();
    if (ev ==nullptr) {
      printf("certifier::framework::cc_trust_data::certify_me: Can't add to platform evidence\n");
      return false;
    }
    ev->set_evidence_type("signed-claim");
    ev->set_serialized_evidence(str_s);
#ifdef GRAMINE_CERTIFIER
  } else if (enclave_type_ == "gramine-enclave") {
    if (!gramine_platform_cert_initialized) {
      printf("certifier::framework::cc_trust_data::certify_me: gramine certs not initialized\n");
      return false;
    }
    evidence* ev = platform_evidence.add_assertion();
    if (ev ==nullptr) {
      printf("certifier::framework::cc_trust_data::certify_me: Can't add to gramine platform evidence\n");
      return false;
    }
    ev->set_evidence_type("cert");
    ev->set_serialized_evidence(gramine_platform_cert);
    // May add more certs later
#endif
#ifdef SEV_SNP
  } else if (enclave_type_ == "sev-enclave") {
    if (!plat_certs_initialized) {
      printf("certifier::framework::cc_trust_data::certify_me: sev certs not initialized\n");
      return false;
    }
    evidence* ev = platform_evidence.add_assertion();
    if (ev ==nullptr) {
      printf("certifier::framework::cc_trust_data::certify_me: Can't add to platform evidence\n");
      return false;
    }
    ev->set_evidence_type("cert");
    ev->set_serialized_evidence(serialized_ark_cert);
    ev = platform_evidence.add_assertion();
    if (ev ==nullptr) {
      printf("certifier::framework::cc_trust_data::certify_me: Can't add to platform evidence\n");
      return false;
    }
    ev->set_evidence_type("cert");
    ev->set_serialized_evidence(serialized_ask_cert);
    ev = platform_evidence.add_assertion();
    if (ev ==nullptr) {
      printf("certifier::framework::cc_trust_data::certify_me: Can't add to platform evidence\n");
      return false;
    }
    ev->set_evidence_type("cert");
    ev->set_serialized_evidence(serialized_vcek_cert);
#endif
#ifdef OE_CERTIFIER
  } else if (enclave_type_ == "oe-enclave") {
    if (!cc_provider_provisioned_) {
      printf("certifier::framework::cc_trust_data::certify_me: Can't get pem-chain\n");
      return false;
    }
    if (pem_cert_chain != "") {
      evidence* ev = platform_evidence.add_assertion();
      if (ev ==nullptr) {
        printf("certifier::framework::cc_trust_data::certify_me: Can't add to platform evidence\n");
        return false;
      }
      ev->set_evidence_type("pem-cert-chain");
      ev->set_serialized_evidence(pem_cert_chain);
    }
#endif
  } else {
    printf("certifier::framework::cc_trust_data::certify_me: Unknown enclave type\n");
    return false;
  }

  attestation_user_data ud;
  if (purpose_ == "authentication") {
#ifdef DEBUG
    printf("\n---In certify me\n");
    printf("Filling ud with public auth key:\n");
    print_key(public_auth_key_);
    printf("\n");
#endif

    if (!make_attestation_user_data(enclave_type_,
          public_auth_key_, &ud)) {
      printf("certifier::framework::cc_trust_data::certify_me: Can't make user data (1)\n");
      return false;
    }
#ifdef DEBUG
    printf("\n---In certify me\n");
    printf("key in attestation user data:\n");
    print_key(ud.enclave_key());
    printf("\nprivate auth key:\n");
    print_key(private_auth_key_);
    printf("\npublic auth key:\n");
    print_key(public_auth_key_);
    printf("\n");
    printf("User data:\n");
    print_user_data(ud);
    printf("\n");
#endif
  } else if (purpose_ == "attestation") {
    if (!make_attestation_user_data(enclave_type_,
          public_service_key_, &ud)) {
      printf("certifier::framework::cc_trust_data::certify_me: Can't make user data (1)\n");
      return false;
    }
#ifdef DEBUG
    printf("\n---In certify me\n");
    printf("private service key:\n");
    print_key(private_service_key_);
    printf("\npublic service key:\n");
    print_key(public_service_key_);
    printf("\n");
#endif
  } else {
    printf("certifier::framework::cc_trust_data::certify_me: neither attestation or authorization\n");
    return false;
  }
  string serialized_ud;
  if (!ud.SerializeToString(&serialized_ud)) {
    printf("certifier::framework::cc_trust_data::certify_me: Can't serialize user data\n");
    return false;
  }

  int size_out = 16000;
  byte out[size_out];
  if (!Attest(enclave_type_, serialized_ud.size(),
        (byte*) serialized_ud.data(), &size_out, out)) {
    printf("certifier::framework::cc_trust_data::certify_me: Attest failed\n");
    return false;
  }
  string the_attestation_str;
  the_attestation_str.assign((char*)out, size_out);

  // Get certified
  trust_request_message request;
  trust_response_message response;

  // Should trust_request_message should be signed by auth key
  //   to prevent MITM attacks?  Probably not.
  request.set_requesting_enclave_tag("requesting-enclave");
  request.set_providing_enclave_tag("providing-enclave");
  if (enclave_type_ == "application-enclave" || enclave_type_ == "simulated-enclave") {
    request.set_submitted_evidence_type("vse-attestation-package");
  } else if (enclave_type_ == "sev-enclave") {
    request.set_submitted_evidence_type("sev-platform-package");
  } else if (enclave_type_ == "gramine-enclave") {
    request.set_submitted_evidence_type("gramine-evidence");
  } else if (enclave_type_ == "oe-enclave") {
    request.set_submitted_evidence_type("oe-evidence");
  } else {
    request.set_submitted_evidence_type("vse-attestation-package");
  }
  request.set_purpose(purpose_);

  // Construct the evidence package
  // Put initialized platform evidence and attestation in the following order:
  //  platform_says_attest_key_is_trusted, the_attestation
  evidence_package* ep = new(evidence_package);
  if (!construct_platform_evidence_package(enclave_type_, purpose_, platform_evidence,
        the_attestation_str, ep))  {
    printf("certifier::framework::cc_trust_data::certify_me: construct_platform_evidence_package failed\n");
    return false;
  }
  request.set_allocated_support(ep);

  // Serialize request
  string serialized_request;
  if (!request.SerializeToString(&serialized_request)) {
    printf("certifier::framework::cc_trust_data::certify_me: Can't serialize request\n");
    return false;
  }

#ifdef DEBUG
  printf("\nRequest:\n");
  print_trust_request_message(request);
#endif

  // Open socket and send request.
  int sock = -1;
  if (!open_client_socket(host_name, port, &sock)) {
    printf("certifier::framework::cc_trust_data::certify_me: Can't open request socket\n");
    return false;
  }

  if (sized_socket_write(sock, serialized_request.size(), (byte*)serialized_request.data()) <
        (int)serialized_request.size()) {
    return false;
  }

  // Read response from Certifier Service.
  string serialized_response;
  int resp_size = sized_socket_read(sock, &serialized_response);
  if (resp_size < 0) {
     printf("certifier::framework::cc_trust_data::certify_me: Can't read response\n");
    return false;
  }
  if (!response.ParseFromString(serialized_response)) {
    printf("certifier::framework::cc_trust_data::certify_me: Can't parse response\n");
    return false;
  }
  close(sock);

#ifdef DEBUG
  printf("\nResponse:\n");
  print_trust_response_message(response);
#endif

  if (response.status() != "succeeded") {
    printf("certifier::framework::cc_trust_data::certify_me: Certification failed\n");
    return false;
  }

  // Store the admissions certificate cert or platform rule
  if (purpose_ == "authentication") {
    public_auth_key_.set_certificate(response.artifact());
    private_auth_key_.set_certificate(response.artifact());

#ifdef DEBUG
    printf("\nAfter cert assigned\n");
    printf("private key:\n");
    print_key(private_auth_key_);
    printf("\n");
    X509* art_cert = X509_new();
    if (asn1_to_x509(private_auth_key_.certificate(), art_cert)) {
      printf("Cert:\n");
      X509_print_fp(stdout, art_cert);
    }
    X509_free(art_cert);
#endif

    // Update store with cert and save it
    string auth_tag("auth-key");
    const key_message* km = store_.get_authentication_key_by_tag(auth_tag);
    if (km == nullptr) {
      printf("certifier::framework::cc_trust_data::certify_me: Can't find authentication key in store\n");
      return false;
    }
    ((key_message*) km)->set_certificate(response.artifact());
    cc_auth_key_initialized_ = true;
    cc_is_certified_ = true;

  } else if (purpose_ == "attestation") {

    // Update store and save it
    string key_tag("service-attest-key");
    const key_message* km = store_.get_authentication_key_by_tag(key_tag);
    if (km == nullptr) {
      if (!store_.add_authentication_key(key_tag, private_service_key_)) {
        printf("certifier::framework::cc_trust_data::certify_me: Can't find service key in store\n");
        return false;
      }
    }

    // Set platform_rule
    string pr_str;
    pr_str.assign((char*)response.artifact().data(),response.artifact().size());
    if (!platform_rule_.ParseFromString(pr_str)) {
      printf("certifier::framework::cc_trust_data::certify_me: Can't parse platform rule\n");
      return false;
    }

    // Update store with platform_rule and save it
    string platform_rule_tag("platform-rule");
    if (!store_.add_signed_claim(platform_rule_tag, platform_rule_)) {
      printf("certifier::framework::cc_trust_data::certify_me: Can't add platform rule\n");
    }
    cc_service_platform_rule_initialized_ = true;
    cc_is_certified_ = true;

  } else {
    printf("certifier::framework::cc_trust_data::certify_me: Unknown purpose\n");
    return false;
  }

  if (!put_trust_data_in_store()) {
    printf("certify_me: Can't put trust data in store\n");
    return false;
  }
  return save_store();
}

bool certifier::framework::cc_trust_data::init_peer_certification_data(const string& public_key_alg) {
  // bool peer_data_initialized_;
  // key_message local_policy_key_;
  // string local_policy_cert_;
  return false;
}

bool certifier::framework::cc_trust_data::recover_peer_certification_data() {
  return false;
}

bool certifier::framework::cc_trust_data::get_peer_certification(const string& host_name, int port) {
  return false;
}

bool certifier::framework::cc_trust_data::run_peer_certificationservice(const string& host_name, int port) {
  return false;
}

// --------------------------------------------------------------------------------------
// helpers for proofs

bool construct_platform_evidence_package(string& attesting_enclave_type, const string& purpose,
      evidence_list& platform_assertions, string& serialized_attestation,
      evidence_package* ep) {

  string pt("vse-verifier");
  string et("signed-claim");
  ep->set_prover_type(pt);

#ifdef DEBUG
  printf("construct_platform_evidence_package %d existing assertions\n",
      platform_assertions.assertion_size());
  for (int i = 0; i < platform_assertions.assertion_size(); i++) {
    print_evidence(platform_assertions.assertion(i));
    printf("\n");
  }
#endif
  for (int i = 0; i < platform_assertions.assertion_size(); i++) {
    const evidence& ev_from = platform_assertions.assertion(i);
    evidence* ev_to = ep->add_fact_assertion();
    ev_to->CopyFrom(ev_from);
  }

  // add attestation
  evidence* ev2 = ep->add_fact_assertion();
  if ("simulated-enclave" ==  attesting_enclave_type ||
      "application-enclave" == attesting_enclave_type) {
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
  } else if ("sev-enclave" ==  attesting_enclave_type) {
    string et2("sev-attestation");
    ev2->set_evidence_type(et2);
  } else {
    return false;
  }

  ev2->set_serialized_evidence(serialized_attestation);
  return true;
}

// Todo: This isn't used
bool add_policy_key_says_platform_key_is_trusted(signed_claim_message& platform_key_is_trusted,
      evidence_package* ep) {

  string et("signed-claim");

  evidence* ev = ep->add_fact_assertion();
  ev->set_evidence_type(et);
  signed_claim_message sc;
  sc.CopyFrom(platform_key_is_trusted);
  string serialized_sc;
  if (!sc.SerializeToString(&serialized_sc))
    return false;
  ev->set_serialized_evidence((byte*)serialized_sc.data(), serialized_sc.size());
  return true;
}

// ----------------------------------------------------------------------------------------------
// Socket and SSL support

void print_cn_name(X509_NAME* name) {
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

void print_org_name(X509_NAME* name) {
  int len = X509_NAME_get_text_by_NID(name, NID_organizationName, nullptr, 0);
  if (len <= 0)
    return;
  len++;

  char name_buf[len];
  if (X509_NAME_get_text_by_NID(name, NID_organizationName, name_buf, len) > 0) {
    printf(" %s", name_buf);
  }
  printf("\n");
}

/* Declare an array of SSL Error codes mapped to an error description */
optlookup Ssl_errors[] =
  {
      DCL_OPTLOOKUP(SSL_ERROR_NONE                 , "No ssl error")
    , DCL_OPTLOOKUP(SSL_ERROR_WANT_READ            , "want read error")
    , DCL_OPTLOOKUP(SSL_ERROR_WANT_WRITE           , "want write error")
#ifndef BORING_SSL
    , DCL_OPTLOOKUP(SSL_ERROR_WANT_CONNECT         , "want connect error")
    , DCL_OPTLOOKUP(SSL_ERROR_WANT_ASYNC           , "want async error")
    , DCL_OPTLOOKUP(SSL_ERROR_WANT_CLIENT_HELLO_CB , "want client hello error")
#endif   // BORING_SSL
    , DCL_OPTLOOKUP(SSL_ERROR_WANT_ACCEPT          , "want accept error")
    , DCL_OPTLOOKUP(SSL_ERROR_WANT_X509_LOOKUP     , "want X509 lookup error")
    , DCL_OPTLOOKUP(SSL_ERROR_SSL                  , "generic ssl error")
    , DCL_OPTLOOKUP(SSL_ERROR_SYSCALL              , "syscall error")
    , DCL_OPTLOOKUP(SSL_ERROR_ZERO_RETURN          , "zero return error")
    , DCL_OPTLOOKUP_TERM()
  };

// Method to convert SSL error-code to human-readable string, a la' strerror()
static inline const char * ssl_strerror(int code) {
  const char *msg = optbyid(Ssl_errors, code);
  return(msg ? msg : "Unknown ssl error, " CC_TO_STR(code));
}

void print_ssl_error(int code) {
  printf("%s\n", ssl_strerror(code));
}

// Socket and SSL support

bool open_client_socket(const string& host_name, int port, int* soc) {
  struct addrinfo hints;
  struct addrinfo *result, *rp;
  int sfd, s;

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
    sfd = socket(rp->ai_family, rp->ai_socktype,
                 rp->ai_protocol);
    if (sfd == -1)
      continue;

    if (connect(sfd, rp->ai_addr, rp->ai_addrlen) != -1)
      break;

    close(sfd);
  }

  if (rp == NULL) {
    fprintf(stderr, "Could not connect\n");
    return false;
  }

  freeaddrinfo(result);

  *soc = sfd;
  return true;
}

bool open_server_socket(const string& host_name, int port, int* soc) {
  struct addrinfo hints;
  struct addrinfo *result, *rp;
  int sfd, s;

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
    sfd = socket(rp->ai_family, rp->ai_socktype,
                 rp->ai_protocol);
    if (sfd == -1)
      continue;

    if (bind(sfd, rp->ai_addr, rp->ai_addrlen) == 0)
      break;

    close(sfd);
  }

  if (rp == NULL) {
    fprintf(stderr, "%s: Could not bind to %s:%d\n",
            __func__, host_name.c_str(), port);
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
int verify_callback(int preverify, X509_STORE_CTX* x509_ctx) {
  int depth = X509_STORE_CTX_get_error_depth(x509_ctx);
  int err = X509_STORE_CTX_get_error(x509_ctx);

  X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
  X509_NAME* iname = cert ? X509_get_issuer_name(cert) : NULL;
  X509_NAME* sname = cert ? X509_get_subject_name(cert) : NULL;

  printf("Depth %d, Preverify: %d\n", depth, preverify);
  printf("Issuer CN : ");
  print_cn_name(iname);
  printf("Subject CN: ");
  print_cn_name(sname);

  if(depth == 0) {
    /* If depth is 0, its the server's certificate. Print the SANs too */
    printf("Subject ORG: ");
    print_org_name(sname);
  }

  return preverify;
}

// ----------------------------------------------------------------------------------

bool extract_id_from_cert(X509* in, string* out) {
  if (in == nullptr)
    return false;
  X509_NAME* sname = X509_get_subject_name(in);
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
  out->assign((char*)name_buf, strlen(name_buf)+1);
  return true;
}

// Loads server side certs and keys.
bool load_server_certs_and_key(X509* root_cert,
      key_message& private_key, SSL_CTX* ctx) {
  // load auth key, policy_cert and certificate chain
  // Todo: Add other key types
  RSA* r = RSA_new();
  if (!key_to_RSA(private_key, r)) {
    printf("load_server_certs_and_key: key_to_RSA failed\n");
    return false;
  }
  EVP_PKEY* auth_private_key = EVP_PKEY_new();
  EVP_PKEY_set1_RSA(auth_private_key, r);

  X509* x509_auth_key_cert= X509_new();
  string auth_cert_str;
  auth_cert_str.assign((char*)private_key.certificate().data(),
        private_key.certificate().size());
  if (!asn1_to_x509(auth_cert_str, x509_auth_key_cert)) {
      printf("load_server_certs_and_key: asn1_to_x509 failed\n");
      return false;
  }

  STACK_OF(X509)* stack = sk_X509_new_null();
  if (sk_X509_push(stack, root_cert) == 0) {
    printf("load_server_certs_and_key: sk_X509_push failed\n");
    return false;
  }

#ifdef BORING_SSL
  if (!SSL_CTX_use_certificate(ctx, x509_auth_key_cert)) {
      printf("load_server_certs_and_key: use cert failed\n");
      return false;
  }
  if (!SSL_CTX_use_PrivateKey(ctx, auth_private_key)) {
      printf("load_server_certs_and_key: use priv key failed\n");
      return false;
  }

  if (!SSL_CTX_set1_chain(ctx, stack)) {
    printf("load_server_certs_and_key: set1 chain error\n");
    return false;
  }
#else
  if (SSL_CTX_use_cert_and_key(ctx, x509_auth_key_cert, auth_private_key, stack, 1) <= 0 ) {
      printf("load_server_certs_and_key: SSL_CTX_use_cert_and_key failed\n");
#ifdef DEBUG
      printf("cert:\n");
      X509_print_fp(stdout, x509_auth_key_cert);
      printf("key:\n");
      print_key(private_key);
      printf("\n");
#endif
      return false;
  }
#endif

  if (!SSL_CTX_check_private_key(ctx)) {
      printf("load_server_certs_and_key: SSL_CTX_check_private_key failed\n");
      return false;
  }
  SSL_CTX_add_client_CA(ctx, root_cert);

#ifdef BORING_SSL
  SSL_CTX_add1_chain_cert(ctx, root_cert);
#else
  SSL_CTX_add1_to_CA_list(ctx, root_cert);

#ifdef DEBUG
  const STACK_OF(X509_NAME)* ca_list= SSL_CTX_get0_CA_list(ctx);
  printf("CA names to offer\n");
  if (ca_list != nullptr) {
    for (int i = 0; i < sk_X509_NAME_num(ca_list); i++) {
      X509_NAME* name = sk_X509_NAME_value(ca_list, i);
      print_cn_name(name);
    }
  }
#endif
#endif // BORING_SSL

  return true;
}

bool certifier::framework::server_dispatch(const string& host_name, int port,
      string& asn1_root_cert, key_message& private_key,
      const string& private_key_cert, void (*func)(secure_authenticated_channel&)) {

  OPENSSL_init_ssl(0, NULL);
  SSL_load_error_strings();

  X509* root_cert = X509_new();
  if (!asn1_to_x509(asn1_root_cert, root_cert)) {
    printf("server_dispatch: Can't convert cert\n");
    return false;
  }

  // Get a socket.
  int sock = -1;
  if (!open_server_socket(host_name, port, &sock)) {
    printf("%s: Can't open server socket to %s:%d\n",
            __func__, host_name.c_str(), port);
    return false;
  }

  // Set up TLS handshake data.
  SSL_METHOD* method = (SSL_METHOD*) TLS_server_method();
  SSL_CTX* ctx = SSL_CTX_new(method);
  if (ctx == NULL) {
    printf("server_dispatch: SSL_CTX_new failed (1)\n");
    return false;
  }
  X509_STORE* cs = SSL_CTX_get_cert_store(ctx);
  X509_STORE_add_cert(cs, root_cert);

#if 1
  X509* x509_auth_cert = X509_new();
  if (asn1_to_x509(private_key_cert, x509_auth_cert)) {
    X509_STORE_add_cert(cs, x509_auth_cert);
  }
#endif

  if (!load_server_certs_and_key(root_cert, private_key, ctx)) {
    printf("server_dispatch: SSL_CTX_new failed (2)\n");
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
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
  // For debug: SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
  //SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);

  while (1) {
#ifdef DEBUG
    printf("at accept\n");
#endif
    struct sockaddr_in addr;
    unsigned int len = sizeof(sockaddr_in);
    int client = accept(sock, (struct sockaddr*)&addr, &len);
    string my_role("server");
    secure_authenticated_channel nc(my_role);
    if (!nc.init_server_ssl(host_name, port, asn1_root_cert, private_key, private_key_cert)) {
      continue;
    }
    nc.ssl_ = SSL_new(ctx);
    SSL_set_fd(nc.ssl_, client);
    nc.sock_ = client;
    nc.server_channel_accept_and_auth(func);
  }
  return true;
}

certifier::framework::secure_authenticated_channel::secure_authenticated_channel(string& role) {
  role_ = role;
  channel_initialized_ = false;
  ssl_ctx_= nullptr;
  store_ctx_= nullptr;
  ssl_= nullptr;
  sock_ = -1;
  my_cert_= nullptr;
  peer_cert_= nullptr;
  peer_id_.clear();
}

certifier::framework::secure_authenticated_channel::~secure_authenticated_channel() {
  role_.clear();
  channel_initialized_ = false;
  // delete?
  if (ssl_ctx_ != nullptr)
    SSL_CTX_free(ssl_ctx_); 
  ssl_ctx_= nullptr;
  if (store_ctx_ != nullptr)
    X509_STORE_CTX_free(store_ctx_);
  store_ctx_= nullptr;
  // delete?
  ssl_= nullptr;
  if (sock_ > 0)
    ::close(sock_);
  sock_ = -1;
  // delete?
  my_cert_= nullptr;
  // delete?
  if (peer_cert_ != nullptr)
    X509_free(peer_cert_);
  peer_cert_= nullptr;
  peer_id_.clear();
}

bool certifier::framework::secure_authenticated_channel::init_client_ssl(const string& host_name, int port,
        string& asn1_root_cert, key_message& private_key, const string& auth_cert) {

  OPENSSL_init_ssl(0, NULL);
  SSL_load_error_strings();

  private_key_.CopyFrom(private_key);
  asn1_root_cert_.assign((char*)asn1_root_cert.data(), asn1_root_cert.size());
  root_cert_ = X509_new();
  if (!asn1_to_x509(asn1_root_cert, root_cert_)) {
    printf("init_client_ssl: root cert invalid\n");
    return false;
  }

  const SSL_METHOD* method = TLS_client_method();
  if(method == nullptr) {
    printf("init_client_ssl: Can't get method\n");
    return false;
  }

  ssl_ctx_ = SSL_CTX_new(method);
  if(ssl_ctx_ == nullptr) {
    printf("init_client_ssl: Can't get SSL_CTX\n");
    return false;
  }

  X509_STORE* cs = SSL_CTX_get_cert_store(ssl_ctx_);
  X509_STORE_add_cert(cs, root_cert_);

#if 1
  X509* x509_auth_cert = X509_new();
  if (asn1_to_x509(auth_cert, x509_auth_cert)) {
    X509_STORE_add_cert(cs, x509_auth_cert);
  }
#endif

  // For debugging: SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
  SSL_CTX_set_verify(ssl_ctx_, SSL_VERIFY_PEER, nullptr);

  SSL_CTX_set_verify_depth(ssl_ctx_, 4);
  const long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
  SSL_CTX_set_options(ssl_ctx_, flags);

  if (!load_client_certs_and_key()) {
    printf("init_client_ssl: load_client_certs_and_key failed\n");
    return false;
  }

  if (!open_client_socket(host_name, port, &sock_)) {
    printf("init_client_ssl: Can't open client socket\n");
    return false;
  }

  ssl_ = SSL_new(ssl_ctx_);
  SSL_set_fd(ssl_, sock_);
  int res = SSL_set_cipher_list(ssl_, "TLS_AES_256_GCM_SHA384");  // Change?

  // SSL_connect - initiate the TLS/SSL handshake with an TLS/SSL server
  int ret = SSL_connect(ssl_);
  if (ret <= 0) {
    int err = SSL_get_error(ssl_, ret);
    printf("init_client_ssl: ssl_connect failed, ret=%d, err=%d: %s\n",
           ret, err, ssl_strerror(err));
    return false;
  }

  // Verify a server certificate was presented during the negotiation
  peer_cert_ = SSL_get_peer_certificate(ssl_);
  if (peer_cert_ != nullptr) {
    peer_id_.clear();
    if (!extract_id_from_cert(peer_cert_, &peer_id_)) {
      printf("init_client_ssl: Can't extract id\n");
    }
  }

#ifdef DEBUG
  if(peer_cert_) {
    printf("Client: Peer cert presented in nego\n");
  } else {
    printf("Client: No peer cert presented in nego\n");
  }
#endif
  channel_initialized_ = true;
  return true;
}

// Loads client side certs and keys.  Note: key for private_key is in
//    the key.
bool certifier::framework::secure_authenticated_channel::load_client_certs_and_key() {
  // Todo: Add other key types
  RSA* r = RSA_new();
  if (!key_to_RSA(private_key_, r)) {
    printf("load_client_certs_and_key: Can't convert to RSA key\n");
    return false;
  }
  EVP_PKEY* auth_private_key = EVP_PKEY_new();
  EVP_PKEY_set1_RSA(auth_private_key, r);

  X509* x509_auth_key_cert= X509_new();
  string auth_cert_str;
  auth_cert_str.assign((char*)private_key_.certificate().data(), private_key_.certificate().size());
  if (!asn1_to_x509(auth_cert_str, x509_auth_key_cert)) {
    printf("load_client_certs_and_key: can't translate der to X509\n");
    return false;
  }

  STACK_OF(X509)* stack = sk_X509_new_null();
#if 0
  if (sk_X509_push(stack, root_cert_) == 0) {
    printf("load_client_certs_and_key, error 3\n");
    return false;
  }
#endif

  if (!SSL_CTX_use_certificate(ssl_ctx_, x509_auth_key_cert)) {
      printf("load_client_certs_and_key: use cert failed\n");
      return false;
  }
  if (!SSL_CTX_use_PrivateKey(ssl_ctx_, auth_private_key)) {
      printf("load_client_certs_and_key: use priv key failed\n");
      return false;
  }

  if (!SSL_CTX_check_private_key(ssl_ctx_) ) {
    printf("load_client_certs_and_key: private key check failed\n");
    return false;
  }

#ifdef BORING_SSL
  SSL_CTX_add1_chain_cert(ssl_ctx_, root_cert_);
#else
  if (SSL_CTX_use_cert_and_key(ssl_ctx_, x509_auth_key_cert, auth_private_key, stack, 1) <= 0 ) {
    printf("load_client_certs_and_key: use_cert_and_key failed\n");
    return false;
  }

  SSL_CTX_add1_to_CA_list(ssl_ctx_, root_cert_);
  
#ifdef DEBUG
  const STACK_OF(X509_NAME)* ca_list= SSL_CTX_get0_CA_list(ssl_ctx_);
  printf("CA names to offer\n");
  if (ca_list != nullptr) {
    for (int i = 0; i < sk_X509_NAME_num(ca_list); i++) {
      X509_NAME* name = sk_X509_NAME_value(ca_list, i);
      print_cn_name(name);
    }
  }
#endif
#endif // BORING_SSL
  return true;
}

void certifier::framework::secure_authenticated_channel::server_channel_accept_and_auth(
      void (*func)(secure_authenticated_channel&)) {

  // accept and carry out auth
  int res = SSL_accept(ssl_);
  if (res != 1) {
    printf("server_channel_accept_and_auth: Can't SSL_accept connection"
           ", res=%d\n", res);
    unsigned long code = ERR_get_error();
    printf("Accept error: %s\n", ERR_lib_error_string(code));
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
      printf("server_channel_accept_and_auth: Can't extract id\n");
    }
  }

#ifdef DEBUG
    if(peer_cert_) {
      printf("server_channel_accept_and_auth: Peer cert presented in nego\n");
    } else {
      printf("server_channel_accept_and_auth: No peer cert presented in nego\n");
    }
#endif

  channel_initialized_ = true;
  func(*this);
  return;
}

bool certifier::framework::secure_authenticated_channel::init_server_ssl(const string& host_name,
      int port, string& asn1_root_cert, key_message& private_key, const string& auth_cert) {
  SSL_load_error_strings();

  // set keys and cert
  private_key_.CopyFrom(private_key);
  asn1_root_cert_.assign((char*)asn1_root_cert.data(), asn1_root_cert.size());
  root_cert_ = X509_new();
  if (!asn1_to_x509(asn1_root_cert, root_cert_)) {
    printf("init_server_ssl: Can't translate der to X509\n");
    return false;
  }
  return true;
}

int certifier::framework::secure_authenticated_channel::read(int size, byte* b) {
  return  SSL_read(ssl_, b, size);
}

int certifier::framework::secure_authenticated_channel::read(string* out) {
  return sized_ssl_read(ssl_, out);
}

int certifier::framework::secure_authenticated_channel::write(int size, byte* b) {
  return sized_ssl_write(ssl_, size, b);
}

void certifier::framework::secure_authenticated_channel::close() {
  ::close(sock_);
  if (ssl_ != nullptr) {
    SSL_free(ssl_);
    ssl_ = nullptr;
  }
}

bool certifier::framework::secure_authenticated_channel::get_peer_id(string* out) {
  out->assign((char*)peer_id_.data(), peer_id_.size());
  return true;
}
