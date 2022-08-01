#include "support.h"
#include "certifier.h"
#include "simulated_enclave.h"

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include  <netdb.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/err.h>

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

#ifndef _CC_HELPERS_CC_
#define _CC_HELPERS_CC_

const int cc_helper_symmetric_key_size = 64;

class cc_trust_data {
public:
  bool cc_basic_data_initialized_;
  string purpose_;
  string enclave_type_;
  string store_file_name_;

  bool cc_policy_info_initialized_;
  string serialized_policy_cert_;
  X509* x509_policy_cert_;
  key_message public_policy_key_;

  bool cc_policy_store_initialized_;
  policy_store store_;

  bool cc_provider_provisioned_;

  // For auth
  bool cc_auth_key_initialized_;
  key_message private_auth_key_;
  key_message public_auth_key_;

  bool cc_symmetric_key_initialized_;
  byte symmetric_key_bytes_[cc_helper_symmetric_key_size];
  key_message symmetric_key_;

  // For attest
  bool cc_service_key_initialized_;
  key_message private_service_key_;
  key_message public_service_key_;

  bool cc_service_cert_initialized_;
  string serialized_service_cert_;

  bool cc_service_platform_rule_initialized_;
  signed_claim_message platform_rule_;

  // This is the sealing key
  bool cc_sealing_key_initialized_;
  byte service_symmetric_key_[cc_helper_symmetric_key_size];
  key_message service_sealing_key_;

  cc_trust_data();
  cc_trust_data(const string& enclave_type, const string& purpose,
      const string& policy_store_name);
  ~cc_trust_data();

  bool cc_all_initialized();
  bool initialize_simulated_enclave_data(const string& attest_key_file_name,
      const string& measurement_file_name, const string& attest_endorsement_file_name);
  bool init_policy_key(int asn1_cert_size, byte* asn1_cert);
  bool put_trust_data_in_store();
  bool get_trust_data_from_store();
  bool save_store();
  bool fetch_store();
  void clear_sensitive_data();
  bool cold_init();
  bool warm_restart();
  bool certify_me(const string& host_name, int port);
  bool GetPlatformSaysAttestClaim(signed_claim_message* scm);
  void print_trust_data();
};

bool open_client_socket(const string& host_name, int port, int* soc);
bool open_server_socket(const string& host_name, int port, int* soc);

bool construct_platform_evidence_package(signed_claim_message& platform_attest_claim,
    signed_claim_message& the_attestation, evidence_package* ep);
bool construct_attestation(entity_message& attest_key_entity, entity_message& auth_key_entity,
        entity_message& measurement_entity, vse_clause* vse_attest_clause);
void print_cn_name(X509_NAME* name);
void print_org_name(X509_NAME* name);
void print_ssl_error(int code);

bool client_auth_server(X509* x509_policy_cert, SSL* ssl);
bool load_server_certs_and_key(X509* x509_policy_cert, key_message& private_key, SSL_CTX* ctx);
bool init_client_ssl(X509* x509_policy_cert, key_message& private_key,
    const string& host_name, int port,
    int* p_sd, SSL_CTX** p_ctx, SSL** p_ssl);
bool client_auth_client(key_message& private_key, SSL* ssl);
void close_client_ssl(int sd, SSL_CTX* ctx, SSL* ssl);
#endif

