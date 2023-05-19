//  Copyright (c) 2021-23, VMware Inc, and the Certifier Authors.  All rights reserved.
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

#ifndef _CERTIFIER_FRAMEWORK_H__
#define _CERTIFIER_FRAMEWORK_H__

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

// Policy store
// -------------------------------------------------------------------

namespace certifier {
  namespace framework {
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

    // Protect Support
    // -------------------------------------------------------------------

    bool Protect_Blob(const string& enclave_type,
      key_message& key, int size_unencrypted_data, byte* unencrypted_data,
      int* size_protected_blob, byte* blob);
    bool Unprotect_Blob(const string& enclave_type,
      int size_protected_blob, byte* protected_blob,
      key_message* key, int* size_of_unencrypted_data, byte* data);


    class cc_trust_data {
    private:
      static const int cc_helper_symmetric_key_size = 64;

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
      bool cc_is_certified_;

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

      // For peer-to-peer certification
      bool peer_data_initialized_;
      key_message local_policy_key_;
      string local_policy_cert_;

      cc_trust_data();
      cc_trust_data(const string& enclave_type, const string& purpose,
          const string& policy_store_name);
      ~cc_trust_data();

      // Each of the enclave types have bespoke initialization
      bool initialize_simulated_enclave_data(const string& attest_key_file_name,
          const string& measurement_file_name, const string& attest_endorsement_file_name);
      bool initialize_sev_enclave_data(const string& platform_ark_der_file,
          const string& platform_ask_der_file,
          const string& platform_vcek_der_file);
      bool initialize_gramine_enclave_data(const int size, byte* cert);
      bool initialize_oe_enclave_data(const string& file);
      bool initialize_application_enclave_data(const string& parent_enclave_type,
              int in_fd, int out_fd);

      bool cc_all_initialized();
      bool init_policy_key(int asn1_cert_size, byte* asn1_cert);
      bool put_trust_data_in_store();
      bool get_trust_data_from_store();
      bool save_store();
      bool fetch_store();
      void clear_sensitive_data();
      // This changes
      bool cold_init(const string& public_key_alg, const string& symmetric_key_alg,
                     const string& hash_alg, const string& hmac_alg);
      bool warm_restart();
      bool certify_me(const string& host_name, int port);
      bool GetPlatformSaysAttestClaim(signed_claim_message* scm);
      void print_trust_data();

      // For peer-to-peer certification
      bool init_peer_certification_data(const string& public_key_alg);
      bool recover_peer_certification_data();
      bool get_peer_certification(const string& host_name, int port);
      bool run_peer_certificationservice(const string& host_name, int port);
    };

    class secure_authenticated_channel {
    public:
      string role_;
      bool channel_initialized_;
      key_message private_key_;
      SSL_CTX* ssl_ctx_;
      X509_STORE_CTX* store_ctx_;
      SSL* ssl_;
      int sock_;
      string asn1_root_cert_;
      X509* root_cert_;
      X509* my_cert_;
      string asn1_my_cert_;
      X509* peer_cert_;
      string peer_id_;

      secure_authenticated_channel(string& role);  // role is client or server
      ~secure_authenticated_channel();

      bool load_client_certs_and_key();

      bool init_client_ssl(const string& host_name, int port, string& asn1_root_cert,
          key_message& private_key, const string& private_key_cert);
      bool init_server_ssl(const string& host_name, int port, string& asn1_root_cert,
          key_message& private_key, const string& private_key_cert);

      void server_channel_accept_and_auth(void (*func)(secure_authenticated_channel&));

      int read(string* out);
      int read(int size, byte* b);
      int write(int size, byte* b);
      void close();
      bool get_peer_id(string* out);
    };

    bool server_dispatch(const string& host_name, int port,
                         string& asn1_root_cert, key_message& private_key,
                         const string& private_key_cert, void (*)(secure_authenticated_channel&));
  }
}

#endif
