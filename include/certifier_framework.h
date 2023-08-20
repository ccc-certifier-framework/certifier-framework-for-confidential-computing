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

#ifndef _CERTIFIER_FRAMEWORK_H__
#define _CERTIFIER_FRAMEWORK_H__

#include <string>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

#include "certifier_algorithms.h"
#include "certifier.pb.h"

#ifndef byte
typedef unsigned char byte;
#endif

using std::string;

// Policy store
// -------------------------------------------------------------------

namespace certifier {
namespace framework {

// This will replace the old policy store
class store_entry {
 public:
  string tag_;
  string type_;
  string value_;

  store_entry();
  ~store_entry();

  void print();
};

// Standard types are: string, binary-blob, der-encoded-cert, and protobuf
// serialized
//   key, keys, and signed-claim protobufs. However the store imposes no
//   restrictions on what serialization is.
class policy_store {
 public:
  enum { MAX_NUM_ENTRIES = 500 };

  unsigned      max_num_ents_;
  unsigned      num_ents_;
  store_entry **entry_;

 public:
  policy_store(unsigned max_ents);
  policy_store();
  ~policy_store();

 private:
  bool add_entry(const string &tag, const string &type, const string &value);

 public:
  unsigned      get_num_entries();
  int           find_entry(const string &tag, const string &type);
  const string *tag(unsigned ent);
  const string *type(unsigned ent);
  store_entry * get_entry(unsigned ent);
  bool          delete_entry(unsigned ent);
  bool          get(unsigned ent, string *v);
  bool          put(unsigned ent, const string v);
  bool          update_or_insert(const string &tag,
                                 const string &type,
                                 const string &value);
  void          print();
  bool          Serialize(string *psout);
  bool          Deserialize(string &in);
};

// Trusted primitives
// -------------------------------------------------------------------

bool Seal(const string &enclave_type,
          const string &enclave_id,
          int           in_size,
          byte *        in,
          int *         size_out,
          byte *        out);

bool Unseal(const string &enclave_type,
            const string &enclave_id,
            int           in_size,
            byte *        in,
            int *         size_out,
            byte *        out);

bool Attest(const string &enclave_type,
            int           what_to_say_size,
            byte *        what_to_say,
            int *         size_out,
            byte *        out);

// Protect Support
// -------------------------------------------------------------------

bool protect_blob(const string &enclave_type,
                  key_message & key,
                  int           size_unencrypted_data,
                  byte *        unencrypted_data,
                  int *         size_protected_blob,
                  byte *        blob);
bool unprotect_blob(const string &enclave_type,
                    int           size_protected_blob,
                    byte *        protected_blob,
                    key_message * key,
                    int *         size_of_unencrypted_data,
                    byte *        data);
bool reprotect_blob(const string &enclave_type,
                    key_message * key,
                    int           size_protected_blob,
                    byte *        protected_blob,
                    int *         size_new_encrypted_blob,
                    byte *        data);


class domain_info {
 public:
  string domain_name_;
  string domain_policy_cert_;
  string host_;
  int    port_;
  string service_host_;
  int    service_port_;
};

class certifiers;

class cc_trust_data {

 private:
  void cc_trust_data_default_init();

 public:
  // Python swig bindings need this to be public, to size other array decls
  static const int max_symmetric_key_size_ = 128;

  bool cc_basic_data_initialized_;

  string purpose_;
  string enclave_type_;
  string store_file_name_;
  string public_key_algorithm_;
  string symmetric_key_algorithm_;

  // For primary security domain only
  bool        cc_policy_info_initialized_;
  string      serialized_policy_cert_;
  X509 *      x509_policy_cert_;
  key_message public_policy_key_;

  bool         cc_policy_store_initialized_;
  policy_store store_;

  // platform initialized?
  bool cc_provider_provisioned_;

  // primary domain certified?
  bool cc_is_certified_;

  bool   primary_admissions_cert_valid_;
  string serialized_primary_admissions_cert_;
  // Note: if purpose is attestation, serialized_home_admissions_cert_
  // is the same as the serialized_service_cert_, so remove it later

  // auth key is the same in all domains
  bool        cc_auth_key_initialized_;
  key_message private_auth_key_;
  key_message public_auth_key_;

  // For attest
  bool        cc_service_key_initialized_;
  key_message private_service_key_;
  key_message public_service_key_;

  bool   cc_service_cert_initialized_;
  string serialized_service_cert_;

  bool                 cc_service_platform_rule_initialized_;
  signed_claim_message platform_rule_;

  //  symmetric key is the same in any domain
  bool        cc_symmetric_key_initialized_;
  byte        symmetric_key_bytes_[max_symmetric_key_size_];
  key_message symmetric_key_;

  // This is the sealing key
  bool        cc_sealing_key_initialized_;
  byte        sealing_key_bytes_[max_symmetric_key_size_];
  key_message service_sealing_key_;

  // The domains I get certified in.
  // If purpose is attestation, there can only be one.
  int          max_num_certified_domains_;
  int          num_certified_domains_;
  certifiers **certified_domains_;

  // For peer-to-peer certification (not used now)
  bool        peer_data_initialized_;
  key_message local_policy_key_;
  string      local_policy_cert_;


  enum { MAX_NUM_CERTIFIERS = 32 };
  cc_trust_data();
  cc_trust_data(const string &enclave_type,
                const string &purpose,
                const string &policy_store_name);
  ~cc_trust_data();

  // Each of the enclave types have bespoke initialization
  bool initialize_simulated_enclave_data(
      const string &attest_key_file_name,
      const string &measurement_file_name,
      const string &attest_endorsement_file_name);
  bool initialize_sev_enclave_data(const string &platform_ark_der_file,
                                   const string &platform_ask_der_file,
                                   const string &platform_vcek_der_file);
  bool initialize_gramine_enclave_data(const int size, byte *cert);
  bool initialize_oe_enclave_data(const string &file);
  bool initialize_application_enclave_data(const string &parent_enclave_type,
                                           int           in_fd,
                                           int           out_fd);
  bool initialize_keystone_enclave_data(
      const string &attest_key_file_name,
      const string &measurement_file_name,
      const string &attest_endorsement_file_name);

  bool initialize_islet_enclave_data(
      const string &attest_key_file_name,
      const string &measurement_file_name,
      const string &attest_endorsement_file_name);

  bool cc_all_initialized();
  bool init_policy_key(byte *asn1_cert, int asn1_cert_size);
  bool put_trust_data_in_store();
  bool get_trust_data_from_store();
  bool save_store();
  bool fetch_store();
  void clear_sensitive_data();

  bool generate_symmetric_key(bool regen);
  bool generate_sealing_key(bool regen);
  bool generate_auth_key(bool regen);
  bool generate_service_key(bool regen);

  bool cold_init(const string &public_key_alg,
                 const string &symmetric_key_alg,
                 byte *        asn1_cert,
                 int           asn1_cert_size,
                 const string &home_domain_name,
                 const string &home_host,
                 int           home_port,
                 const string &service_host,
                 int           service_port);
  bool warm_restart();
  bool GetPlatformSaysAttestClaim(signed_claim_message *scm);
  void print_trust_data();

  bool certify_primary_domain();
  bool certify_me() { return certify_primary_domain(); };

  // For peer-to-peer certification (not used yet)
  bool init_peer_certification_data(const string &public_key_alg);
  bool recover_peer_certification_data();
  bool get_peer_certification(const string &host_name, int port);
  bool run_peer_certification_service(const string &host_name, int port);

  // multi-domain support
  bool add_or_update_new_domain(const string &domain_name,
                                const string &cert,
                                const string &host,
                                int           port,
                                const string &service_host,
                                int           service_port);
  bool certify_secondary_domain(const string &domain_name);
  bool get_certifiers_from_store();
  bool put_certifiers_in_store();
};

// Certification Anchors

class certifiers {
 private:
  // should be const, don't delete it
  cc_trust_data *owner_;

 public:
  string domain_name_;
  string domain_policy_cert_;
  string host_;
  int    port_;
  bool   is_certified_;
  string admissions_cert_;
  string service_host_;
  int    service_port_;

  certifiers(cc_trust_data *owner);
  ~certifiers();

  bool init_certifiers_data(const string &domain_name,
                            const string &cert,
                            const string &host,
                            int           port,
                            const string &service_host,
                            int           service_port);

  bool get_certified_status();
  bool certify_domain();
  void print_certifiers_entry();
};

class secure_authenticated_channel {
 public:
  string          role_;
  bool            channel_initialized_;
  key_message     private_key_;
  SSL_CTX *       ssl_ctx_;
  X509_STORE_CTX *store_ctx_;
  SSL *           ssl_;
  int             sock_;
  string          asn1_root_cert_;
  X509 *          root_cert_;
  X509 *          my_cert_;
  string          asn1_my_cert_;
  X509 *          peer_cert_;
  string          peer_id_;

  secure_authenticated_channel(string &role);  // role is client or server
  ~secure_authenticated_channel();

  bool load_client_certs_and_key();

  bool init_client_ssl(const string &host_name,
                       int           port,
                       string &      asn1_root_cert,
                       key_message & private_key,
                       const string &private_key_cert);
  bool init_server_ssl(const string &host_name,
                       int           port,
                       string &      asn1_root_cert,
                       key_message & private_key,
                       const string &private_key_cert);

  void server_channel_accept_and_auth(
      void (*func)(secure_authenticated_channel &));

  int  read(string *out);
  int  read(int size, byte *b);
  int  write(int size, byte *b);
  void close();
  bool get_peer_id(string *out_peer_id);
};

bool server_dispatch(const string &host_name,
                     int           port,
                     string &      asn1_root_cert,
                     key_message & private_key,
                     const string &private_key_cert,
                     void (*)(secure_authenticated_channel &));
}  // namespace framework
}  // namespace certifier

#endif
