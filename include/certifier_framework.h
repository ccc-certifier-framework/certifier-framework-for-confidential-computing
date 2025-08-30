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

// Note only one of NEW_API and OLD_API can be defined.
#ifndef NEW_API
#  define OLD_API 1
#endif

// -------------------------------------------------------------------

namespace certifier {
namespace framework {

// Policy store
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
  store_entry  *get_entry(unsigned ent);
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
          byte         *in,
          int          *size_out,
          byte         *out);

bool Unseal(const string &enclave_type,
            const string &enclave_id,
            int           in_size,
            byte         *in,
            int          *size_out,
            byte         *out);

bool Attest(const string &enclave_type,
            int           what_to_say_size,
            byte         *what_to_say,
            int          *size_out,
            byte         *out);

// Protect Support
// -------------------------------------------------------------------

bool protect_blob(const string &enclave_type,
                  key_message  &key,
                  int           size_unencrypted_data,
                  byte         *unencrypted_data,
                  int          *size_protected_blob,
                  byte         *blob);

bool unprotect_blob(const string &enclave_type,
                    int           size_protected_blob,
                    byte         *protected_blob,
                    key_message  *key,
                    int          *size_of_unencrypted_data,
                    byte         *data);

bool reprotect_blob(const string &enclave_type,
                    key_message  *key,
                    int           size_protected_blob,
                    byte         *protected_blob,
                    int          *size_new_encrypted_blob,
                    byte         *data);

// Note added 28 August 2025
// I'm changing the API exposed by trust manager a little.
// and tidying up a bit.  There are two defines, NEW_API
// and OLD_API which conditionally compile in the NEW
// and/or OLD API's.  For compatibility, both will be
// defined initially although I hope to remove OLD_API
// in the future.
//
//    a. Paul England pointed out that the simulated_enclave,
//       which is currently in $CERTIFIER/src should move to a
//       subdirectory like the other platform interfaces.
//    b. Some of the interfaces assumed that a program (or app) would
//       talk to only one application server and participate in
//       one domain. Later improvements removed these restrictions.
//       So some calls (like cold_init) ask for the URL of an applications
//       server when initializing the trust manager and the trust manager
//       has a concept of "primary" domain. Neither of these are necessary.
//       No certified domain is distinguished and you only need to know
//       the url (and port) of an applications server when you connect to
//       it using secure_authenticated_channel.  These changes (and some
//       other cosmetic ones) will have minimal effect on application
//       writing but should make the code easier to understand.

class domain_info {
 public:
  string domain_name_;
  string domain_policy_cert_;
  string host_;
  int    port_;
#ifdef OLD_API
  string service_host_;
  int    service_port_;
#endif
};

const int max_accerlerators = 4;
class accelerator {
 public:
  accelerator();
  ~accelerator();
  string  accelerator_type_;
  bool    verified_;
  string  location_type_;  // in-memory, network, file
  string  file_name;
  string  network_address_;
  byte   *address_;
  long    size_;
  int     num_certs_;
  string *certs_;
  string  measurement_;
};

class certifiers;

class cc_trust_manager {

 private:
  void cc_trust_manager_default_init();

 public:
  // Python swig bindings need this to be public, to size other array decls
  static const int max_symmetric_key_size_ = 128;

  string purpose_;
  string enclave_type_;
  string store_file_name_;
  string public_key_algorithm_;
  string symmetric_key_algorithm_;

  int         num_accelerators_;
  accelerator accelerators_[max_accerlerators];
  bool add_accelerator(const string &acc_type, int num_certs, string *certs);
  bool accelerator_verified(const string &acc_type);

  bool         cc_policy_store_initialized_;
  policy_store store_;

  // platform initialized?
  bool cc_provider_provisioned_;

#ifdef OLD_API
  // primary domain certified?
  bool   cc_is_certified_;
  bool   primary_admissions_cert_valid_;
  string serialized_primary_admissions_cert_;

  // For primary security domain only
  bool        cc_basic_data_initialized_;
  bool        cc_policy_info_initialized_;
  string      serialized_policy_cert_;
  X509       *x509_policy_cert_;
  key_message public_policy_key_;
  bool        init_policy_key(byte *asn1_cert, int asn1_cert_size);
  // Note: if purpose is attestation, serialized_home_admissions_cert_
  // is the same as the serialized_service_cert_, so remove it later
#endif

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
  cc_trust_manager();
  cc_trust_manager(const string &enclave_type,
                   const string &purpose,
                   const string &policy_store_name);
  ~cc_trust_manager();

  // Each of the enclave types have bespoke initialization
  bool initialize_simulated_enclave(
      const string &serialized_attest_key,
      const string &measurement,
      const string &serialized_attest_endorsement);

  // Interface invoked through Python apps
  bool python_initialize_simulated_enclave(
      const byte *serialized_attest_key,
      int         attest_key_size,
      const byte *measurement,
      int         measurement_size,
      const byte *serialized_attest_endorsement,
      int         attest_key_signed_claim_size);
  bool initialize_sev_enclave(const string &ark_der_cert,
                              const string &ask_der_cert,
                              const string &vcek_der_cert);
  bool initialize_gramine_enclave(const int size, byte *cert);
  bool initialize_oe_enclave(const string &cert);
  bool initialize_application_enclave(const string &parent_enclave_type,
                                      int           in_fd,
                                      int           out_fd);
  bool initialize_keystone_enclave();
  bool initialize_islet_enclave();

  // If n == 0, systems should be able to find parameters
  // by default, for example, sev and sgx.
  bool initialize_enclave(int n, string *params);

  bool put_trust_data_in_store();
  bool get_trust_data_from_store();
#ifdef NEW_API
  bool initialize_store();
#endif
  bool fetch_store();
  bool save_store();
  void clear_sensitive_data();

  bool generate_symmetric_key(bool regen);
  bool generate_sealing_key(bool regen);
  bool generate_auth_key(bool regen);
  bool generate_service_key(bool regen);

#ifdef OLD_API
  bool cc_all_initialized();
  bool certify_primary_domain();
  bool certify_me() { return certify_primary_domain(); };

  bool cold_init(const string &public_key_alg,
                 const string &symmetric_key_alg,
                 const string &home_domain_name,
                 const string &home_host,
                 int           home_port,
                 const string &service_host,
                 int           service_port);

  bool warm_restart();
#endif
#ifdef NEW_API
  certifiers *find_certifier_by_domain_name(const string &domain_name);
  bool        initialize_keys(const string &public_key_alg,
                              const string &symmetric_key_alg,
                              bool          force = false);
  bool        initialize_new_domain(const string &domain_name,
                                    const string &symmetric_key_alg,
                                    const string &host_url,
                                    int           port);
  bool        initialize_existing_domain(const string &domain_name);
  bool get_admissions_cert(const string &domain_name, string *admin_cert);
  bool admissions_cert_valid_status(const string &domain_name);
#endif

  bool GetPlatformSaysAttestClaim(signed_claim_message *scm);
  void print_trust_data();

  // For peer-to-peer certification (not used yet)
  bool init_peer_certification_data(const string &public_key_alg);
  bool recover_peer_certification_data();
  bool get_peer_certification(const string &host_name, int port);
  bool run_peer_certification_service(const string &host_name, int port);

  // multi-domain support
#ifdef OLD_API
  bool add_or_update_new_domain(const string &domain_name,
                                const string &policy_cert,
                                const string &host,
                                int           port,
                                const string &service_host,
                                int           service_port);
  bool certify_secondary_domain(const string &domain_name);
#endif
#ifdef NEW_API
  bool add_or_update_new_domain(const string &domain_name,
                                const string &policy_cert,
                                const string &host,
                                int           port);
#endif
  bool get_certifiers_from_store();
  bool put_certifiers_in_store();
  bool write_private_key_to_file(const string &filename);
};


// Certification Anchors
class certifiers {
 private:
  // should be const, don't delete it
  cc_trust_manager *owner_;

 public:
  string signed_rule_;
  string purpose_;
  string domain_name_;
  string domain_policy_cert_;
#ifdef NEW_API
  bool        is_initialized_;
  X509       *x509_policy_cert_;
  key_message public_policy_key_;
#endif  // NEW_API
  string host_;
  int    port_;
  string admissions_cert_;
  bool   is_certified_;

  certifiers(cc_trust_manager *owner);
  ~certifiers();

#ifdef OLD_API
  string service_host_;
  int    service_port_;
#endif

#ifdef NEW_API
  bool init_certifiers_data_new(const string &domain_name,
                                const string &cert,
                                const string &host,
                                int           port);
#endif  // NEW_API

#ifdef OLD_API
  bool init_certifiers_data(const string &domain_name,
                            const string &cert,
                            const string &host,
                            int           port,
                            const string &service_host,
                            int           service_port);
  bool get_certified_status();
#endif  // OLD_API

  bool certify_domain(const string &purpose);
  void print_certifiers_entry();
};

class secure_authenticated_channel {
 public:
  string          role_;
  bool            channel_initialized_;
  key_message     private_key_;
  SSL_CTX        *ssl_ctx_;
  X509_STORE_CTX *store_ctx_;
  SSL            *ssl_;
  int             sock_;

  string asn1_root_cert_;  // root cert for my certificate
  X509  *root_cert_;

  string asn1_peer_root_cert_;  // root cert for peer
  X509  *peer_root_cert_;

  int     num_cert_chain_;
  string *cert_chain_;

  string asn1_my_cert_;
  X509  *my_cert_;

  X509  *peer_cert_;
  string peer_id_;

  secure_authenticated_channel(string &role);  // role is client or server
  ~secure_authenticated_channel();

  bool load_client_certs_and_key();

  // Interface invoked through Python apps. (We don't use the python_ prefix
  // as other tests / programs also exercise this through C++ code.)

  bool init_client_ssl(const string &host_name,
                       int           port,
                       const string &asn1_root_cert,
                       key_message  &private_key,
                       const string &private_key_cert);

#ifdef OLD_API
  bool init_client_ssl(const string           &host_name,
                       int                     port,
                       const cc_trust_manager &mgr);
#endif  // OLD_API
#ifdef NEW_API
  bool init_client_ssl(const string     &domain_name,
                       const string     &host_name,
                       int               port,
                       cc_trust_manager &mgr);
#endif

  // Interface invoked through Python apps. (We don't use the python_ prefix
  // as other tests / programs also exercise this through C++ code.)
  bool init_server_ssl(const string &host_name,
                       int           port,
                       const string &asn1_root_cert,
                       key_message  &private_key,
                       const string &private_key_cert);

#ifdef OLD_API
  bool init_server_ssl(const string           &host_name,
                       int                     port,
                       const cc_trust_manager &mgr);
#endif
#ifdef NEW_API
  bool init_server_ssl(const string     &domain_name,
                       const string     &host_name,
                       int               port,
                       cc_trust_manager &mgr);
#endif  //  NEW_API

  // Interface invoked for user supplied keys and cert chain.
  // This is used, for example, when either endpoint is not a certifier approved
  // key.
  bool init_client_ssl(const string &host_name,
                       int           port,
                       const string &asn1_root_cert,
                       const string &peer_asn1_root_cert,
                       int           cert_chain_length,
                       string       *der_certs,
                       key_message  &private_key,
                       const string &auth_cert);
  bool init_server_ssl(const string &host_name,
                       int           port,
                       const string &asn1_root_cert,
                       const string &peer_asn1_root_cert,
                       int           cert_chain_length,
                       string       *der_certs,
                       key_message  &private_key,
                       const string &auth_cert);

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
                     const string &asn1_root_cert,
                     const string &asn1_peer_root_cert,
                     int           num_certs,
                     string       *cert_chain,
                     key_message  &private_key,
                     const string &private_key_cert,
                     void (*func)(secure_authenticated_channel &));

bool server_dispatch(const string &host_name,
                     int           port,
                     const string &asn1_root_cert,
                     key_message  &private_key,
                     const string &private_key_cert,
                     void (*)(secure_authenticated_channel &));

#ifdef OLD_API
bool server_dispatch(const string           &host_name,
                     int                     port,
                     const cc_trust_manager &mgr,
                     void (*)(secure_authenticated_channel &));
#endif  // OLD_API

#ifdef NEW_API
bool server_dispatch(const string     &domain_name,
                     const string     &host_name,
                     int               port,
                     cc_trust_manager &mgr,
                     void (*)(secure_authenticated_channel &));
#endif

}  // namespace framework
}  // namespace certifier

#endif  // _CERTIFIER_FRAMEWORK_H__
