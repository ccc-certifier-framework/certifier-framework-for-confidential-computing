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

#ifndef byte
typedef unsigned char byte;
#endif

#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include "certifier.pb.h"
#include "certifier.h"

#ifdef OE_CERTIFIER
#  include "openenclave/attestation.h"
#  include "openenclave/sealing.h"
#endif

#include "certifier_utilities.h"
#include "certifier_algorithms.h"

using std::string;

#ifndef _SUPPORT_H__
#  define _SUPPORT_H__

bool encrypt(byte *in,
             int   in_len,
             byte *key,
             byte *iv,
             byte *out,
             int * out_size);
bool decrypt(byte *in,
             int   in_len,
             byte *key,
             byte *iv,
             byte *out,
             int * size_out);

bool make_certifier_rsa_key(int n, key_message *k);
bool rsa_public_encrypt(RSA * key,
                        byte *data,
                        int   data_len,
                        byte *encrypted,
                        int * size_out);
bool rsa_private_decrypt(RSA * key,
                         byte *enc_data,
                         int   data_len,
                         byte *decrypted,
                         int * size_out);

// replace these two
bool rsa_sha256_sign(RSA *key, int size, byte *msg, int *size_out, byte *out);
bool rsa_sha256_verify(RSA *key, int size, byte *msg, int size_sig, byte *sig);
bool rsa_sign(const char *alg,
              RSA *       key,
              int         size,
              byte *      msg,
              int *       size_out,
              byte *      out);
bool rsa_verify(const char *alg,
                RSA *       key,
                int         size,
                byte *      msg,
                int         size_sig,
                byte *      sig);

bool make_certifier_ecc_key(int n, key_message *k);
bool ecc_sign(const char *alg,
              EC_KEY *    key,
              int         size,
              byte *      msg,
              int *       size_out,
              byte *      out);
bool ecc_verify(const char *alg,
                EC_KEY *    key,
                int         size,
                byte *      msg,
                int         size_sig,
                byte *      sig);

bool same_key(const key_message &k1, const key_message &k2);
bool same_measurement(const string &m1, const string &m2);
bool same_entity(const entity_message &e1, const entity_message &e2);
bool same_property(const property &p1, const property &p2);
bool same_properties(const properties &p1, const properties &p2);
bool satisfying_property(const property &p1, const property &p2);
bool satisfying_properties(const properties &p1, const properties &p2);
bool same_platform(const platform &p1, const platform &p2);
bool satisfying_platform(const platform &p1, const platform &p2);
bool same_environment(const environment &e1, const environment &e2);
bool same_vse_claim(const vse_clause &c1, const vse_clause &c2);

bool generate_new_rsa_key(int num_bits, RSA *r);
bool key_to_RSA(const key_message &k, RSA *r);
bool RSA_to_key(const RSA *r, key_message *k);

bool make_key_entity(const key_message &key, entity_message *ent);
bool make_measurement_entity(const string &measurement, entity_message *ent);
bool make_property(string &  name,
                   string &  type,
                   string &  cmp,
                   uint64_t  int_value,
                   string &  string_value,
                   property *prop);
bool make_platform(const string &     type,
                   const properties & p,
                   const key_message *at,
                   platform *         plat);
bool make_platform_entity(platform &plat, entity_message *ent);
bool make_environment_entity(environment &env, entity_message *ent);
bool make_environment(const platform &plat,
                      const string &  measurement,
                      environment *   env);
bool make_unary_vse_clause(const entity_message &subject,
                           string &              verb,
                           vse_clause *          out);
bool make_simple_vse_clause(const entity_message &subject,
                            string &              verb,
                            const entity_message &object,
                            vse_clause *          out);
bool make_indirect_vse_clause(const entity_message &subject,
                              string &              verb,
                              const vse_clause &    in,
                              vse_clause *          out);
bool make_claim(int            size,
                byte *         serialized_claim,
                string &       format,
                string &       descriptor,
                string &       not_before,
                string &       not_after,
                claim_message *out);
bool get_vse_clause_from_signed_claim(const signed_claim_message &scm,
                                      vse_clause *                c);
void print_key_descriptor(const key_message &k);
void print_entity_descriptor(const entity_message &e);
void print_property_descriptor(const property &p);
void print_platform_descriptor(const platform &pl);
void print_environment_descriptor(const environment &env);
void print_vse_clause(const vse_clause c);
void print_claim(const claim_message &claim);
void print_signed_claim(const signed_claim_message &signed_claim);
void print_protected_blob(protected_blob_message &pb);

bool make_signed_claim(const char *          alg,
                       const claim_message & claim,
                       const key_message &   key,
                       signed_claim_message *out);
bool verify_signed_claim(const signed_claim_message &claim,
                         const key_message &         key);
bool get_vse_clause_from_signed_claim(const signed_claim_message &scm,
                                      vse_clause *                c);

int sized_pipe_read(int fd, string *out);
int sized_pipe_write(int fd, int size, byte *buf);

int sized_ssl_read(SSL *ssl, string *out);
int sized_ssl_write(SSL *ssl, int size, byte *buf);

class cert_keys_seen {
 public:
  string       issuer_name_;
  key_message *k_;
};

class cert_keys_seen_list {
 public:
  cert_keys_seen_list(int max_size);
  ~cert_keys_seen_list();
  int              max_size_;
  int              size_;
  cert_keys_seen **entries_;

  key_message *find_key_seen(const string &name);
  bool         add_key_seen(key_message *k);
};

key_message *get_issuer_key(X509 *x, cert_keys_seen_list &list);
EVP_PKEY *   pkey_from_key(const key_message &k);
bool         x509_to_public_key(X509 *x, key_message *k);
bool         construct_vse_attestation_from_cert(const key_message &subj,
                                                 const key_message &signer,
                                                 vse_clause *       cl);
#endif
