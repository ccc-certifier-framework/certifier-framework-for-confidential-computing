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

#ifndef _CERTIFIER_UTILITIES_H__
#define _CERTIFIER_UTILITIES_H__

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

namespace certifier {
namespace utilities {
const int block_size = 16;
const int num_bits_in_byte = 8;

int file_size(const string &file_name);

bool read_file(const string &file_name, int *size, byte *data);
bool write_file(const string &file_name, int size, byte *data);

bool read_file_into_string(const string &file_name, string *out);
bool write_file_from_string(const string &file_name, const string &in);

bool digest_message(const char * alg,
                    const byte * message,
                    int          message_len,
                    byte *       digest,
                    unsigned int digest_len);


bool authenticated_encrypt(const char *alg,
                           byte *      in,
                           int         in_len,
                           byte *      key,
                           int         key_len,
                           byte *      iv,
                           int         iv_len,
                           byte *      out,
                           int *       out_size);
bool authenticated_decrypt(const char *alg,
                           byte *      in,
                           int         in_len,
                           byte *      key,
                           int         key_len,
                           byte *      out,
                           int *       out_size);

EC_KEY *generate_new_ecc_key(int num_bits);
EC_KEY *key_to_ECC(const key_message &kr);
bool    ECC_to_key(const EC_KEY *e, key_message *k);

bool private_key_to_public_key(const key_message &in, key_message *out);
bool get_random(int num_bits, byte *out);

// Serialized time: YYYY-MM-DDTHH:mm:ss. sssZ
bool time_t_to_tm_time(time_t *t, struct tm *tm_time);
bool tm_time_to_time_point(struct tm *tm_time, time_point *tp);
bool asn1_time_to_tm_time(const ASN1_TIME *s, struct tm *tm_time);
bool get_not_before_from_cert(X509 *c, time_point *tp);
bool get_not_after_from_cert(X509 *c, time_point *tp);
bool time_now(time_point *t);
bool time_to_string(time_point &t, string *s);
bool string_to_time(const string &s, time_point *t);
bool add_interval_to_time_point(time_point &t_in,
                                double      hours,
                                time_point *out);
int  compare_time(time_point &t1, time_point &t2);
void print_time_point(time_point &t);
void print_entity(const entity_message &em);
void print_key(const key_message &k);
void print_rsa_key(const rsa_message &rsa);
void print_ecc_key(const ecc_message &rsa);
void print_platform(const platform &pl);
void print_environment(const environment &env);
void print_property(const property &prop);
void print_bytes(int n, byte *buf);

// X509 artifact
bool produce_artifact(key_message &signing_key,
                      string &     issuer_name_str,
                      string &     issuer_description_str,
                      key_message &subject_key,
                      string &     subject_name_str,
                      string &     subject_description_str,
                      uint64_t     sn,
                      double       secs_duration,
                      X509 *       x509,
                      bool         is_root,
                      bool         vcek = false);
bool verify_artifact(X509 &       cert,
                     key_message &verify_key,
                     string *     issuer_name_str,
                     string *     issuer_description_str,
                     key_message *subject_key,
                     string *     subject_name_str,
                     string *     subject_description_str,
                     uint64_t *   sn);

int cipher_block_byte_size(const char *alg_name);
int cipher_key_byte_size(const char *alg_name);
int digest_output_byte_size(const char *alg_name);
int mac_output_byte_size(const char *alg_name);

bool asn1_to_x509(const string &in, X509 *x);
bool x509_to_asn1(X509 *x, string *out);
bool make_root_key_with_cert(string &     type,
                             string &     name,
                             string &     issuer_name,
                             key_message *k);

bool check_date_range(const string &nb, const string &na);

int sized_socket_read(int fd, string *out);
int sized_socket_write(int fd, int size, byte *buf);
}  // namespace utilities
}  // namespace certifier

#endif
