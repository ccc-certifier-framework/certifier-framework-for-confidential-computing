// Copyright 2014-2020 John Manferdelli, All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// or in the the file LICENSE-2.0.txt in the top level sourcedirectory
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License
// File: acl_support.h

#ifndef _ACL_SUPPORT_H__
#define _ACL_SUPPORT_H__

#include "acl.pb.h"

#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/ec.h>

#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "stdio.h"
#include <unistd.h>
#include "sys/fcntl.h"
#include "sys/stat.h"

// These first definition are copied from certifier.  When linked
// into a certifier applications, we should use those.

// ----------------------------------------------------------------------

#ifndef int32_t
typedef int int32_t;
#endif

#ifndef int64_t
#ifdef __linux__
typedef long int int64_t;
#else
typedef long long int int64_t;
#endif
#endif

#ifndef uint32_t
typedef unsigned uint32_t;
#endif

#ifndef uint64_t
#ifdef __linux__
typedef long unsigned uint64_t;
#else
typedef long long unsigned uint64_t;
#endif
#endif

#ifndef NBITSINBYTE
#define NBITSINBYTE 8
#endif
#ifndef NBITSINUINT64
#define NBITSINUINT64 64
#endif

#ifndef byte
typedef unsigned char byte;
#endif

using std::string;

const int seconds_in_day = 86400;
const int seconds_in_minute = 60;
const int seconds_in_hour = 3600;
const double seconds_in_common_year = 365.0 * 86400;
const double seconds_in_leap_year = 366.0 * 86400;
const double seconds_in_gaussian_year = 365.2568983 * 86400;

class time_point {
 public:
  int year_;
  int month_;  // 1= January
  int day_in_month_;
  int hour_;
  int minutes_;
  double seconds_;

  time_point();
  bool time_now();
  bool add_interval_to_time(time_point& from, double seconds_later);
  void print_time();
  bool encode_time(string* the_time);
  bool decode_time(string& encoded_time);
  bool time_point_to_unix_tm(struct tm* time_now);
  bool unix_tm_to_time_point(struct tm* time_now);
};
int compare_time_points(time_point& l, time_point& r);

class random_source {
public:
  bool initialized_;
  bool have_rd_rand_;
  int fd_;

  random_source();
  bool have_intel_rd_rand();
  bool start_random_source();
  int get_random_bytes(int n, byte* b);
  bool close_random_source();
};

void print_bytes(int n, byte* in);
void reverse_bytes(int size, byte* in, byte* out);
void reverse_bytes_in_place(int size, byte* b);
int bits_to_bytes(int n);
int bytes_to_bits(int n);
int bits_to_uint64(int n);
int uint64_to_bits(int n);
bool hex_to_bytes(string& h, string* b);
bool bytes_to_hex(string& b, string* h);
bool base64_to_bytes(string& b64, string* b);
bool bytes_to_base64(string& b, string* b64);

key_message* make_symmetric_key(string& alg, string& name,
      const string& not_before, const string& not_after,
      const string& key_bits);

void print_encrypted_message(encrypted_message& m);
void print_signature_message(signature_message& m);
void print_key_message(const key_message& m);

int crypto_get_random_bytes(int num_bytes, byte* buf);
bool init_crypto();
void close_crypto();

int digest_output_byte_size(const char *alg_name);
int mac_output_byte_size(const char *alg_name);
int cipher_block_byte_size(const char *alg_name);
int cipher_key_byte_size(const char *alg_name);

extern const char* Enc_method_aes_128;
extern const char* Enc_method_aes_256;
extern const char* Enc_method_aes_256_cbc;
extern const char* Enc_method_aes_128_cbc_hmac_sha256;
extern const char* Enc_method_aes_256_cbc_hmac_sha256;
extern const char* Enc_method_aes_256_cbc_hmac_sha384;
extern const char* Enc_method_aes_256_gcm;
extern const char* Enc_method_ecc_256_private;
extern const char* Enc_method_ecc_256_public;
extern const char* Enc_method_ecc_256_sha256_pkcs_sign;
extern const char* Enc_method_ecc_384;
extern const char* Enc_method_ecc_384_private;
extern const char* Enc_method_ecc_384_public;
extern const char* Enc_method_ecc_384_sha384_pkcs_sign;
extern const char* Enc_method_rsa_1024;
extern const char* Enc_method_rsa_1024_private;
extern const char* Enc_method_rsa_1024_public;
extern const char* Enc_method_rsa_1024_sha256_pkcs_sign;
extern const char* Enc_method_rsa_2048;
extern const char* Enc_method_rsa_2048_private;
extern const char* Enc_method_rsa_2048_public;
extern const char* Enc_method_rsa_2048_sha256_pkcs_sign;
extern const char* Enc_method_rsa_3072;
extern const char* Enc_method_rsa_3072_private;
extern const char* Enc_method_rsa_3072_public;
extern const char* Enc_method_rsa_3072_sha384_pkcs_sign;
extern const char* Enc_method_rsa_4096;
extern const char* Enc_method_rsa_4096_private;
extern const char* Enc_method_rsa_4096_public;
extern const char* Enc_method_rsa_4096_sha384_pkcs_sign;
extern const char* Digest_method_sha256;
extern const char* Digest_method_sha_256;
extern const char* Digest_method_sha_384;
extern const char* Digest_method_sha_512;
extern const char* Integrity_method_aes_256_cbc_hmac_sha256;
extern const char* Integrity_method_aes_256_cbc_hmac_sha384;
extern const char* Integrity_method_aes_256_gcm;
extern const char* Integrity_method_hmac_sha256 ;

class cert_keys_seen {
 public: 
  string issuer_name_;
  key_message *k_;
};

class cert_keys_seen_list {
 public:
  cert_keys_seen_list(int max_size);
  ~cert_keys_seen_list();
  int max_size_;
  int size_;
  cert_keys_seen **entries_;

  key_message *find_key_seen(const string &name);
  bool add_key_seen(key_message *k);
}; 
    
class name_size {
 public:
  const char *name_;
  int size_;
};

bool time_t_to_tm_time(time_t *t, struct tm *tm_time);
bool tm_time_to_time_point(struct tm * tm_time, time_point *tp);
bool asn1_time_to_tm_time(const ASN1_TIME *s, struct tm * tm_time);
bool get_not_before_from_cert(X509 *c, time_point *tp) ;
bool get_not_after_from_cert(X509 *c, time_point *tp);
int compare_time(time_point &t1, time_point &t2);

bool digest_message(const char* alg, const byte* message, int message_len,
                    byte* digest, unsigned int digest_len);
bool encrypt(byte *in, int in_len, byte *key, byte *iv,
             byte *out, int * out_size);
bool decrypt(byte *in, int in_len, byte *key, byte *iv,
             byte *out, int * size_out);
bool aes_256_cbc_sha256_encrypt(byte *in, int in_len, byte *key, byte *iv,
                                byte *out, int * out_size);
bool aes_256_cbc_sha256_decrypt(byte *in, int in_len, byte *key, byte *out,
                                int * out_size);
bool aes_256_cbc_sha384_encrypt(byte *in, int   in_len, byte *key, byte *iv,
                                byte *out, int * out_size);
bool aes_256_cbc_sha384_decrypt(byte *in, int in_len, byte *key,
                                byte *out, int * out_size);
bool aes_256_gcm_encrypt(byte *in, int in_len, byte *key, byte *iv,
                         byte *out, int * out_size);
bool aes_256_gcm_decrypt(byte *in, int in_len, byte *key,
                         byte *out, int * out_size);
bool authenticated_encrypt(const char *alg_name, byte* in, int in_len, byte* key, int key_len,
                           byte* iv, int iv_len, byte* out, int* out_size);
bool authenticated_decrypt(const char *alg_name, byte* in, int in_len, byte* key,
                           int key_len, byte* out, int* out_size);

bool private_key_to_public_key(const key_message &in, key_message* out);
bool key_to_RSA(const key_message &k, RSA *r);
bool RSA_to_key(const RSA *r, key_message *k);
EC_KEY *key_to_ECC(const key_message &k);
bool ECC_to_key(const EC_KEY *ecc_key, key_message *k);

bool generate_new_rsa_key(int num_bits, RSA *r);
bool make_certifier_rsa_key(int n, key_message *k);
bool rsa_public_encrypt(RSA * key, byte *data, int data_len,
                        byte *encrypted, int * size_out);
bool rsa_private_decrypt(RSA * key, byte *enc_data, int data_len,
                         byte *decrypted, int * size_out);
bool rsa_sha256_sign(RSA * key, int to_sign_size, byte* to_sign,
                     int* sig_size, byte* sig);
bool rsa_sign(const char *alg, RSA* key, int size,
              byte* msg, int* sig_size, byte* sig);
bool rsa_verify(const char *alg, RSA* key, int size, byte* msg,
                int sig_size, byte* sig);
void print_point(const point_message &pt);

EC_KEY* generate_new_ecc_key(int num_bits);
void print_ecc_key(const ecc_message &em);
bool ecc_sign(const char *alg, EC_KEY* key, int size, byte* msg,
              int* size_out, byte* out);
bool ecc_verify(const char *alg, EC_KEY* key, int size,
                byte* msg, int size_sig, byte* sig);
bool make_certifier_ecc_key(int n, key_message *k);
void print_rsa_key(const rsa_message &rsa);
void print_key_descriptor(const key_message &k);
int add_ext(X509 *cert, int nid, const char *value);

bool produce_artifact(key_message& signing_key, string& issuer_name_str, string& issuer_organization_str,
                      key_message& subject_key, string& subject_name_str,
                      string& subject_organization_str, uint64_t sn,
                      double secs_duration, X509* x509, bool is_root);
bool verify_artifact(X509& cert, key_message &verify_key, string* issuer_name_str,
                     string* issuer_description_str, key_message* subject_key,
                     string* subject_name_str, string* subject_organization_str,
                     uint64_t *sn);
bool verify_cert_chain(X509* root_cert, buffer_list& certs);

bool asn1_to_x509(const string &in, X509 *x);
bool x509_to_asn1(X509 *x, string *out);

int sized_pipe_write(int fd, int size, byte *buf);
int sized_pipe_read(int fd, string *out);
int sized_ssl_write(SSL *ssl, int size, byte *buf);
int sized_ssl_read(SSL *ssl, string *out);
int sized_socket_read(int fd, string *out);
int sized_socket_write(int fd, int size, byte *buf);

bool key_from_pkey(EVP_PKEY *pkey, const string &name, key_message *k);
key_message *get_issuer_key(X509 *x, cert_keys_seen_list &list);
EVP_PKEY *pkey_from_key(const key_message &k);
bool x509_to_public_key(X509 *x, key_message *k);
bool make_root_key_with_cert(string& type, string& name, string& issuer_name, key_message *k);
bool same_point(const point_message &pt1, const point_message &pt2);
bool same_key(const key_message &k1, const key_message &k2);
bool same_cert(X509* c1, X509* c2);
bool rsa_sha256_verify(RSA *key, int size, byte *msg, int sig_size, byte *sig);

int file_size(const string &file_name);
bool write_file(const string &file_name, int size, byte* data);
bool write_file_from_string(const string &file_name, const string &in);
bool read_file(const string &file_name, int* size, byte* data);
bool read_file_into_string(const string &file_name, string* out);
#endif

