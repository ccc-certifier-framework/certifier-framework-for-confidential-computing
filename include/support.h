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

#include "certifier.pb.h"

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
#include "openenclave/attestation.h"
#include "openenclave/sealing.h"
#endif

using std::string;

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


#ifndef _SUPPORT_H__
#define _SUPPORT_H__
const int block_size = 16;
const int num_bits_in_byte = 8;

bool write_file(const string& file_name, int size, byte* data);
int file_size(const string& file_name);
bool read_file(const string& file_name, int* size, byte* data);

bool encrypt(byte* in, int in_len, byte *key,
            byte *iv, byte *out, int* out_size);
bool decrypt(byte *in, int in_len, byte *key,
            byte *iv, byte *out, int* size_out);

bool digest_message(const char* alg, const byte* message, int message_len,
    byte* digest, unsigned int digest_len);


bool authenticated_encrypt(byte* in, int in_len, byte *key,
            byte *iv, byte *out, int* out_size);
bool authenticated_decrypt(byte* in, int in_len, byte *key,
            byte *out, int* out_size);

bool authenticated_encrypt(const char* alg, byte* in, int in_len, byte *key,
            byte *iv, byte *out, int* out_size);
bool authenticated_decrypt(const char* alg, byte* in, int in_len, byte *key,
            byte *out, int* out_size);

bool make_certifier_rsa_key(int n,  key_message* k);
bool rsa_public_encrypt(RSA* key, byte* data, int data_len, byte *encrypted, int* size_out);
bool rsa_private_decrypt(RSA* key, byte* enc_data, int data_len, byte* decrypted, int* size_out);

// replace these two
bool rsa_sha256_sign(RSA* key, int size, byte* msg, int* size_out, byte* out);
bool rsa_sha256_verify(RSA *key, int size, byte* msg, int size_sig, byte* sig);
bool rsa_sign(const char* alg, RSA* key, int size, byte* msg, int* size_out, byte* out);
bool rsa_verify(const char* alg, RSA *key, int size, byte* msg, int size_sig, byte* sig);

bool make_certifier_ecc_key(int n,  key_message* k);
bool ecc_sign(const char* alg, EC_KEY* key, int size, byte* msg, int* size_out, byte* out);
bool ecc_verify(const char* alg, EC_KEY *key, int size, byte* msg, int size_sig, byte* sig);

bool same_key(const key_message& k1, const key_message& k2);
bool same_measurement(string& m1, string& m2);
bool same_entity(const entity_message& e1, const entity_message& e2);
bool same_vse_claim(const vse_clause& c1, const vse_clause& c2);

bool generate_new_rsa_key(int num_bits, RSA* r);
bool key_to_RSA(const key_message& k, RSA* r);
bool RSA_to_key(RSA* r, key_message* k);

EC_KEY* generate_new_ecc_key(int num_bits);
EC_KEY* key_to_ECC(const key_message& kr);
bool ECC_to_key(const EC_KEY* e, key_message* k);

bool private_key_to_public_key(const key_message& in, key_message* out);
bool get_random(int num_bits, byte* out);

bool make_key_entity(const key_message& key, entity_message* ent);
bool make_measurement_entity(string& measurement, entity_message* ent);
bool make_unary_vse_clause(const entity_message& subject, string& verb,
    vse_clause* out);
bool make_simple_vse_clause(const entity_message& subject, string& verb,
    const entity_message& object, vse_clause* out);
bool make_indirect_vse_clause(const entity_message& subject, string& verb,
    const vse_clause& in, vse_clause* out);
bool make_claim(int size, byte* serialized_claim, string& format, string& descriptor,
    string& not_before, string& not_after, claim_message* out);
bool get_vse_clause_from_signed_claim(const signed_claim_message& scm, vse_clause* c);
void print_bytes(int n, byte* buf);
void print_key_descriptor(const key_message& k);
void print_entity_descriptor(const entity_message& e);
void print_vse_clause(const vse_clause c);
void print_claim(const claim_message& claim);
void print_signed_claim(const signed_claim_message& signed_claim);
void print_storage_info(const storage_info_message& smi);
void print_trusted_service_message(const trusted_service_message& tsm);
void print_protected_blob(protected_blob_message& pb);

bool make_signed_claim(const char* alg, const claim_message& claim, const key_message& key,
    signed_claim_message* out);
bool verify_signed_claim(const signed_claim_message& claim, const key_message& key);
bool get_vse_clause_from_signed_claim(const signed_claim_message& scm, vse_clause* c);

// Serialized time: YYYY-MM-DDTHH:mm:ss. sssZ
bool time_now(time_point* t);
bool time_to_string(time_point& t, string* s);
bool string_to_time(const string& s, time_point* t);
bool add_interval_to_time_point(time_point& t_in, double hours, time_point* out);
int compare_time(time_point& t1, time_point& t2);
void print_time_point(time_point& t);
void print_entity(const entity_message& em);
void print_key(const key_message& k);
void print_rsa_key(const rsa_message& rsa);
void print_ecc_key(const ecc_message& rsa);

// X509 artifact
bool produce_artifact(key_message& signing_key, string& issuer_name_str, string& issuer_description_str,
                      key_message& subject_key, string& subject_name_str, string& subject_description_str,
                      uint64_t sn, double secs_duration, X509* x509, bool is_root);
bool verify_artifact(X509& cert, key_message& verify_key,
    string* issuer_name_str, string* issuer_description_str,
    key_message* subject_key, string* subject_name_str, string* subject_description_str,
    uint64_t* sn);

int cipher_block_byte_size(const char* alg_name);
int cipher_key_byte_size(const char* alg_name);
int digest_output_byte_size(const char* alg_name);
int mac_output_byte_size(const char* alg_name);

bool asn1_to_x509(const string& in, X509 *x);
bool x509_to_asn1(X509 *x, string* out);
bool make_root_key_with_cert(string& type, string& name, string& issuer_name, key_message* k);

int sized_pipe_read(int fd, string* out);
int sized_ssl_read(SSL* ssl, string* out);
int sized_socket_read(int fd, string* out);

bool x509_to_public_key(X509* x, key_message* k);
#endif
