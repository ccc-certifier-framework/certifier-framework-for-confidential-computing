//  Copyright (c) 2021-22, VMware Inc, and the Certifier Authors.  All rights
//  reserved.
//
// Licensed under the Apache License, Version 2.0 (the License);
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an AS IS BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.


#ifndef __CERTIFIER_ALGORITHMS_H__
#define __CERTIFIER_ALGORITHMS_H__

#include <vector>

/*
 * Encryption algorithms supported.
 */
extern const char *Enc_method_aes_128;
extern const char *Enc_method_aes_128_cbc_hmac_sha256;
extern const char *Enc_method_aes_256;
extern const char *Enc_method_aes_256_cbc;
extern const char *Enc_method_aes_256_cbc_hmac_sha256;
extern const char *Enc_method_aes_256_cbc_hmac_sha384;
extern const char *Enc_method_aes_256_gcm;
extern const char *Enc_method_ecc_256_private;
extern const char *Enc_method_ecc_256_public;
extern const char *Enc_method_ecc_256_sha256_pkcs_sign;
extern const char *Enc_method_ecc_384;
extern const char *Enc_method_ecc_384_private;
extern const char *Enc_method_ecc_384_public;
extern const char *Enc_method_ecc_384_sha384_pkcs_sign;
extern const char *Enc_method_rsa_1024;
extern const char *Enc_method_rsa_1024_private;
extern const char *Enc_method_rsa_1024_public;
extern const char *Enc_method_rsa_1024_sha256_pkcs_sign;
extern const char *Enc_method_rsa_2048;
extern const char *Enc_method_rsa_2048_private;
extern const char *Enc_method_rsa_2048_public;
extern const char *Enc_method_rsa_2048_sha256_pkcs_sign;
extern const char *Enc_method_rsa_3072;
extern const char *Enc_method_rsa_3072_private;
extern const char *Enc_method_rsa_3072_public;
extern const char *Enc_method_rsa_3072_sha384_pkcs_sign;
extern const char *Enc_method_rsa_4096;
extern const char *Enc_method_rsa_4096_private;
extern const char *Enc_method_rsa_4096_public;
extern const char *Enc_method_rsa_4096_sha384_pkcs_sign;

/*
 * Cryptographic hash algorithms supported.
 */
extern const char *Digest_method_sha256;
extern const char *Digest_method_sha_256;
extern const char *Digest_method_sha_384;
extern const char *Digest_method_sha_512;

/*
 * Integrity protection algorithms, used in conjunction with specific encryption
 * algorithms.
 */
extern const char *Integrity_method_aes_256_cbc_hmac_sha256;
extern const char *Integrity_method_aes_256_cbc_hmac_sha384;
extern const char *Integrity_method_aes_256_gcm;
extern const char *Integrity_method_hmac_sha256;

extern std::vector<const char *> Enc_public_key_algorithms;
extern std::vector<const char *> Enc_authenticated_symmetric_key_algorithms;

extern const int Num_public_key_algorithms;
extern const int Num_symmetric_key_algorithms;

#endif  // __CERTIFIER_ALGORITHMS_H__
