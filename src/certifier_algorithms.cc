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

#include "cc_useful.h"

// clang-format off

/*
 * Encryption algorithms supported.
 */
const char * Enc_method_aes_128                   = "aes-128";
const char * Enc_method_aes_256                   = "aes-256";
const char * Enc_method_aes_256_cbc               = "aes-256-cbc";

// Authenticated symmetric-key algorithms
const char * Enc_method_aes_128_cbc_hmac_sha256   = "aes-128-cbc-hmac-sha256";
const char * Enc_method_aes_256_cbc_hmac_sha256   = "aes-256-cbc-hmac-sha256";
const char * Enc_method_aes_256_cbc_hmac_sha384   = "aes-256-cbc-hmac-sha384";
const char * Enc_method_aes_256_gcm               = "aes-256-gcm";

const char * Enc_method_ecc_256_private           = "ecc-256-private";
const char * Enc_method_ecc_256_public            = "ecc-256-public";
const char * Enc_method_ecc_256_sha256_pkcs_sign  = "ecc-256-sha256-pkcs-sign";
const char * Enc_method_ecc_384                   = "ecc-384";
const char * Enc_method_ecc_384_private           = "ecc-384-private";
const char * Enc_method_ecc_384_public            = "ecc-384-public";
const char * Enc_method_ecc_384_sha384_pkcs_sign  = "ecc-384-sha384-pkcs-sign";
const char * Enc_method_rsa_1024                  = "rsa-1024";
const char * Enc_method_rsa_1024_private          = "rsa-1024-private";
const char * Enc_method_rsa_1024_public           = "rsa-1024-public";
const char * Enc_method_rsa_1024_sha256_pkcs_sign = "rsa-1024-sha256-pkcs-sign";
const char * Enc_method_rsa_2048                  = "rsa-2048";
const char * Enc_method_rsa_2048_private          = "rsa-2048-private";
const char * Enc_method_rsa_2048_public           = "rsa-2048-public";
const char * Enc_method_rsa_2048_sha256_pkcs_sign = "rsa-2048-sha256-pkcs-sign";
const char * Enc_method_rsa_3072                  = "rsa-3072";
const char * Enc_method_rsa_3072_private          = "rsa-3072-private";
const char * Enc_method_rsa_3072_public           = "rsa-3072-public";
const char * Enc_method_rsa_3072_sha384_pkcs_sign = "rsa-3072-sha384-pkcs-sign";
const char * Enc_method_rsa_4096                  = "rsa-4096";
const char * Enc_method_rsa_4096_private          = "rsa-4096-private";
const char * Enc_method_rsa_4096_public           = "rsa-4096-public";
const char * Enc_method_rsa_4096_sha384_pkcs_sign = "rsa-4096-sha384-pkcs-sign";

std::vector<const char *> Enc_public_key_algorithms =
                    {   Enc_method_rsa_2048
                      , Enc_method_rsa_3072
                      , Enc_method_rsa_4096
                      , Enc_method_ecc_384
                    };

const int Num_public_key_algorithms = Enc_public_key_algorithms.size();

// Names of Authenticated symmetric-key algorithms
std::vector<const char *> Enc_authenticated_symmetric_key_algorithms =
                    {   Enc_method_aes_128_cbc_hmac_sha256
                      , Enc_method_aes_256_cbc_hmac_sha256
                      , Enc_method_aes_256_cbc_hmac_sha384
                      , Enc_method_aes_256_gcm
                    };

const int Num_symmetric_key_algorithms = Enc_authenticated_symmetric_key_algorithms.size();

/*
 * Cryptographic hash algorithms supported.
 */
const char * Digest_method_sha256  = "sha256";
const char * Digest_method_sha_256 = "sha-256";
const char * Digest_method_sha_384 = "sha-384";
const char * Digest_method_sha_512 = "sha-512";

/*
 * Integrity protection algorithms, used in conjunction with specific encryption algorithms.
 */
const char * Integrity_method_aes_256_cbc_hmac_sha256 = "aes-256-cbc-hmac-sha256";
const char * Integrity_method_aes_256_cbc_hmac_sha384 = "aes-256-cbc-hmac-sha384";
const char * Integrity_method_aes_256_gcm             = "aes-256-gcm";
const char * Integrity_method_hmac_sha256             = "hmac-sha256";

// clang-format on
