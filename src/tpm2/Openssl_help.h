// Copyright 2015 Google Corporation, All Rights Reserved.
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
//
// Portions of this code were derived TPM2.0-TSS published
// by Intel under the license set forth in intel_license.txt
// and downloaded on or about August 6, 2015.
// File: openssl_helpers.cc

// standard buffer size

#ifndef __OPENSSL_HELPERS__
#define __OPENSSL_HELPERS__
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <tpm20.h>
#include <tpm2_lib.h>
#include <errno.h>

#include <tpm2.pb.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <string>
using std::string;

bool GenerateX509CertificateRequest(x509_cert_request_parameters_message& params,
                                    bool sign_request, X509_REQ* req);
bool GetPublicRsaParametersFromSSLKey(RSA& rsa, rsa_public_key_message* key_msg);
bool GetPrivateRsaParametersFromSSLKey(RSA& rsa,
                                       rsa_private_key_message* key_msg);
bool SignX509Certificate(RSA* signing_key, bool isCa,
                         signing_instructions_message& signing_instructions,
                         EVP_PKEY* signedKey,
                         X509_REQ* req, bool verify_req_sig, X509* cert);
bool VerifyX509CertificateChain(certificate_chain_message& chain);
bool GetCertificateRequestParametersFromX509(X509_REQ& x509_req,
                                             cert_parameters_message* cert_params);
bool GetCertificateParametersFromX509(X509& x509_cert,
                                      cert_parameters_message* cert_params);
bool GetPublicRsaKeyFromParameters(const rsa_public_key_message& key_msg,
                                   RSA* rsa);
bool GetPrivateRsaKeyFromParameters(const rsa_private_key_message& key_msg,
                                    RSA* rsa);

void print_internal_private_key(RSA& key);
void print_cert_request_message(x509_cert_request_parameters_message&
                                req_message);

BIGNUM* bin_to_BN(int len, byte* buf);
string* BN_to_bin(BIGNUM& n);

void XorBlocks(int size, byte* in1, byte* in2, byte* out);
bool AesCtrCrypt(int key_size_bits, byte* key, int size,
                 byte* in, byte* out);
bool KDFa(uint16_t hashAlg, string& key, string& label, string& contextU,
          string& contextV, int bits, int out_size, byte* out);
bool AesCFBEncrypt(byte* key, int in_size, byte* in, int iv_size, byte* iv,
                   int* out_size, byte* out);
bool AesCFBDecrypt(byte* key, int in_size, byte* in, int iv_size, byte* iv,
                   int* out_size, byte* out);
int SizeHash(TPM_ALG_ID hash);
#endif

