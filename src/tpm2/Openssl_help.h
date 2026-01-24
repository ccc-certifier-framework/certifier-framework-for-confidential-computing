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

#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <string>
using std::string;

void print_internal_private_key(RSA& key);

BIGNUM* bin_to_BN(int len, byte_t* buf);
string* BN_to_bin(BIGNUM& n);

void XorBlocks(int size, byte_t* in1, byte_t* in2, byte_t* out);
bool AesCtrCrypt(int key_size_bits, byte_t* key, int size,
                 byte_t* in, byte_t* out);
bool KDFa(uint16_t hashAlg, string& key, string& label, string& contextU,
          string& contextV, int bits, int out_size, byte_t* out);
bool AesCFBEncrypt(byte_t* key, int in_size, byte_t* in, int iv_size, byte_t* iv,
                   int* out_size, byte_t* out);
bool AesCFBDecrypt(byte_t* key, int in_size, byte_t* in, int iv_size, byte_t* iv,
                   int* out_size, byte_t* out);
int SizeHash(TPM_ALG_ID hash);
#endif

