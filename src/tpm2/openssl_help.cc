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
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl_help.h>

#include <string>
using std::string;

//
// Copyright 2015 Google Corporation, All Rights Reserved.
// Copyright 2025 John L Manferdelli, All Rights Reserved.
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
#define MAX_SIZE_PARAMS 4096


void print_internal_private_key(RSA& key) {
  const RSA* r = &key;
  const BIGNUM* n = RSA_get0_n(r);
  const BIGNUM* e = RSA_get0_e(r);
  const BIGNUM* d = RSA_get0_d(r);
  const BIGNUM* p = RSA_get0_p(r);
  const BIGNUM* q = RSA_get0_q(r);
  if (n != nullptr) {
    printf("\nModulus: \n");
    BN_print_fp(stdout, n);
    printf("\n");
  }
  if (e != nullptr) {
    printf("\ne: \n");
    BN_print_fp(stdout, e);
    printf("\n");
  }
  if (d != nullptr) {
    printf("\nd: \n");
    BN_print_fp(stdout, d);
    printf("\n");
  }
  if (p != nullptr) {
    printf("\np: \n");
    BN_print_fp(stdout, p);
    printf("\n");
  }
  if (q != nullptr) {
    printf("\nq: \n");
    BN_print_fp(stdout, q);
    printf("\n");
  }
#if 0
  if (key.dmp1 != nullptr) {
    printf("\ndmp1: \n");
    BN_print_fp(stdout, key.dmp1);
    printf("\n");
  }
  if (key.dmq1 != nullptr) {
    printf("\ndmq1: \n");
    BN_print_fp(stdout, key.dmq1);
    printf("\n");
  }
  if (key.iqmp != nullptr) {
    printf("\niqmp: \n");
    BN_print_fp(stdout, key.iqmp);
    printf("\n");
  }
#endif
}

BIGNUM* bin_to_BN(int len, byte_t* buf) {
  BIGNUM* bn = BN_bin2bn(buf, len, nullptr);
  return bn;
}

string* BN_to_bin(BIGNUM& n) {
  byte_t buf[MAX_SIZE_PARAMS];

  int len = BN_bn2bin(&n, buf);
  return new string((const char*)buf, len);
}

class extEntry {
public:
  char* key_;
  char* value_;

  extEntry(const char* k, const char* v);
  extEntry();
  char* getKey();
  char* getValue();
};

extEntry::extEntry(const char* k, const char* v) {
  key_ = (char*)strdup(k);
  value_ = (char*)strdup(v);
}

extEntry::extEntry() {
  key_ = nullptr;
  value_ = nullptr;
}

char* extEntry::getKey() {
  return key_;
}

char* extEntry::getValue() {
  return value_;
}

bool addExtensionsToCert(int num_entry, extEntry** entries, X509* cert) {
  // add extensions
  for (int i = 0; i < num_entry; i++) {
    int nid = OBJ_txt2nid(entries[i]->getKey());
    ASN1_OCTET_STRING* val = ASN1_OCTET_STRING_new();
    ASN1_STRING_set(val, (const void *)entries[i]->getValue(),
                    strlen(entries[i]->getValue()));
    X509_EXTENSION* ext = X509_EXTENSION_create_by_NID(NULL, nid, 0, val);
    if (ext == 0) {
      printf("Bad ext_conf %d\n", i);
      printf("ERR: %s\n", ERR_lib_error_string(ERR_get_error()));
      return false;
    }
    if (!X509_add_ext(cert, ext, -1)) {
      printf("Bad add ext %d\n", i);
      printf("ERR: %s\n", ERR_lib_error_string(ERR_get_error()));
      return false;
    }
    X509_EXTENSION_free(ext);
  }
  return true;
}

void XorBlocks(int size, byte_t* in1, byte_t* in2, byte_t* out) {
  for (int i = 0; i < size; i++)
    out[i] = in1[i] ^ in2[i];
}

bool KDFa(uint16_t hashAlg, string& key, string& label, string& contextU,
          string& contextV, int bits, int out_size, byte_t* out) {
  uint32_t len = 32;
  uint32_t counter = 0;
  int bytes_left = (bits + 7) / 8;
  byte_t* current_out = out;
  int size_buf = 0;
  byte_t buf[MAX_SIZE_PARAMS];
  int n;
  HMAC_CTX* ctx = nullptr;

  memset(buf, 0, 128);
  change_endian32(&counter, (uint32_t*)&buf[size_buf]);
  size_buf += sizeof(uint32_t);
  n = strlen(label.c_str()) + 1;
  if ((size_buf + n) > MAX_SIZE_PARAMS) return false;
  memcpy(&buf[size_buf], label.data(), n);
  size_buf += n;
  if ((size_buf + contextU.size()) > MAX_SIZE_PARAMS) return false;
  memcpy(&buf[size_buf], contextU.data(), contextU.size());
  size_buf += contextU.size();
  if ((size_buf + contextV.size()) > MAX_SIZE_PARAMS) return false;
  memcpy(&buf[size_buf], contextV.data(), contextV.size());
  size_buf += contextV.size();
  if ((size_buf + sizeof(uint32_t)) > MAX_SIZE_PARAMS) return false;
  change_endian32((uint32_t*)&bits, (uint32_t*)&buf[size_buf]);
  size_buf += sizeof(uint32_t);

  while (bytes_left > 0) {
    counter++;
    change_endian32(&counter, (uint32_t*)buf);

    if (hashAlg == TPM_ALG_SHA1 ) {
      HMAC_Init_ex(ctx, key.data(), key.size(), EVP_sha1(), nullptr);
    } else {
      HMAC_Init_ex(ctx, key.data(), key.size(), EVP_sha256(), nullptr);
    }
    HMAC_Update(ctx, buf, size_buf);
    HMAC_Final(ctx, current_out, &len);
    HMAC_CTX_free(ctx);
    current_out += len;
    bytes_left -= len;
  }
  return true;
}

bool AesCtrCrypt(int key_size_bits, byte_t* key, int size,
                 byte_t* in, byte_t* out) {
  AES_KEY ectx;
  uint64_t ctr[2] = {0ULL, 0ULL};
  byte_t block[32];

  if (key_size_bits != 128) {
    return false;
  }
  
  AES_set_encrypt_key(key, 128, &ectx);
  while (size > 0) {
    ctr[1]++;
    AES_encrypt((byte_t*)ctr, block, &ectx);
    XorBlocks(16, block, in, out);
    in += 16;
    out += 16;
    size -= 16;
  }
  return true;
}

#define AESBLKSIZE 16

bool AesCFBEncrypt(byte_t* key, int in_size, byte_t* in, int iv_size, byte_t* iv,
                   int* out_size, byte_t* out) {
  byte_t last_cipher[32];
  byte_t cipher_block[32];
  int size = 0;
  int current_size;

  AES_KEY ectx;
  AES_set_encrypt_key(key, 128, &ectx);

  // Don't write iv, called already knows it
  if(iv_size != AESBLKSIZE) return false;
  memcpy(last_cipher, iv, AESBLKSIZE);

  while (in_size > 0) {
    if ((size + AESBLKSIZE) > *out_size) return false; 
    // C[0] = IV, C[i] = P[i] ^ E(K, C[i-1])
    AES_encrypt(last_cipher, cipher_block, &ectx);
    if (in_size >= AESBLKSIZE)
      current_size = AESBLKSIZE;
    else
      current_size = in_size;
    XorBlocks(AESBLKSIZE, cipher_block, in, last_cipher);
    memcpy(out, last_cipher, current_size);
    out += current_size;
    size += current_size;
    in += current_size;
    in_size -= current_size;
  }
  *out_size = size;
  return true;
}

bool AesCFBDecrypt(byte_t* key, int in_size, byte_t* in, int iv_size, byte_t* iv,
                   int* out_size, byte_t* out) {
  byte_t last_cipher[32];
  byte_t cipher_block[32];
  int size = 0;
  int current_size;

  AES_KEY ectx;
  AES_set_encrypt_key(key, 128, &ectx);

  // Don't write iv, called already knows it
  if(iv_size != AESBLKSIZE) return false;
  memcpy(last_cipher, iv, AESBLKSIZE);

  while (in_size > 0) {
    if ((size + AESBLKSIZE) > *out_size) return false; 
    // P[i] = C[i] ^ E(K, C[i-1])
    AES_encrypt(last_cipher, cipher_block, &ectx);
    if (in_size >= AESBLKSIZE)
      current_size = AESBLKSIZE;
    else
      current_size = in_size;
    XorBlocks(current_size, cipher_block, in, out);
    memcpy(last_cipher, in, current_size);
    out += current_size;
    size += current_size;
    in += current_size;
    in_size -= current_size;
  }
  *out_size = size;
  return true;
}

int SizeHash(TPM_ALG_ID hash) {
  switch(hash) {
  case TPM_ALG_SHA1:
    return 20;
  case TPM_ALG_SHA256:
    return 32;
  default:
    return -1;
  }
}
