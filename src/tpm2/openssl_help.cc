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
#include <openssl/core_names.h>
#include <openssl/kdf.h>
#include <openssl/params.h>


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


void print_internal_private_key(RSA &key) {
  const RSA    *r = &key;
  const BIGNUM *n = RSA_get0_n(r);
  const BIGNUM *e = RSA_get0_e(r);
  const BIGNUM *d = RSA_get0_d(r);
  const BIGNUM *p = RSA_get0_p(r);
  const BIGNUM *q = RSA_get0_q(r);
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

BIGNUM *bin_to_BN(int len, byte_t *buf) {
  BIGNUM *bn = BN_bin2bn(buf, len, nullptr);
  return bn;
}

string *BN_to_bin(BIGNUM &n) {
  byte_t buf[MAX_SIZE_PARAMS];

  int len = BN_bn2bin(&n, buf);
  return new string((const char *)buf, len);
}

class extEntry {
 public:
  char *key_;
  char *value_;

  extEntry(const char *k, const char *v);
  extEntry();
  char *getKey();
  char *getValue();
};

extEntry::extEntry(const char *k, const char *v) {
  key_ = (char *)strdup(k);
  value_ = (char *)strdup(v);
}

extEntry::extEntry() {
  key_ = nullptr;
  value_ = nullptr;
}

char *extEntry::getKey() {
  return key_;
}

char *extEntry::getValue() {
  return value_;
}

bool addExtensionsToCert(int num_entry, extEntry **entries, X509 *cert) {
  // add extensions
  for (int i = 0; i < num_entry; i++) {
    int                nid = OBJ_txt2nid(entries[i]->getKey());
    ASN1_OCTET_STRING *val = ASN1_OCTET_STRING_new();
    ASN1_STRING_set(val,
                    (const void *)entries[i]->getValue(),
                    strlen(entries[i]->getValue()));
    X509_EXTENSION *ext = X509_EXTENSION_create_by_NID(NULL, nid, 0, val);
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

void XorBlocks(int size, byte_t *in1, byte_t *in2, byte_t *out) {
  for (int i = 0; i < size; i++)
    out[i] = in1[i] ^ in2[i];
}

bool kdfa(uint16_t      alg,
          const string &key,
          const string &label,
          const string &inA,
          const string &inB,
          int           num_bits,
          string       *key_out) {
  int bytes_requested = (num_bits + NBITSINBYTE - 1) / NBITSINBYTE;
  int bytes_produced = 0;

  int    max_size_in = 128;
  int    max_size_out = 128;
  int    size_in = 0;
  byte_t in[max_size_in];
  byte_t out[max_size_out];

  byte_t *current_in = in;
  byte_t *current_out = out;

  uint32_t count = 1;

  // count
  current_in += sizeof(uint32_t);
  size_in += sizeof(uint32_t);

  // label is string, include terminating null char
  if ((size_in + (int)label.size() + 1) > max_size_in) {
    printf("%s(), line %d, error, buffer overflow\n", __func__, __LINE__);
    return false;
  }
  memcpy(current_in, (byte_t *)label.data(), label.size() + 1);
  current_in += label.size() + 1;
  size_in += label.size() + 1;

  if ((size_in + (int)inA.size()) > max_size_in) {
    printf("%s(), line %d, error, buffer overflow\n", __func__, __LINE__);
    return false;
  }
  if (inA.size() > 0) {
    memcpy(current_in, (byte_t *)inA.data(), inA.size());
    current_in += inA.size();
    size_in += inA.size();
  }

  if ((size_in + (int)inB.size()) > max_size_in) {
    printf("%s(), line %d, error, buffer overflow\n", __func__, __LINE__);
    return false;
  }
  if (inB.size() > 0) {
    memcpy(current_in, (byte_t *)inB.data(), inB.size());
    current_in += inB.size();
    size_in += inB.size();
  }

  if ((size_in + (int)sizeof(uint32_t)) > max_size_in) {
    printf("%s(), line %d, error, buffer overflow\n", __func__, __LINE__);
    return false;
  }
  change_endian32((uint32_t *)&num_bits, (uint32_t *)current_in);
  current_in += sizeof(uint32_t);
  size_in += sizeof(uint32_t);

  int size_hmac = 0;
  if (alg == TPM_ALG_SHA1) {
    size_hmac = 20;
  } else if (alg == TPM_ALG_SHA256) {
    size_hmac = 32;
  } else {
    printf("%s() error, line %d, unsupported alg\n", __func__, __LINE__);
    return false;
  }

  while (bytes_produced < bytes_requested) {
    change_endian32(&count, (uint32_t *)in);

#ifdef DEBUG7
    printf("seed     (%d): ", (int)key.size());
    print_bytes(key.size(), (byte_t *)key.data());
    printf("\n");
    printf("kdfa buf (%d): ", size_in);
    print_bytes(size_in, in);
    printf("\n");
#endif

    if ((bytes_produced + size_hmac) > max_size_out) {
      printf("%s() error, line %d, buffer overflow\n", __func__, __LINE__);
      return false;
    }

    HMAC_CTX *hctx = HMAC_CTX_new();
    if (hctx == nullptr) {
      printf("%s() error, line %d, Can't allocate hmac contaxt\n",
             __func__,
             __LINE__);
      return false;
    }
    if (alg == TPM_ALG_SHA1) {
      HMAC_Init_ex(hctx, (byte_t *)key.data(), key.size(), EVP_sha1(), nullptr);
      HMAC_Update(hctx, (const byte_t *)in, (size_t)size_in);
      HMAC_Final(hctx, current_out, (unsigned *)&size_hmac);
    } else if (alg == TPM_ALG_SHA256) {
      HMAC_Init_ex(hctx,
                   (byte_t *)key.data(),
                   key.size(),
                   EVP_sha256(),
                   nullptr);
      HMAC_Update(hctx, (const byte_t *)in, (size_t)size_in);
      HMAC_Final(hctx, current_out, (unsigned *)&size_hmac);
    } else {
      printf("%s(), line %d, error, unsupported alg\n", __func__, __LINE__);
      return false;
    }
    current_out += size_hmac;
    bytes_produced += size_hmac;
    HMAC_CTX_free(hctx);

    count++;
  }

  key_out->assign((char *)out, bytes_requested);
  return true;
}


bool kdf_hkdf(uint16_t hashAlg,
              string  &salt,
              string  &ikm,
              string  &info,
              int      out_len,
              string  *key_out) {
  if (hashAlg != TPM_ALG_SHA256) {
    printf("%s() error, line %d, unsupported algorithm\n", __func__, __LINE__);
    return false;
  }
  EVP_KDF      *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
  EVP_KDF_CTX  *kctx = EVP_KDF_CTX_new(kdf);
  unsigned char out[out_len];

  OSSL_PARAM params[] = {
      OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                       (char *)"SHA256",
                                       0),
      OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                                        (byte_t *)ikm.data(),
                                        ikm.size()),
      OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                        (byte_t *)salt.data(),
                                        salt.size()),
      OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                                        (byte_t *)info.data(),
                                        info.size()),
      OSSL_PARAM_construct_end()};

  if (EVP_KDF_derive(kctx, out, sizeof(out), params) != 1) {
    return false;
  }

  EVP_KDF_CTX_free(kctx);
  EVP_KDF_free(kdf);

  key_out->assign((char *)out, out_len);
  return true;
}

bool AesCtrCrypt(int     key_size_bits,
                 byte_t *key,
                 int     size,
                 byte_t *in,
                 byte_t *out) {
  AES_KEY  ectx;
  uint64_t ctr[2] = {0ULL, 0ULL};
  byte_t   block[32];

  if (key_size_bits != 128) {
    return false;
  }

  AES_set_encrypt_key(key, 128, &ectx);
  while (size > 0) {
    ctr[1]++;
    AES_encrypt((byte_t *)ctr, block, &ectx);
    XorBlocks(16, block, in, out);
    in += 16;
    out += 16;
    size -= 16;
  }
  return true;
}

#define AESBLKSIZE 16

bool AesCFBEncrypt(int     bits_key_size,
                   byte_t *key,
                   int     in_size,
                   byte_t *in,
                   int     iv_size,
                   byte_t *iv,
                   int    *out_size,
                   byte_t *out) {
  byte_t last_cipher[32];
  byte_t cipher_block[32];
  int    size = 0;
  int    current_size;

  AES_KEY ectx;
  AES_set_encrypt_key(key, bits_key_size, &ectx);

  // Don't write iv, called already knows it
  if (iv_size != AESBLKSIZE)
    return false;
  memcpy(last_cipher, iv, AESBLKSIZE);

  while (in_size > 0) {
    if ((size + AESBLKSIZE) > *out_size)
      return false;
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

bool AesCFBDecrypt(int     bits_key_size,
                   byte_t *key,
                   int     in_size,
                   byte_t *in,
                   int     iv_size,
                   byte_t *iv,
                   int    *out_size,
                   byte_t *out) {
  byte_t last_cipher[32];
  byte_t cipher_block[32];
  int    size = 0;
  int    current_size;

  AES_KEY ectx;
  AES_set_encrypt_key(key, bits_key_size, &ectx);

  // Don't write iv, called already knows it
  if (iv_size != AESBLKSIZE)
    return false;
  memcpy(last_cipher, iv, AESBLKSIZE);

  while (in_size > 0) {
    if ((size + AESBLKSIZE) > *out_size)
      return false;
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
  switch (hash) {
    case TPM_ALG_SHA1:
      return 20;
    case TPM_ALG_SHA256:
      return 32;
    default:
      return -1;
  }
}
