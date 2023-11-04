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

#include "certifier.h"
#include "support.h"

using namespace certifier::utilities;

bool test_random(bool print_all) {
  int  n = 128;
  byte out[n];

  memset(out, 0, n);
  if (!get_random(n * 8, out)) {
    printf("%s() error, line: %d, get_random failed\n", __func__, __LINE__);
    return false;
  }

  if (print_all) {
    printf("Random bytes: ");
    print_bytes(n, out);
    printf("\n");
  }
  return true;
}

bool test_encrypt(bool print_all) {
  const int   in_size = 2 * block_size;
  const int   out_size = in_size + 128;
  const char *alg_name = Enc_method_aes_256_cbc_hmac_sha256;
  const int   key_size = cipher_key_byte_size(alg_name);
  int         blk_size = cipher_block_byte_size(alg_name);

  byte      key[key_size];
  const int iv_size = blk_size;
  byte      iv[block_size];
  byte      plain[in_size];
  byte      cipher[out_size];
  const int decrypt_size = in_size + block_size;
  byte      decrypted[decrypt_size];
  int       size1 = in_size;
  int       size2 = decrypt_size;

  memset(plain, 0, in_size);
  memset(cipher, 0, out_size);
  memset(key, 0, key_size);
  memset(iv, 0, iv_size);
  memset(decrypted, 0, in_size);

  for (int i = 0; i < key_size; i++)
    key[i] = (byte)(i % 16);
  for (int i = 0; i < blk_size; i++)
    iv[i] = (byte)(i % 16);
  const char *msg = "this is a message of length 32.";
  memcpy(plain, (byte *)msg, 32);

  if (print_all) {
    printf("input: ");
    print_bytes(in_size, plain);
    printf("\n");
  }
  if (!encrypt(plain, in_size, key, iv, cipher, &size1)) {
    printf("%s() error, line: %d, encrypt failed\n", __func__, __LINE__);
    return false;
  }
  if (print_all) {
    printf("encrypt succeeded, in_size: %d, out_size is %d\n", in_size, size1);
    printf("iv: ");
    print_bytes(block_size, iv);
    printf("\n");
    printf("cipher: ");
    print_bytes(size2, cipher);
    printf("\n");
  }
  if (!decrypt(cipher, size1, key, iv, decrypted, &size2)) {
    printf("%s() error, line: %d, decrypt failed\n", __func__, __LINE__);
    return false;
  }
  if (print_all) {
    printf("decrypt succeeded, out_size is %d\n", size2);
    printf("decrypted: ");
    print_bytes(size2, decrypted);
    printf("\n");
  }
  if (size2 != in_size || memcmp(plain, decrypted, in_size) != 0) {
    printf("comparison failed\n");
    printf("%s() error, line: %d, comparison failed\n", __func__, __LINE__);
    return false;
  }
  return true;
}

bool test_authenticated_encrypt(bool print_all) {
  const int in_size = 2 * block_size;
  const int out_size = in_size + 256;
  const int key_size = 96;
  byte      key[key_size];
  const int iv_size = block_size;
  byte      iv[block_size];
  byte      plain[in_size];
  byte      cipher[out_size];
  int       size_encrypt_out = out_size;
  int       size_decrypt_out = out_size;

  const int decrypt_size = in_size + block_size;
  byte      decrypted[decrypt_size];

  memset(plain, 0, in_size);
  memset(cipher, 0, out_size);
  memset(key, 0, key_size);
  memset(iv, 0, iv_size);
  memset(decrypted, 0, decrypt_size);

  for (int i = 0; i < key_size; i++)
    key[i] = (byte)(i % 16);

  for (int i = 0; i < block_size; i++)
    iv[i] = (byte)(i % 16);
  const char *msg = "this is a message of length 32.";
  memcpy(plain, (byte *)msg, 32);

  if (print_all) {
    printf("\nAuthenticated encryption\n");
    printf("input: ");
    print_bytes(in_size, plain);
    printf("\n");
  }

  if (!authenticated_encrypt(Enc_method_aes_256_cbc_hmac_sha256,
                             plain,
                             in_size,
                             key,
                             key_size,
                             iv,
                             iv_size,
                             cipher,
                             &size_encrypt_out)) {
    printf("%s() error, line: %d, authenticated encrypt failed\n",
           __func__,
           __LINE__);
    return false;
  }
  if (print_all) {
    printf("authenticated encrypt for aes-256-cbc-hmac-sha256 succeeded, "
           "in_size: %d, out_size is %d\n",
           in_size,
           size_encrypt_out);
    printf("iv: ");
    print_bytes(block_size, iv);
    printf("\n");
    printf("cipher: ");
    print_bytes(size_encrypt_out, cipher);
    printf("\n");
  }
  if (!authenticated_decrypt(Enc_method_aes_256_cbc_hmac_sha256,
                             cipher,
                             size_encrypt_out,
                             key,
                             key_size,
                             decrypted,
                             &size_decrypt_out)) {
    printf("%s() error, line: %d, authenticated decrypt failed\n",
           __func__,
           __LINE__);
    return false;
  }

  if (print_all) {
    printf("authenticated decrypt for aes-256-cbc-hmac-sha256 succeeded, "
           "out_size is %d\n",
           size_decrypt_out);
    printf("decrypted: ");
    print_bytes(size_decrypt_out, decrypted);
    printf("\n");
    printf("\n");
  }
  if (size_decrypt_out != in_size || memcmp(plain, decrypted, in_size) != 0) {
    printf("%s() error, line: %d, comparisonfailed\n", __func__, __LINE__);
    return false;
  }

  size_encrypt_out = out_size;
  size_decrypt_out = out_size;
  int size_in = 32;
  if (print_all) {
    printf("\nAuthenticated encryption\n");
    printf("input: ");
    print_bytes(in_size, plain);
    printf("\n");
  }

  if (!authenticated_encrypt(Enc_method_aes_256_cbc_hmac_sha384,
                             plain,
                             in_size,
                             key,
                             key_size,
                             iv,
                             iv_size,
                             cipher,
                             &size_encrypt_out)) {
    printf("%s() error, line: %d, authenticated encrypt failed\n",
           __func__,
           __LINE__);
    return false;
  }
  if (print_all) {
    printf("authenticated encrypt for aes-256-cbc-hmac-sha384 succeeded, "
           "in_size: %d, out_size is %d\n",
           in_size,
           size_encrypt_out);
    printf("iv: ");
    print_bytes(block_size, iv);
    printf("\n");
    printf("cipher: ");
    print_bytes(size_encrypt_out, cipher);
    printf("\n");
  }
  if (!authenticated_decrypt(Enc_method_aes_256_cbc_hmac_sha384,
                             cipher,
                             size_encrypt_out,
                             key,
                             key_size,
                             decrypted,
                             &size_decrypt_out)) {
    printf("%s() error, line: %d, authenticated decrypt failed\n",
           __func__,
           __LINE__);
    return false;
  }

  if (print_all) {
    printf("authenticated decrypt for aes-256-cbc-hmac-sha384 succeeded, "
           "out_size is %d\n",
           size_decrypt_out);
    printf("decrypted: ");
    print_bytes(size_decrypt_out, decrypted);
    printf("\n");
    printf("\n");
  }
  if (size_decrypt_out != size_in || memcmp(plain, decrypted, size_in) != 0) {
    printf("%s() error, line: %d, plaintext and decrypted text are different\n",
           __func__,
           __LINE__);
    return false;
  }

  size_encrypt_out = out_size;
  size_decrypt_out = out_size;

  if (!authenticated_encrypt(Enc_method_aes_256_gcm,
                             plain,
                             in_size,
                             key,
                             key_size,
                             iv,
                             iv_size,
                             cipher,
                             &size_encrypt_out)) {
    printf("%s() error, line: %d, authenticated_encrypt() for aes-256-gcm "
           "encrypt failed\n",
           __func__,
           __LINE__);
    return false;
  }
  if (print_all) {
    printf("authenticated encrypt for aes-256-gcm succeeded, in_size: %d, "
           "out_size is %d\n",
           in_size,
           size_encrypt_out);
    printf("iv: ");
    print_bytes(block_size, iv);
    printf("\n");
    printf("cipher: ");
    print_bytes(size_encrypt_out, cipher);
    printf("\n");
  }
  if (!authenticated_decrypt(Enc_method_aes_256_gcm,
                             cipher,
                             size_encrypt_out,
                             key,
                             key_size,
                             decrypted,
                             &size_decrypt_out)) {
    printf(
        "%s() error, line: %d, authenticated for aes-256-gcm decrypt failed\n",
        __func__,
        __LINE__);
    return false;
  }

  if (print_all) {
    printf("authenticated decrypt for aes-256-gcm succeeded, out_size is %d\n",
           size_decrypt_out);
    printf("decrypted: ");
    print_bytes(size_decrypt_out, decrypted);
    printf("\n");
    printf("\n");
  }
  if (size_decrypt_out != size_in || memcmp(plain, decrypted, size_in) != 0) {
    printf("%s() error, line: %d, comparison failed\n", __func__, __LINE__);
    return false;
  }

  return true;
}

bool test_public_keys(bool print_all) {

  RSA *r1 = RSA_new();

  if (!generate_new_rsa_key(2048, r1)) {
    printf("%s() error, line: %d, generate_new_rsa_key failed\n",
           __func__,
           __LINE__);
    return false;
  }

  key_message km1;
  if (!RSA_to_key(r1, &km1)) {
    printf("%s() error, line: %d, RSA_to_key failed\n", __func__, __LINE__);
    return false;
  }
  if (print_all) {
    print_key((const key_message &)km1);
  }

  const char *msg = "This is a message of length 32  ";
  int         size_data = 32;
  byte        data[size_data];
  int         size_out = 2048;
  byte        out[size_out];
  int         size_recovered = 2048;
  byte        recovered[size_recovered];

  memset(data, 0, size_data);
  memset(out, 0, size_out);
  memset(recovered, 0, size_recovered);
  memcpy(data, (byte *)msg, size_data);

  if (print_all) {
    printf("public to encrypt: ");
    print_bytes(size_data, data);
    printf("\n");
  }
  if (!rsa_public_encrypt(r1, data, size_data, out, &size_out)) {
    printf("%s() error, line: %d, rsa_public_encrypt failed\n",
           __func__,
           __LINE__);
    return false;
  }
  if (print_all) {
    printf("public encrypted: ");
    print_bytes(size_out, out);
    printf("\n");
  }
  if (!rsa_private_decrypt(r1, out, size_out, recovered, &size_recovered)) {
    printf("%s() error, line: %d, rsa_private_decrypt failed\n",
           __func__,
           __LINE__);
    return false;
  }
  if (print_all) {
    printf("public recovered: ");
    print_bytes(size_recovered, recovered);
    printf("\n");
  }
  RSA_free(r1);
  if (memcmp(data, recovered, size_recovered) != 0) {
    printf("%s() error, line: %d, memcmpfailed\n", __func__, __LINE__);
    return false;
  }

  RSA *r2 = RSA_new();
  if (!generate_new_rsa_key(4096, r2)) {
    printf("%s() error, line: %d, generate_new_rsa_key failed\n",
           __func__,
           __LINE__);
    return false;
  }

  size_out = 2048;
  size_recovered = 2048;
  key_message km2;
  if (!RSA_to_key(r2, &km2)) {
    printf("RSA_to_key failed\n");
    return false;
  }
  if (print_all) {
    printf("\n");
    print_key((const key_message &)km2);
  }

  memset(data, 0, size_data);
  memset(out, 0, size_out);
  memset(recovered, 0, size_recovered);
  memcpy(data, (byte *)msg, size_data);

  if (print_all) {
    printf("public to encrypt: ");
    print_bytes(size_data, data);
    printf("\n");
  }
  if (!rsa_public_encrypt(r2, data, size_data, out, &size_out)) {
    printf("%s() error, line: %d, rsa_public_encrypt failed\n",
           __func__,
           __LINE__);
    return false;
  }
  if (print_all) {
    printf("public encrypted: ");
    print_bytes(size_out, out);
    printf("\n");
  }
  if (!rsa_private_decrypt(r2, out, size_out, recovered, &size_recovered)) {
    printf("%s() error, line: %d, rsa_private_decrypt failed\n",
           __func__,
           __LINE__);
    return false;
  }
  if (print_all) {
    printf("public recovered: ");
    print_bytes(size_recovered, recovered);
    printf("\n");
  }
  RSA_free(r2);
  if (memcmp(data, recovered, size_recovered) != 0) {
    printf("%s() error, line: %d, memcmp failed\n", __func__, __LINE__);
    return false;
  }

  // ECC
  size_out = 2048;
  size_recovered = 2048;
  EC_KEY *ecc_key = generate_new_ecc_key(384);
  if (ecc_key == nullptr) {
    printf("%s() error, line: %d, Can't generate new ecc key failed\n",
           __func__,
           __LINE__);
    return false;
  }
  key_message km3;
  if (!ECC_to_key(ecc_key, &km3)) {
    printf("%s() error, line: %d, ECC_to_key failed\n", __func__, __LINE__);
    return false;
  }
  if (print_all) {
    printf("\n");
    print_key((const key_message &)km3);
  }
  if (print_all) {
    printf("public to encrypt: ");
    print_bytes(size_data, data);
    printf("\n");
  }
  if (!ecc_sign(Digest_method_sha_384,
                ecc_key,
                size_data,
                data,
                &size_out,
                out)) {
    printf("ecc_sign failed\n");
    printf("Sig size: %d\n", size_out);
    return false;
  }
  if (print_all) {
    printf("ecc sign out    : ");
    print_bytes(size_out, out);
    printf("\n");
  }
  if (!ecc_verify(Digest_method_sha_384,
                  ecc_key,
                  size_data,
                  data,
                  size_out,
                  out)) {
    printf("%s() error, line: %d, ecc verify failed\n", __func__, __LINE__);
    return false;
  }

  key_message priv_km;
  key_message pub_km;
  if (!ECC_to_key(ecc_key, &priv_km)) {
    printf("%s() error, line: %d, ECC_to_key failed\n", __func__, __LINE__);
    return false;
  }

  priv_km.set_key_name("test-key");
  priv_km.set_key_type(Enc_method_ecc_384_private);
  if (print_all) {
    printf("Key:\n");
    print_key(priv_km);
    printf("\n");
  }

  if (!private_key_to_public_key(priv_km, &pub_km)) {
    printf("%s() error, line: %d, ECC private_key_to_public_key failed\n",
           __func__,
           __LINE__);
    return false;
  }

  if (print_all) {
    printf("Key:\n");
    print_key(pub_km);
    printf("\n");

    printf("Descriptor: ");
    print_key_descriptor(pub_km);
    printf("\n");
  }

  EC_KEY_free(ecc_key);

  size_out = 2048;
  size_recovered = 2048;
  memset(data, 0, size_data);
  memset(out, 0, size_out);
  memset(recovered, 0, size_recovered);
  memcpy(data, (byte *)msg, size_data);

  EC_KEY *ecc_key2 = generate_new_ecc_key(256);
  if (ecc_key2 == nullptr) {
    printf("%s() error, line: %d, Can't generate new ecc key\n",
           __func__,
           __LINE__);
    return false;
  }
  key_message km4;
  if (!ECC_to_key(ecc_key2, &km4)) {
    printf("Can't ECC to key\n");
    return false;
  }
  if (print_all) {
    printf("\n");
    print_key((const key_message &)km4);
  }

  if (print_all) {
    printf("public to encrypt: ");
    print_bytes(size_data, data);
    printf("\n");
  }
  if (!ecc_sign(Digest_method_sha_256,
                ecc_key2,
                size_data,
                data,
                &size_out,
                out)) {
    printf("%s() error, line: %d, ecc_sign failed, size: %d\n",
           __func__,
           __LINE__,
           size_out);
    return false;
  }
  if (print_all) {
    printf("ecc sign out %d : ", size_out);
    print_bytes(size_out, out);
    printf("\n");
  }
#if 1
  // TODO: sometimes this faults
  if (!ecc_verify(Digest_method_sha_256,
                  ecc_key,
                  size_data,
                  data,
                  size_out,
                  out)) {
    printf("%s() error, line: %d, ecc_verify failed\n", __func__, __LINE__);
    return false;
  }
#endif

  key_message priv_km2;
  key_message pub_km2;
  if (!ECC_to_key(ecc_key2, &priv_km2)) {
    printf("%s() error, line: %d, ECC_to_key failed\n", __func__, __LINE__);
    return false;
  }

  priv_km2.set_key_name("test-key");
  priv_km2.set_key_type(Enc_method_ecc_256_private);
  if (print_all) {
    printf("Key:\n");
    print_key(priv_km2);
    printf("\n");
  }

  if (!private_key_to_public_key(priv_km2, &pub_km2)) {
    printf("%s() error, line: %d, ECC private_key_to_public_key failed\n",
           __func__,
           __LINE__);
    return false;
  }

  if (print_all) {
    printf("Key:\n");
    print_key(pub_km2);
    printf("\n");

    printf("Descriptor: ");
    print_key_descriptor(pub_km2);
    printf("\n");
  }

  EC_KEY_free(ecc_key2);
  return true;
}

//  Test vectors
//    Input: "abc"
//    sha256: ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61
//    f20015ad sha384: cb00753f45a35e8b b5a03d699ac65007 272c32ab0eded163
//    1a8b605a43ff5bed
//            8086072ba1e7cc23 58baeca134c825a7
//    sha512: ddaf35a193617aba cc417349ae204131 12e6fa4e89a97ea2
//    0a9eeee64b55d39a
//            2192992a274fc1a8 36ba3c23a3feebbd 454d4423643ce80e
//            2a9ac94fa54ca49f

byte sha256_test[32] = {0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
                        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
                        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
                        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};

byte sha384_test[48] = {
    0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b, 0xb5, 0xa0, 0x3d, 0x69,
    0x9a, 0xc6, 0x50, 0x07, 0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63,
    0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff, 0x5b, 0xed, 0x80, 0x86, 0x07, 0x2b,
    0xa1, 0xe7, 0xcc, 0x23, 0x58, 0xba, 0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7};

byte sha512_test[64] = {
    0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73,
    0x49, 0xae, 0x20, 0x41, 0x31, 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9,
    0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a, 0x21,
    0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba, 0x3c, 0x23,
    0xa3, 0xfe, 0xeb, 0xbd, 0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8,
    0x0e, 0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f};

bool test_digest(bool print_all) {
  const char * message = "1234";
  int          msg_len = strlen(message);
  unsigned int size_digest = 64;
  byte         digest[size_digest];

  memset(digest, 0, size_digest);
  if (!digest_message(Digest_method_sha_256,
                      (const byte *)message,
                      msg_len,
                      digest,
                      size_digest)) {
    printf("%s() error, line: %d, digest failed, %d\n",
           __func__,
           __LINE__,
           size_digest);
    return false;
  }
  if (print_all) {
    printf("SHA-256 message: ");
    print_bytes(msg_len, (byte *)message);
    printf("\n");
    printf("SHA-256 digest : ");
    print_bytes(32, digest);
    printf("\n");
  }

  // Verifier outputs
  const char *message2 = "abc";
  msg_len = 3;

  size_digest = (unsigned int)digest_output_byte_size(Digest_method_sha256);
  if (size_digest < 0) {
    printf("%s() error, line: %d, digest size failed, %d\n",
           __func__,
           __LINE__,
           size_digest);
    return false;
  }
  memset(digest, 0, size_digest);
  if (!digest_message(Digest_method_sha_256,
                      (const byte *)message2,
                      msg_len,
                      digest,
                      size_digest)) {
    printf("%s() error, line: %d, digest_message() failed\n",
           __func__,
           __LINE__);
    return false;
  }
  if (print_all) {
    printf("\nSHA-256 message: ");
    print_bytes(msg_len, (byte *)message2);
    printf("\n");
    printf("SHA-256 digest : ");
    print_bytes((int)size_digest, digest);
    printf("\n");
  }
  if (memcmp(digest, sha256_test, size_digest) != 0) {
    printf("%s() error, line: %d, test digest doesn't match\n",
           __func__,
           __LINE__);
    return false;
  }

  size_digest = (unsigned int)digest_output_byte_size(Digest_method_sha_384);
  if (size_digest < 0) {
    printf("%s() error, line: %d, digest_message failed\n", __func__, __LINE__);
    return false;
  }
  memset(digest, 0, size_digest);
  if (!digest_message(Digest_method_sha_384,
                      (const byte *)message2,
                      msg_len,
                      digest,
                      size_digest)) {
    printf("%s() error, line: %d, digest_message failed\n", __func__, __LINE__);
    return false;
  }
  if (print_all) {
    printf("SHA-384 message: ");
    print_bytes(msg_len, (byte *)message2);
    printf("\n");
    printf("SHA-384 digest : ");
    print_bytes((int)size_digest, digest);
    printf("\n");
  }
  if (memcmp(digest, sha384_test, size_digest) != 0) {
    printf("%s() error, line: %d, memcmp failed\n", __func__, __LINE__);
    return false;
  }

  size_digest = (unsigned int)digest_output_byte_size(Digest_method_sha_512);
  if (size_digest < 0) {
    printf("%s() error, line: %d, digest_message failed\n", __func__, __LINE__);
    return false;
  }
  memset(digest, 0, size_digest);
  if (!digest_message(Digest_method_sha_512,
                      (const byte *)message2,
                      msg_len,
                      digest,
                      size_digest)) {
    printf("%s() error, line: %d, digest_message failed\n", __func__, __LINE__);
    return false;
  }
  if (print_all) {
    printf("SHA-512 message: ");
    print_bytes(msg_len, (byte *)message2);
    printf("\n");
    printf("SHA-512 digest : ");
    print_bytes((int)size_digest, digest);
    printf("\n");
  }
  if (memcmp(digest, sha512_test, size_digest) != 0) {
    printf("%s() error, line: %d, memcmp failed\n", __func__, __LINE__);
    return false;
  }

  return true;
}

#define NUM_TEST_FILES_TO_DIGEST 4

/*
 * test_digest_multiple() - Similar to test_digest()
 *
 * Here we do a simple verification whether the hash-digest produced by
 * digest_message() is the same if you read-in all input files once
 * v/s if you read-on each file one-at-a-time and make multiple calls
 * to digest_message(). Using digest_message(), which is a wrapper around
 * underlying EVP_Digest*() interfaces, is not additive. This test checks
 * that the resultant digest is different between the two schemes.
 */
bool test_digest_multiple(bool print_all) {
  // This test-case will be invoked by ./certifier_tests.exe from the src/
  // dir. Create a list of files to build the hash digest for verification.
  const char *files_list[] = {"./certifier_tests.exe",
                              "./support_tests.cc",
                              "../libcertifier_framework.so",
                              "../certifier_framework.py"};
  int         files_size[NUM_TEST_FILES_TO_DIGEST] = {0};

  // Read-in other files to capture each file's size
  int         max_file_size = 0;
  int         all_files_total_size = 0;
  const char *filename = nullptr;
  for (int i = 0; i < NUM_TEST_FILES_TO_DIGEST; i++) {
    filename = files_list[i];
    int this_files_size = file_size(filename);
    if (this_files_size < 0) {
      printf("Error: Input file '%s' not found.\n", filename);
      return false;
    }
    files_size[i] = this_files_size;
    if (max_file_size < this_files_size) {
      max_file_size = this_files_size;
    }
    all_files_total_size += this_files_size;
  }

  byte *to_hash_single = (byte *)malloc(max_file_size);
  if (to_hash_single == nullptr) {
    printf("Error: Cannot malloc %d bytes for to_hash_single[]\n",
           max_file_size);
    return false;
  }

  const int sha256_size = 32;

  byte digest_updated[sha256_size];
  memset(digest_updated, 0, sizeof(digest_updated));

  // Compute the aggregated hash digest, one file-at-a-time.
  for (int i = 0; i < NUM_TEST_FILES_TO_DIGEST; i++) {
    filename = files_list[i];
    if (!read_file(filename, &files_size[i], to_hash_single)) {
      free(to_hash_single);
      printf("Error: Cannot read file '%s'\n", filename);
      return false;
    }
    if (print_all) {
      printf("Read file: '%s', size=%d\n", filename, files_size[i]);
    }
    // Update digest-hash across each file
    if (!digest_message(Digest_method_sha256,
                        to_hash_single,
                        files_size[i],
                        digest_updated,
                        sizeof(digest_updated))) {
      free(to_hash_single);
      printf("Error: digest_message() failed on file '%s'\n", filename);
      return false;
    }
    printf("Digest after file %d    : ", i);
    print_bytes(sizeof(digest_updated), digest_updated);
    printf("\n");
  }
  free(to_hash_single);

  byte *to_hash_multiple = (byte *)malloc(all_files_total_size);
  if (to_hash_multiple == nullptr) {
    printf("Error: Cannot malloc %d bytes for to_hash_multiple[]\n",
           all_files_total_size);
    return false;
  }
  byte *to_hash_mult_start = to_hash_multiple;
  if (print_all) {
    printf("Allocated to_hash_mult_start[] of size=%d bytes.\n",
           all_files_total_size);
  }

  // Read-in all files, adjacent to each other, into to_hash_multiple[]
  for (int i = 0; i < NUM_TEST_FILES_TO_DIGEST; i++) {
    filename = files_list[i];
    if (!read_file(filename, &files_size[i], to_hash_multiple)) {
      free(to_hash_mult_start);
      printf("Error: Cannot read file '%s'\n", filename);
      return false;
    }
    if (print_all) {
      printf("Read file: '%s', size=%d to_hash_multiple=%p\n",
             filename,
             files_size[i],
             to_hash_multiple);
    }
    to_hash_multiple += files_size[i];
  }

  // Compute hash of all files read-in and hashed at once
  byte digest_multiple[sha256_size];
  memset(digest_multiple, 0, sizeof(digest_multiple));

  // Update digest-hash across all the files, combined ...
  if (!digest_message(Digest_method_sha256,
                      to_hash_mult_start,
                      all_files_total_size,
                      digest_multiple,
                      sizeof(digest_multiple))) {
    free(to_hash_mult_start);
    printf("Error: digest_message() failed on all files\n");
    return false;
  }
  free(to_hash_mult_start);
  printf("Digest after all files : ");
  print_bytes(sizeof(digest_multiple), digest_multiple);
  printf("\n");

  return memcmp(digest_multiple, digest_updated, sizeof(digest_updated)) == 0;
}

bool test_sign_and_verify(bool print_all) {
  RSA *r = RSA_new();

  if (!generate_new_rsa_key(2048, r)) {
    printf("%s() error, line: %d, generate_new_rsa_key failed\n",
           __func__,
           __LINE__);
    return false;
  }

  key_message km;
  if (!RSA_to_key(r, &km)) {
    printf("%s() error, line: %d, RSA_to_key failed\n", __func__, __LINE__);
    return false;
  }
  if (print_all) {
    print_key((const key_message &)km);
  }

  const char *test_message = "I am a test message, verify me";

  int  sig_size = RSA_size(r);
  byte sig[sig_size];
  int  recovered_size = sig_size;
  byte recovered[recovered_size];
  memset(sig, 0, sig_size);
  memset(recovered, 0, recovered_size);

  if (!rsa_sha256_sign(r,
                       strlen(test_message),
                       (byte *)test_message,
                       &sig_size,
                       sig)) {
    printf("%s() error, line: %d, rsa_sha256_sign failed\n",
           __func__,
           __LINE__);
    return false;
  }
  if (!rsa_sha256_verify(r,
                         strlen(test_message),
                         (byte *)test_message,
                         sig_size,
                         sig)) {
    printf("%s() error, line: %d, rsa_sha256_verify failed\n",
           __func__,
           __LINE__);
    return false;
  }

  RSA_free(r);
  return true;
}

bool test_key_translation(bool print_all) {
  key_message k1;

  if (!make_certifier_rsa_key(2048, &k1)) {
    printf("%s() error, line: %d, make_certifier_rsa_key failed\n",
           __func__,
           __LINE__);
    return false;
  }

  RSA *r2 = RSA_new();
  if (!key_to_RSA(k1, r2)) {
    printf("%s() error, line: %d, key_to_RSA failed\n", __func__, __LINE__);
    return false;
  }
  if (print_all) {
    int nb = RSA_bits(r2);
    printf("BITS: %d\n", nb);
  }
  key_message k2;
  RSA_to_key(r2, &k2);
  RSA_free(r2);
  if (!same_key(k1, k2)) {
    printf("%s() error, line: %d, same_key failed\n", __func__, __LINE__);
    return false;
  }

  key_message k3;
  if (!make_certifier_rsa_key(2048, &k3)) {
    printf("%s() error, line: %d, make_certifier_rsa_key failed\n",
           __func__,
           __LINE__);
    return false;
  }
  if (same_key(k1, k3)) {
    printf("%s() error, line: %d, same_key failed\n", __func__, __LINE__);
    return false;
  }
  return true;
}

bool test_time(bool print_all) {
  time_point t_now;
  time_point t_test;
  time_point t_later;
  string     s_now;
  string     s_later;
  double     hours_to_add = 365.0 * 24.0;

  if (!time_now(&t_now)) {
    printf("%s() error, line: %d, time_now failed\n", __func__, __LINE__);
    return false;
  }
  if (!time_to_string(t_now, &s_now)) {
    printf("%s() error, line: %d, time_to_string failed\n", __func__, __LINE__);
    return false;
  }
  if (!string_to_time(s_now, &t_test)) {
    printf("%s() error, line: %d, string_to_time failed\n", __func__, __LINE__);
    return false;
  }
  if (!add_interval_to_time_point(t_now, hours_to_add, &t_later)) {
    printf("%s() error, line: %d, add_interval_to_time_point failed\n",
           __func__,
           __LINE__);
    return false;
  }
  if (print_all) {
    printf("now: ");
    print_time_point(t_now);
    printf("time as string: %s\n", s_now.c_str());
    printf("recovered: ");
    print_time_point(t_test);
    printf("later: ");
    print_time_point(t_later);
  }

  time_t     now;
  struct tm  tm_time;
  time_point tp;

  time(&now);
  if (!time_t_to_tm_time(&now, &tm_time)) {
    printf("%s() error, line: %d, time_t_to_tm_time failed\n",
           __func__,
           __LINE__);
    return false;
  }
  if (!tm_time_to_time_point(&tm_time, &tp)) {
    printf("%s() error, line: %d, tm_time_to_time_point failed\n",
           __func__,
           __LINE__);
    return false;
  }

  if (print_all) {
    printf("Current time: ");
    print_time_point(tp);
    printf("\n");
  }
  return true;
}
