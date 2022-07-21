#include "certifier.h"
#include "support.h"

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

bool test_encrypt(bool print_all) {
  const int in_size = 2 * block_size;
  const int out_size = in_size + 128;
  const char* alg_name= "aes-256-cbc-hmac-sha256";
  const int key_size = cipher_key_byte_size(alg_name);
  int blk_size =  cipher_block_byte_size(alg_name);

  byte key[key_size];
  const int iv_size = blk_size;
  byte iv[block_size];
  byte plain[in_size];
  byte cipher[out_size];
  const int decrypt_size = in_size + block_size;
  byte decrypted[decrypt_size];
  int size1 = in_size;
  int size2 = decrypt_size;

  memset(plain, 0, in_size);
  memset(cipher, 0, out_size);
  memset(key, 0, key_size);
  memset(iv, 0, iv_size);
  memset(decrypted, 0, in_size);

  for(int i = 0; i < key_size; i++)
    key[i] = (byte) (i %16); 
  for(int i = 0; i < blk_size; i++)
    iv[i] = (byte) (i %16); 
  const char* msg = "this is a message of length 32.";
  memcpy(plain, (byte*)msg, 32);

  if (print_all) {
    printf("input: "); print_bytes(in_size, plain); printf("\n");
  }
  if (!encrypt(plain, in_size, key, iv, cipher, &size1)) {
    printf("encrypt failed\n");
    return false;
  }
  if (print_all) {
    printf("encrypt succeeded, in_size: %d, out_size is %d\n", in_size, size1);
    printf("iv: "); print_bytes(block_size, iv); printf("\n");
    printf("cipher: "); print_bytes(size2, cipher); printf("\n");
  }
  if (!decrypt(cipher, size1, key, iv, decrypted, &size2)) {
    printf("decrypt failed\n");
    return false;
  }
  if (print_all) {
    printf("decrypt succeeded, out_size is %d\n", size2);
    printf("decrypted: "); print_bytes(size2, decrypted); printf("\n");
  }
  if (size2 != in_size || memcmp(plain, decrypted, in_size) != 0) {
    printf("comparison failed\n");
    return false;
  }
  return true;
}

bool test_authenticated_encrypt(bool print_all) {
  const int in_size = 2 * block_size;
  const int out_size = in_size + 256;
  const int key_size = 64;
  byte key[key_size];
  const int iv_size = block_size;
  byte iv[block_size];
  byte plain[in_size];
  byte cipher[out_size];
  int size_encrypt_out = out_size;
  int size_decrypt_out = out_size;

  const int decrypt_size = in_size + block_size;
  byte decrypted[decrypt_size];

  memset(plain, 0, in_size);
  memset(cipher, 0, out_size);
  memset(key, 0, key_size);
  memset(iv, 0, iv_size);
  memset(decrypted, 0, decrypt_size);

  for(int i = 0; i < key_size; i++)
    key[i] = (byte) (i %16); 

  for(int i = 0; i < block_size; i++)
    iv[i] = (byte) (i %16); 
  const char* msg = "this is a message of length 32.";
  memcpy(plain, (byte*)msg, 32);

  if (print_all) {
    printf("\nAuthenticated encryption\n");
    printf("input: "); print_bytes(in_size, plain); printf("\n");
  }
  if (!authenticated_encrypt(plain, in_size, key, iv, cipher, &size_encrypt_out)) {
    printf("authenticated encrypt failed\n");
    return false;
  }
  if (print_all) {
    printf("authenticated encrypt succeeded, in_size: %d, out_size is %d\n", in_size, size_encrypt_out);
    printf("iv: "); print_bytes(block_size, iv); printf("\n");
    printf("cipher: "); print_bytes(size_encrypt_out, cipher); printf("\n");
  }
  if (!authenticated_decrypt(cipher, size_encrypt_out, key,
            decrypted, &size_decrypt_out)) {
    printf("authenticated decrypt failed\n");
    return false;
  }
  if (print_all) {
    printf("authenticated decrypt succeeded, out_size is %d\n", size_decrypt_out);
    printf("decrypted: "); print_bytes(size_decrypt_out, decrypted); printf("\n");
    printf("\n");
  }
  if (size_decrypt_out != in_size || memcmp(plain, decrypted, in_size) != 0) {
    printf("comparison failed\n");
    return false;
  }
  return true;
}

bool test_public_keys(bool print_all) {
  RSA* r= RSA_new();

  if (!generate_new_rsa_key(2048, r))
    return false;

  key_message km;
  if (!RSA_to_key(r, &km))
    return false;
  if (print_all) {
    print_key((const key_message&)km);
  }

  const char* msg = "This is a message of length 32  ";
  int size_data = 32;
  byte data[size_data];
  int size_out = 512;
  byte out[size_out];
  int size_recovered = 512;
  byte recovered[size_recovered];

  memset(data, 0, size_data);
  memset(out, 0, size_out);
  memset(recovered, 0, size_recovered);
  memcpy(data, (byte*)msg, size_data);

  if (print_all) {
    printf("public to encrypt: "); print_bytes(size_data, data); printf("\n");
  }
  if (!rsa_public_encrypt(r, data, size_data, out, &size_out))
    return false;
  if (print_all) {
    printf("public encrypted: "); print_bytes(size_out, out); printf("\n");
  }
  if (!rsa_private_decrypt(r, out, size_out, recovered, &size_recovered))
    return false;
  if (print_all) {
    printf("public recovered: "); print_bytes(size_recovered, recovered); printf("\n");
  }
  RSA_free(r);
  if (memcmp(data, recovered, size_recovered) != 0)
    return false;
  return true;
}

bool test_digest(bool print_all) {
  const char* message = "1234";
  int msg_len = strlen(message);
  unsigned int size_digest = 32;
  byte digest[size_digest];

  memset(digest, 0, 32);
  if (!digest_message((const byte*) message, msg_len, digest, 32))
    return false;
  if (print_all) {
    printf("SHA-256 message: "); print_bytes(msg_len, (byte*)message); printf("\n");
    printf("SHA-256 digest : "); print_bytes(32, digest); printf("\n");
  }
  // FIX: put comparison here
  return true;
}

bool test_sign_and_verify(bool print_all) {
  RSA* r = RSA_new();

  if (!generate_new_rsa_key(2048, r)) {
    printf("generate_new_rsa_key failed\n");
    return false;
  }

  key_message km;
  if (!RSA_to_key(r, &km)) {
    printf("RSA_to_key failed\n");
    return false;
  }
  if (print_all) {
    print_key((const key_message&)km);
  }

  const char* test_message = "I am a test message, verify me";

  int sig_size = RSA_size(r);
  byte sig[sig_size];
  int recovered_size = sig_size;
  byte recovered[recovered_size];
  memset(sig, 0, sig_size);
  memset(recovered, 0, recovered_size);

  if (!rsa_sha256_sign(r, strlen(test_message), (byte*)test_message, &sig_size, sig)) {
    printf("rsa_sha256_sign failed\n");
    return false;
  }
  if (!rsa_sha256_verify(r, strlen(test_message), (byte*)test_message, sig_size, sig)) {
    printf("rsa_sha256_verify failed\n");
    return false;
  }

  RSA_free(r);
  return true;
}

bool test_key_translation(bool print_all) {
  key_message k1;

  if(!make_certifier_rsa_key(2048, &k1))
    return false;

  RSA* r2 = RSA_new();
  if(!key_to_RSA(k1, r2))
    return false;
  if (print_all) {
    int nb = RSA_bits(r2);
    printf("BITS: %d\n", nb);
  }
  key_message k2;
  RSA_to_key(r2, &k2);
  RSA_free(r2);
  if (!same_key(k1, k2))
    return false;

  key_message k3;
  if(!make_certifier_rsa_key(2048, &k3))
    return false;
  if (same_key(k1, k3))
    return false;
  return true;
}

bool test_time(bool print_all) {
  time_point t_now;
  time_point t_test;
  time_point t_later;
  string s_now;
  string s_later;
  double hours_to_add = 365.0 * 24.0;

  if (!time_now(&t_now))
    return false;
  if (!time_to_string(t_now, &s_now))
    return false;
  if (!string_to_time(s_now, &t_test))
    return false;
  if (!add_interval_to_time_point(t_now, hours_to_add, &t_later))
    return false;
  if (print_all) {
    printf("now: ");
    print_time_point(t_now);
    printf("time as string: %s\n", s_now.c_str());
    printf("recovered: ");
    print_time_point(t_test);
    printf("later: ");
    print_time_point(t_later);
  }
  return true;
}

