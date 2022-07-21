#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/x509v3.h>

#include "support.h" 
#include "certifier.pb.h" 

#include <string>
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


class name_size {
public:
  const char* name_;
  int size_;
};

name_size cipher_block_byte_name_size[] = {
  {"aes-256", 16},
  {"aes-256-cbc-hmac-sha256", 16},
  {"aes-128", 16},
  {"aes-128-cbc-hmac-sha256", 16},
  {"rsa-2048-sha256-pkcs-sign", 256},
  {"rsa-2048", 256},
  {"rsa-1024-sha256-pkcs-sign", 128},
  {"rsa-1024", 128},
  {"rsa-1024-private", 128},
  {"rsa-1024-public", 128},
  {"rsa-2048-private", 256},
  {"rsa-2048-public", 256},
};

name_size cipher_key_byte_name_size[] = {
  {"aes-256", 32},
  {"aes-256-cbc-hmac-sha256", 64},
  {"rsa-2048-sha256-pkcs-sign", 256},
  {"rsa-2048", 256},
  {"rsa-1024-sha256-pkcs-sign", 128},
  {"rsa-1024", 128},
  {"rsa-2048-private", 256},
  {"rsa-2048-public", 256},
  {"rsa-1024-private", 128},
  {"rsa-1024-public", 128},
};

name_size digest_byte_name_size[] = {
  {"sha-256", 32},
  {"sha256", 32},
};

name_size mac_byte_name_size[] = {
  {"hmac-sha256", 32},
  {"aes-256-cbc-hmac-sha256", 32},
};

int cipher_block_byte_size(const char* alg_name) {
  int size = sizeof(cipher_block_byte_name_size) / sizeof(cipher_block_byte_name_size[0]);

  for (int i = 0; i < size; i++) {
    if (strcmp(alg_name, cipher_block_byte_name_size[i].name_) == 0)
      return cipher_block_byte_name_size[i].size_;
  }
  return -1;
}

int cipher_key_byte_size(const char* alg_name) {
  int size = sizeof(cipher_key_byte_name_size) / sizeof(cipher_key_byte_name_size[0]);

  for (int i = 0; i < size; i++) {
    if (strcmp(alg_name, cipher_key_byte_name_size[i].name_) == 0)
      return cipher_key_byte_name_size[i].size_;
  }
  return -1;
}

int digest_output_byte_size(const char* alg_name) {
  int size = sizeof(digest_byte_name_size) / sizeof(digest_byte_name_size[0]);

  for (int i = 0; i < size; i++) {
    if (strcmp(alg_name, digest_byte_name_size[i].name_) == 0)
      return digest_byte_name_size[i].size_;
  }
  return -1;
}

int mac_output_byte_size(const char* alg_name) {
  int size = sizeof(mac_byte_name_size) / sizeof(mac_byte_name_size[0]);

  for (int i = 0; i < size; i++) {
    if (strcmp(alg_name, mac_byte_name_size[i].name_) == 0)
      return mac_byte_name_size[i].size_;
  }
  return -1;
}

bool write_file(string& file_name, int size, byte* data) {
  int out = open(file_name.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0644);
  if (out < 0)
    return false;
  write(out, data, size);
  close(out);
  return true;
}

int file_size(string& file_name) {
  struct stat file_info;

  if (stat(file_name.c_str(), &file_info) != 0)
    return false;
  if (!S_ISREG(file_info.st_mode))
    return false;
  return (int)file_info.st_size;
}

bool read_file(string& file_name, int* size, byte* data) {
  struct stat file_info;

  if (stat(file_name.c_str(), &file_info) != 0)
    return false;
  if (!S_ISREG(file_info.st_mode))
    return false;
  int bytes_in_file = (int)file_info.st_size;
  if (bytes_in_file > *size) {
    return false;
  }
  int fd = ::open(file_name.c_str(), O_RDONLY);
  if (fd < 0)
    return false;
  int n = (int)read(fd, data, bytes_in_file);
  close(fd);
  *size = n;
  return true;
}

bool time_now(time_point* t) {
  time_t now;
  struct tm current_time;

  time(&now);
  gmtime_r(&now, &current_time);
  t->set_year(current_time.tm_year + 1900);
  t->set_month(current_time.tm_mon + 1);
  t->set_day(current_time.tm_mday);
  t->set_hour(current_time.tm_hour);
  t->set_minute(current_time.tm_min);
  t->set_seconds(current_time.tm_sec);
  return true;
}

bool time_to_string(time_point& t, string* s) {
  char t_buf[128];

  // YYYY-MM-DDTHH:mm:ss.sssZ
  int n = sprintf(t_buf, "%04d-%02d-%02dT%02d:%02d:%8.5lfZ",
      t.year(), t.month(),t.day(),
      t.hour(), t.minute(), t.seconds());
  s->assign((const char*)t_buf);
  return true;
}

bool string_to_time(const string& s, time_point* t) {
  int y, m, d, h, min;
  double secs;
  sscanf(s.c_str(), "%04d-%02d-%02dT%02d:%02d:%lfZ",
      &y, &m, &d, &h, &min, &secs);
  t->set_year(y);
  t->set_month(m);
  t->set_day(d);
  t->set_hour(h);
  t->set_minute(min);
  t->set_seconds(secs);
  return true;
}

// 1 if t1 > t2
// 0 if t1 == t2
// -1 if t1 < t2
int compare_time(time_point& t1, time_point& t2) {
  if (t1.year() > t2.year())
    return 1;
  if (t1.year() < t2.year())
    return -1;
  if (t1.month() > t2.month())
    return 1;
  if (t1.month() < t2.month())
    return -1;
  if (t1.day() > t2.day())
    return 1;
  if (t1.day() < t2.day())
    return -1;
  if (t1.hour() > t2.hour())
    return 1;
  if (t1.hour() < t2.hour())
    return -1;
  if (t1.minute() > t2.minute())
    return 1;
  if (t1.minute() < t2.minute())
    return -1;
  if (t1.seconds() > t2.seconds())
    return 1;
  if (t1.seconds() < t2.seconds())
    return -1;
  return 0;
}

bool add_interval_to_time_point(time_point& t_in, double hours, time_point* t_out) {
  int y, m, d, h, min;
  double secs;

  y = t_in.year();
  m = t_in.month();
  d = t_in.day();
  h = t_in.hour();
  min = t_in.minute();
  secs = t_in.seconds();

  int y_add = hours / (24.0 * 365.0);
  hours -= ((double)y_add) * 24.0 * 365.0;
  int m_add = hours / (24.0 * 30);
  hours -= ((double)m_add) * 24.0 * 30.0;
  int d_add = hours / 24.0;
  hours -= ((double)d_add) * 24.0;
  int h_add = hours;
  hours -= ((double)h_add);
  int min_add = hours * 60.0;
  hours -= ((double)min_add) * 60.0;
  // hours is now seconds to add

  y += y_add;
  m += m_add;
  d += d_add;
  h += h_add;
  min += min_add;
  secs += hours;
  int n;

  if (secs > 60.0) {
    n = secs / 60.0;
    min += n;
    secs -= ((double)n) * 60.0;
  }
  if (min > 60) {
    n = min / 60;
    h += n;
    h -= n;
  }
  if (h > 24) {
    n = h / 24;
    d += n;
    h -= n;
  }
  if (d > 28) {
    switch(d) {
      case 2:
        if (y%4 == 0) {
          if (d <= 29)
            break;
          d -= 29;
          m += 1;
          break;
        }
        break;
        if (d <= 28) 
          break;
        d -= 28;
        m += 1;
        break;
      case 4:
      case 6:
      case 11:
        if (d <= 30)
          break;
        d -= 30;
        m += 1;
        break;
      default:
        if (d <= 31)
          break;
        d -= 31;
        m += 1;
        break;
    }
  }
  if (m > 12) {
    m = 1;
    y += 1;
  }

  t_out->set_year(y);
  t_out->set_month(m);
  t_out->set_day(d);
  t_out->set_hour(h);
  t_out->set_minute(min);
  t_out->set_seconds(secs);
  return true;
}

void print_time_point(time_point& t) {
  printf("%02d-%02d-%02dT%02d:%02d:%8.5lfZ\n", t.year(), t.month(),
    t.day(), t.hour(), t.minute(), t.seconds());
}

// Encryption is ssl
//    Set up a context
//    Initialize the encryption operation
//    Providing plaintext bytes to be encrypted
//    Finalising the encryption operation
//    During initialisation we will provide an EVP_CIPHER object.
//      In this case we are using EVP_aes_256_cbc(),
//      which uses the AES algorithm with a 256-bit key in 
//      CBC mode.

bool encrypt(byte* in, int in_len, byte *key,
            byte *iv, byte *out, int* out_size) {
  EVP_CIPHER_CTX *ctx = nullptr;
  int len = 0;
  int out_len = 0;
  bool ret = true;

  if(!(ctx = EVP_CIPHER_CTX_new())) {
      ret = false;
      goto done;
    }
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
      ret = false;
      goto done;
    }
  if(1 != EVP_EncryptUpdate(ctx, out, &len, in, in_len)) {
      ret = false;
      goto done;
    }
  out_len = len;
  if(1 != EVP_EncryptFinal_ex(ctx, out + len, &len)) {
      ret = false;
      goto done;
    }
  out_len += len;

done:
  if (ctx != nullptr)
    EVP_CIPHER_CTX_free(ctx);
  *out_size = out_len;
  return ret;
}

bool decrypt(byte *in, int in_len, byte *key,
            byte *iv, byte *out, int* size_out) {
    EVP_CIPHER_CTX *ctx = nullptr;
    int len = 0;
    int out_len = 0;
    bool ret = true;

    if(!(ctx = EVP_CIPHER_CTX_new())) {
      ret = false;
      goto done;
    }
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
      ret = false;
      goto done;
    }
    if(1 != EVP_DecryptUpdate(ctx, out, &len, in, in_len)) {
      ret = false;
      goto done;
    }
    out_len = len;
    if(1 != EVP_DecryptFinal_ex(ctx, out + len, &len)) {
      ret = false;
      goto done;
    }
    out_len += len;

done:
    if (ctx != nullptr)
      EVP_CIPHER_CTX_free(ctx);
    *size_out = out_len; 
    return ret;
}

bool digest_message(const byte* message, int message_len,
    byte* digest, unsigned int digest_len) {
  EVP_MD_CTX *mdctx;

  if((mdctx = EVP_MD_CTX_new()) == NULL)
    return false;
  if(1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL))
    return false;
  if(1 != EVP_DigestUpdate(mdctx, message, message_len))
    return false;
  if(1 != EVP_DigestFinal_ex(mdctx, digest, &digest_len))
    return false;
  EVP_MD_CTX_free(mdctx);

  return true;
}

bool authenticated_encrypt(byte* in, int in_len, byte *key,
            byte *iv, byte *out, int* out_size) {

  const char* alg_name = "aes-256-cbc-hmac-sha256";
  int blk_size =  cipher_block_byte_size(alg_name);
  int key_size =  cipher_key_byte_size(alg_name);
  int mac_size =  mac_output_byte_size(alg_name);
  int cipher_size = *out_size - blk_size;
  memset(out, 0, *out_size);

  if (!encrypt(in, in_len, key, iv, out + block_size, &cipher_size))
    return false;
  memcpy(out, iv, block_size);
  cipher_size += block_size;

  unsigned int hmac_size = mac_size;
  HMAC(EVP_sha256(), &key[key_size / 2], mac_size, out, cipher_size, out + cipher_size, &hmac_size);
  *out_size = cipher_size + hmac_size;
  return true;
}

bool authenticated_decrypt(byte* in, int in_len, byte *key,
            byte *out, int* out_size) {

  const char* alg_name = "aes-256-cbc-hmac-sha256";
  int blk_size =  cipher_block_byte_size(alg_name);
  int key_size =  cipher_key_byte_size(alg_name);
  int mac_size =  mac_output_byte_size(alg_name);
  int cipher_size = *out_size - blk_size;

  int plain_size = *out_size - blk_size - mac_size;

  int msg_with_iv_size = in_len - mac_size;
  unsigned int hmac_size = mac_size;
  byte* hmac_out[hmac_size];
  HMAC(EVP_sha256(), &key[key_size / 2], mac_size, in, msg_with_iv_size, (byte*)hmac_out, &hmac_size);
  if (memcmp(hmac_out, in + msg_with_iv_size, mac_size) != 0) {
    return false;
  }

  if (!decrypt(in + block_size, msg_with_iv_size - block_size, key, in, out, &plain_size))
    return false;
  *out_size = plain_size;
  return (memcmp(hmac_out, in + msg_with_iv_size, mac_size) == 0);
}

bool private_key_to_public_key(const key_message& in, key_message* out) {

  int n_bytes;
  if (in.key_type() == "rsa-2048-private") {
    out->set_key_type("rsa-2048-public");
    n_bytes = cipher_block_byte_size("rsa-2048-public");
  } else if (in.key_type() == "rsa-1024-private") {
    out->set_key_type("rsa-1024-public");
    n_bytes = cipher_block_byte_size("rsa-1024-public");
  } else {
    return false;
  }

  out->set_key_name(in.key_name());
  out->set_key_format(in.key_format());
  out->set_not_before(in.not_before());
  out->set_not_after(in.not_after());
  out->set_certificate(in.certificate().data(), in.certificate().size());

  rsa_message* rk = new(rsa_message);
  rk->set_public_modulus(in.rsa_key().public_modulus().data(),
      in.rsa_key().public_modulus().size());
  rk->set_public_exponent(in.rsa_key().public_exponent().data(),
      in.rsa_key().public_exponent().size());
  out->set_allocated_rsa_key(rk);
  return true;
}

bool make_certifier_rsa_key(int n,  key_message* k) {
  if (k == nullptr)
    return false;

  RSA* r = RSA_new();
  if (!generate_new_rsa_key(n, r))
    return false;

  if (n == 2048) {
    k->set_key_type("rsa-2048-private");
  } else if (n == 1024) {
    k->set_key_type("rsa-1024-private");
  } else {
    RSA_free(r);
    return false;
  }
  k->set_key_format("vse-key");
  if (!RSA_to_key(r, k))
    return false;
  RSA_free(r);
  return true;
}

bool rsa_public_encrypt(RSA* key, byte* data, int data_len, byte *encrypted, int* size_out) {
  int n = RSA_public_encrypt(data_len, data, encrypted, key, RSA_PKCS1_PADDING);
  if (n <= 0)
    return false;
  if (n <= 0)
    return false;
  *size_out = n; 
  return true;
}

bool rsa_private_decrypt(RSA* key, byte* enc_data, int data_len,  byte* decrypted, int* size_out) {
  int  n = RSA_private_decrypt(data_len, enc_data, decrypted, key, RSA_PKCS1_PADDING);
  if (n <= 0)
    return false;
  if (n <= 0)
    return false;
  *size_out = n; 
  return true;
}

#if 0

// This is the original (incorrect) signature

bool rsa_sha256_sign(RSA*key, int size, byte* msg, int* size_out, byte* out) {
  // hash message
  unsigned int size_buf= RSA_size(key);
  byte buf[size_buf];
  memset(buf, 0, size_buf);
  int digest_size = digest_output_byte_size("sha-256");

  // Padding:  0x00 || 0x01 || PS || 0x00 || M to fill buffer
  if (!digest_message((const byte*) msg, size, buf + (size_buf - digest_size), digest_size)) {
    printf("digest failed\n");
    return false;
  }
  buf[1] = 1;
  int  n = RSA_private_encrypt(size_buf, buf, out, key, RSA_NO_PADDING);
  if (n <= 0)
    return false;
  *size_out = n;
  return true;
}

bool rsa_sha256_verify(RSA*key, int size, byte* msg, int size_sig, byte* sig) {

  unsigned int size_digest = digest_output_byte_size("sha-256");
  byte digest[size_digest];
  memset(digest, 0, size_digest);
  if (!digest_message((const byte*) msg, size, digest, size_digest))
    return false;

  int size_decrypted = RSA_size(key);
  byte decrypted[size_decrypted];
  int n = RSA_public_decrypt(size_sig, sig, decrypted, key, RSA_NO_PADDING);
  if (n <= 0)
    return false;
  if (memcmp(digest, &decrypted[size_decrypted - size_digest], size_digest) != 0)
    return false;
  return true;
}

#else

//  PKCS compliant signer
bool rsa_sha256_sign(RSA*key, int to_sign_size, byte* to_sign, int* sig_size, byte* sig) {
  EVP_MD_CTX* sign_ctx = EVP_MD_CTX_create();
  EVP_PKEY* private_key  = EVP_PKEY_new();
  EVP_PKEY_assign_RSA(private_key, key);

  if (EVP_DigestSignInit(sign_ctx, nullptr, EVP_sha256(), nullptr, private_key) <= 0) {
      return false;
  }
  if (EVP_DigestSignUpdate(sign_ctx,  to_sign, to_sign_size) <= 0) {
      return false;
  }
  size_t t = *sig_size;
  if (EVP_DigestSignFinal(sign_ctx, nullptr, (size_t*)&t) <= 0) {
      return false;
  }
  *sig_size = t;
  if (EVP_DigestSignFinal(sign_ctx, sig, &t) <= 0) {
      return false;
  }
  EVP_MD_CTX_destroy(sign_ctx);
  return true;
}

bool rsa_sha256_verify(RSA*key, int size, byte* msg, int sig_size, byte* sig) {

  unsigned int size_digest = digest_output_byte_size("sha-256");
  byte digest[size_digest];
  memset(digest, 0, size_digest);

  if (!digest_message((const byte*) msg, size, digest, size_digest))
    return false;
  int size_decrypted = RSA_size(key);
  byte decrypted[size_decrypted];
  memset(decrypted, 0, size_decrypted);
  int n = RSA_public_encrypt(sig_size, sig, decrypted, key, RSA_NO_PADDING);
  if (memcmp(digest, &decrypted[n - size_digest], size_digest) != 0)
    return false;

  const int check_size = 16;
  byte check_buf[16] = {
    0x00, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  };
  if (memcmp(check_buf, decrypted, check_size) != 0)
    return false;
  return true;
}

#endif

bool generate_new_rsa_key(int num_bits, RSA* r) {
  bool ret= true;
  BIGNUM* bne = NULL;
  uint32_t e = RSA_F4;

  bne = BN_new();
  if (1 != BN_set_word(bne, e)) {
    ret = false;
    goto done;
  }
  if (1 != RSA_generate_key_ex(r, num_bits, bne, NULL)) {
    ret = false;
    goto done;
  }

done:
  BN_free(bne);
  return ret;
}

bool key_to_RSA(const key_message& k, RSA* r) {
  if (k.key_format() != "vse-key") {
    return false;
  }

  int key_size_bits= 0;
  bool private_key= true;

  if (k.key_type() == "rsa-1024-public") {
    key_size_bits= 1024;
    private_key = false;
  } else if (k.key_type() == "rsa-1024-private") {
    key_size_bits= 1024;
    private_key = true;
  } else if (k.key_type() == "rsa-2048-public") {
    key_size_bits= 2048;
    private_key = false;
  } else if (k.key_type() == "rsa-2048-private") {
    key_size_bits= 2048;
    private_key = true;
  } else {
    return false;
  }

  if (!k.has_rsa_key()) {
    return false;
  }
  const rsa_message& rsa_key_data = k.rsa_key();
  if (!rsa_key_data.has_public_modulus() || !rsa_key_data.has_public_exponent()) {
    print_key(k);
    return false;
  }
  BIGNUM* n =  BN_bin2bn((byte*)(rsa_key_data.public_modulus().data()),
                (int)(rsa_key_data.public_modulus().size()), NULL);
  BIGNUM* e =  BN_bin2bn((const byte*) rsa_key_data.public_exponent().data(),
                (int)rsa_key_data.public_exponent().size(), NULL);
  BIGNUM* d = nullptr;
  if (private_key && rsa_key_data.has_private_exponent()) {
    d =  BN_bin2bn((const byte*) rsa_key_data.private_exponent().data(),
                (int)rsa_key_data.private_exponent().size(), NULL);
  }
  if (1 != RSA_set0_key(r, n, e, d)) {
    return false;
  }
  return true;
}

bool RSA_to_key(RSA* r, key_message* k) {
  const BIGNUM* m = nullptr;
  const BIGNUM* e = nullptr;
  const BIGNUM* d = nullptr;
  
  k->set_key_format("vse-key");
  RSA_get0_key(r, &m, &e, &d);

  int rsa_size = RSA_bits(r);
  if (rsa_size == 1024) {
    if (d == nullptr)
      k->set_key_type("rsa-1024-public");
    else
      k->set_key_type("rsa-1024-private");
  } else if (rsa_size == 2048) {
    if (d == nullptr)
      k->set_key_type("rsa-2048-public");
    else
      k->set_key_type("rsa-2048-private");
  } else {
    return false;
  }
  rsa_message* rsa= new(rsa_message);
  k->set_allocated_rsa_key(rsa);

  int i;
  int size;
  if (m != nullptr) {
    size = BN_num_bytes(m);
    byte n_b[size];
    memset(n_b, 0, size);
    i = BN_bn2bin(m, n_b);
    rsa->set_public_modulus((void*)n_b, i);
  }
  if (e != nullptr) {
    size = BN_num_bytes(e);
    byte e_b[size];
    memset(e_b, 0, size);
    i = BN_bn2bin(e, e_b);
    rsa->set_public_exponent((void*)e_b, i);
  }
  if (d != nullptr) {
    size = BN_num_bytes(d);
    byte d_b[size];
    memset(d_b, 0, size);
    i = BN_bn2bin(d, d_b);
    rsa->set_private_exponent((void*)d_b, i);
  }
  return true;
}

bool make_root_key_with_cert(string& type, string& name, string& issuer_name, key_message* k) {
  string root_name("root");

  if (type == "rsa-2048-private" || type == "rsa-1024-private") {
    int n = 2048;
    if (type == "rsa-2048-private")
      n = 2048;
    else if (type == "rsa-1024-private")
      n = 1024;
    if (!make_certifier_rsa_key(n,  k))
      return false;
    k->set_key_format("vse-key");
    k->set_key_type(type);
    k->set_key_name(name);
    double duration = 5.0 * 86400.0 * 365.0;
    X509* cert = X509_new();
    if (cert == nullptr)
      return false;
    if (!produce_artifact(*k, issuer_name, root_name, *k, issuer_name, root_name,
                      01L, duration, cert, true)) {
      return false;
    }
    string cert_asn;
    if (!x509_to_asn1(cert, &cert_asn))
      return false;
    k->set_certificate((byte*)cert_asn.data(), cert_asn.size());
    X509_free(cert);
  } else {
    return false;
  }
  return true;
}

bool get_random(int num_bits, byte* out) {
  bool ret = true;

#if 1
  int in = open("/dev/urandom", O_RDONLY, 0644);
#else
  // FIX! it should be /dev/random
  int in = open("/dev/random", O_RDONLY, 0644);
#endif
  int n = ((num_bits + num_bits_in_byte - 1) / num_bits_in_byte);
  if (read(in, out, n) != n)
    ret = false;
  close(in);
  return ret;
}

bool same_key(const key_message& k1, const key_message& k2) {
  if (k1.key_type() != k2.key_type())
    return false;
  if (k1.key_type() == "rsa-2048-private" || k1.key_type() == "rsa-2048-public" ||
      k1.key_type() == "rsa-1024-private" || k1.key_type() == "rsa-1024-public") {
    string b1, b2;
    if (!k1.has_rsa_key() || !k2.has_rsa_key())
      return false;
    if (k1.rsa_key().public_modulus() != k2.rsa_key().public_modulus())
      return false;
    if (k1.rsa_key().public_exponent() != k2.rsa_key().public_exponent())
      return false;
    return true;
  } else if (k1.key_type() == "aes-256-cbc-hmac-sha256" || k1.key_type() == "aes-256-cbc" || k1.key_type() == "aes-256") {
    if (!k1.has_secret_key_bits())
      return false;
    if (k1.secret_key_bits().size() != k2.secret_key_bits().size())
      return false;
    return (memcmp(k1.secret_key_bits().data(), k2.secret_key_bits().data(), k1.secret_key_bits().size()) == 0);
  } else {
    return false;
  }
  return true;
}

bool same_measurement(string& m1, string& m2) {
  if (m1.size() != m2.size())
    return false;
  if (memcmp((byte*)m1.data(), (byte*)m2.data(), m1.size()) != 0)
    return false;
  return true;
}

bool same_entity(const entity_message& e1, const entity_message& e2) {
  if (e1.entity_type() != e2.entity_type())
    return false;
  if (e1.entity_type() == "key")
    return same_key(e1.key(), e2.key());
  if (e1.entity_type() == "measurement") {
    string s1;
    string s2;
    s1.assign((char*)e1.measurement().data(), e1.measurement().size());
    s2.assign((char*)e2.measurement().data(), e2.measurement().size());
    return same_measurement(s1, s2);
  }
  return false;
}

bool same_vse_claim(const vse_clause& c1, const vse_clause& c2) {
  if (c1.has_subject() != c2.has_subject() || c1.has_object() != c2.has_object() ||
      c1.has_verb() != c2.has_verb() || c1.has_clause() != c2.has_clause())
    return false;

  if (c1.has_subject()) {
      if (!same_entity(c1.subject(), c2.subject()))
        return false;
  }

  if (c1.has_verb()) {
      if (c1.verb() != c2.verb())
        return false;
  }

  if (c1.has_object()) {
      if (!same_entity(c1.object(), c2.object()))
        return false;
  }

  if (c1.has_clause())
    return same_vse_claim(c1.clause(), c2.clause());

  return true;
}

bool make_key_entity(const key_message& key, entity_message* ent) {
  ent->set_entity_type("key");
  key_message* k = new(key_message);
  k->CopyFrom(key);
  ent->set_allocated_key(k);
  return true;
}

bool make_measurement_entity(string& measurement, entity_message* ent) {
  ent->set_entity_type("measurement");
  string* m = new string(measurement);
  ent->set_allocated_measurement(m);
  return true;
}

bool make_unary_vse_clause(const entity_message& subject, string& verb,
    vse_clause* out) {
  entity_message* s= new(entity_message);
  s->CopyFrom(subject);
  out->set_allocated_subject(s);
  out->set_verb(verb);
  return true;
}

bool make_simple_vse_clause(const entity_message& subject, string& verb,
    const entity_message& object, vse_clause* out) {
  entity_message* s= new(entity_message);
  s->CopyFrom(subject);
  out->set_allocated_subject(s);
  entity_message* o= new(entity_message);
  o->CopyFrom(object);
  out->set_allocated_object(o);
  out->set_verb(verb);
  return true;
}

bool make_indirect_vse_clause(const entity_message& subject, string& verb,
    const vse_clause& in, vse_clause* out) {
  entity_message* s = new(entity_message);
  s->CopyFrom(subject);
  out->set_allocated_subject(s);
  vse_clause* cl = new(vse_clause);
  cl->CopyFrom(in);
  out->set_allocated_clause(cl);
  out->set_verb(verb);
  return true;
}

bool make_claim(int size, byte* serialized_claim, string& format, string& descriptor,
    string& not_before, string& not_after, claim_message* out) {
  out->set_claim_format(format);
  out->set_claim_descriptor(descriptor);
  out->set_not_before(not_before);
  out->set_not_after(not_after);
  out->set_serialized_claim((void*)serialized_claim, size);
  return true;
}

void print_bytes(int n, byte* buf) {
  for(int i = 0; i < n; i++)
    printf("%02x", buf[i]);
}

void print_rsa_key(const rsa_message& rsa) {
  if (rsa.has_public_modulus()) {
    printf("Modulus: ");
    print_bytes(rsa.public_modulus().size(), (byte*)rsa.public_modulus().data());
    printf("\n");
  }
  if (rsa.has_public_exponent()) {
    printf("Public exponent: ");
    print_bytes(rsa.public_exponent().size(), (byte*)rsa.public_exponent().data());
    printf("\n");
  }
  if (rsa.has_private_exponent()) {
    printf("Private exponent: ");
    print_bytes(rsa.private_exponent().size(), (byte*)rsa.private_exponent().data());
    printf("\n");
  }
  if (rsa.has_private_p()) {
  }
  if (rsa.has_private_q()) {
  }
  if (rsa.has_private_dp()) {
  }
  if (rsa.has_private_dq()) {
  }
}

void print_key(const key_message& k) {
  if (k.has_key_name()) {
    printf("Key name: %s\n", k.key_name().c_str());
  }
  if (k.has_key_type()) {
    printf("Key type: %s\n", k.key_type().c_str());
  }
  if (k.has_key_format()) {
    printf("Key format: %s\n", k.key_format().c_str());
  }
  if (k.has_rsa_key()) {
    print_rsa_key(k.rsa_key());
  }
  if (k.has_ecc_key()) {
  }
  if (k.has_secret_key_bits()) {
    printf("Secret key bits: ");
    print_bytes(k.secret_key_bits().size(), (byte*)k.secret_key_bits().data());
    printf("\n");
  }
  if (k.has_certificate() && k.certificate().size() > 0) {
    X509* cert= X509_new();
    if (cert == nullptr)
      return;
    string in;
    in.assign((char*)k.certificate().data(), k.certificate().size());
    if (!asn1_to_x509(in, cert)) {
      X509_free(cert);
      return;
    }
    X509_print_fp(stdout, cert);
    X509_free(cert);
  }
}

void print_key_descriptor(const key_message& k) {

  if (!k.has_key_type())
    return;

  if (k.key_type() == "rsa-2048-private" || k.key_type() == "rsa-2048-public" ||
      k.key_type() == "rsa-1024-private" || k.key_type() == "rsa-1024-public") {
    printf("Key[rsa, ");
    if (k.has_key_name()) {
      printf("%s, ", k.key_name().c_str());
    }
    if (k.has_rsa_key()) {
      int l = (int)k.rsa_key().public_modulus().size();
      if (l > 20)
        l = 20;
      if (k.rsa_key().has_public_modulus()) {
        print_bytes(l, (byte*)k.rsa_key().public_modulus().data());
      }
    }
    printf("]");
  } else {
    printf(" unsupported type %s ", k.key_type().c_str());
  }
}

void print_entity_descriptor(const entity_message& e) {
  if (e.entity_type() == "key" && e.has_key()) {
    print_key_descriptor(e.key());
  } else if (e.entity_type() == "measurement" && e.has_measurement()) {
    printf("Measurement[");
    print_bytes((int)e.measurement().size(), (byte*)e.measurement().data());
    printf("] ");
  } else {
  }
}

void print_vse_clause(const vse_clause c) {
  if (c.has_subject()) {
    print_entity_descriptor(c.subject());
    printf(" ");
  }
  if (c.has_verb()) {
    printf("%s ", c.verb().c_str());
  }
  if (c.has_object()) {
    print_entity_descriptor(c.object());
    printf(" ");
  }
  if (c.has_clause()) {
    print_vse_clause(c.clause());
    printf(" ");
  }
}

void print_claim(const claim_message& claim) {
  if (!claim.has_claim_format()) {
    return;
  }
  printf("format: %s\n", claim.claim_format().c_str());
  if (claim.has_claim_descriptor()) {
    printf("%s\n", claim.claim_descriptor().c_str());
  }
  if (claim.has_not_before()) {
    printf("not before: %s\n", claim.not_before().c_str());
  }
  if (claim.has_not_after()) {
    printf("not after: %s\n", claim.not_after().c_str());
  }
  if (claim.claim_format() == "vse-clause" && claim.has_serialized_claim()) {
    vse_clause c;
    c.ParseFromString(claim.serialized_claim());
    print_vse_clause(c);
    printf("\n");
  }
  if (claim.claim_format() == "vse-attestation" && claim.has_serialized_claim()) {
    attestation at;
    at.ParseFromString(claim.serialized_claim());
    print_attestation(at);
    printf("\n");
  }
}

void print_attestation(attestation& at) {
  if (at.has_description())
    printf("Description: %s\n", at.description().c_str());
  if (at.has_key_id())
    printf("Key-id: %s\n", at.key_id().c_str());
  if (at.has_measurement()) {
    printf("Measurement: ");
    print_bytes((int)at.measurement().size(), (byte*)at.measurement().data());
    printf("\n");
  }
  if (at.has_time())
    printf("time attested: %s\n", at.time().c_str());
  if (at.has_clause()) {
    print_vse_clause(at.clause());
  }
}

void print_signed_claim(const signed_claim_message& signed_claim) {
  printf("\nSigned claim\n");
  if (!signed_claim.has_serialized_claim_message())
    return;
  claim_message cl;
  string s_claim;
  s_claim.assign((char*)signed_claim.serialized_claim_message().data(), 
      signed_claim.serialized_claim_message().size());
  cl.ParseFromString(s_claim);
  print_claim(cl);
  printf("Serialized: "); print_bytes((int)signed_claim.serialized_claim_message().size(),
    (byte*)signed_claim.serialized_claim_message().data()); printf("\n");
  if (signed_claim.has_signing_key()) {
    printf("Signer key: "); print_key(signed_claim.signing_key()); printf("\n");
  }
  if (signed_claim.has_signing_algorithm()) {
    printf("Signing algorithm: %s\n", signed_claim.signing_algorithm().c_str());
  }
  if (signed_claim.has_signature()) {
    printf("Signature: ");
    print_bytes((int)signed_claim.signature().size(),
      (byte*)signed_claim.signature().data());
    printf("\n");
  }

  if (cl.claim_format() == "vse-clause") {
    vse_clause v1;
    string serialized_vse;
    serialized_vse.assign((char*)cl.serialized_claim().data(),
        cl.serialized_claim().size());
    if (v1.ParseFromString(serialized_vse)) {
      print_vse_clause(v1);
      printf("\n");
    }
  }
}

void print_entity(const entity_message& em) {
  if (!em.has_entity_type())
    printf("%s entity\n", em.entity_type().c_str());
  if (em.entity_type() == "key") {
    print_key(em.key());
  } else if (em.entity_type() == "measurement") {
    printf("Measurement[");
    print_bytes((int)em.measurement().size(), (byte*)em.measurement().data());
    printf("] ");
  } else {
    return;
  }
}

bool verify_signed_attestation(int serialized_size, byte* serialized,
      int sig_size, byte* sig, const key_message& key) {
  attestation at;
  string s;
  s.assign((char*)serialized, serialized_size);
  at.ParseFromString(s);

  RSA* r = RSA_new();
  if (!key_to_RSA(key, r))
    return false;
  bool fRet= rsa_sha256_verify(r, serialized_size, serialized, sig_size, sig);
  RSA_free(r);
  return fRet;
}

bool make_signed_claim(const claim_message& claim, const key_message& key,
    signed_claim_message* out) {

  string serialized_claim;
  if(!claim.SerializeToString(&serialized_claim))
    return false;

  out->set_signing_algorithm("rsa-2048-sha256-pkcs-sign");
  out->set_serialized_claim_message((void*)serialized_claim.data(), serialized_claim.size());

  RSA* r = RSA_new();
  if (!key_to_RSA(key, r))
    return false;

  int sig_size = RSA_size(r);
  byte sig[sig_size];
  bool success = rsa_sha256_sign(r, serialized_claim.size(), (byte*)serialized_claim.data(),
    &sig_size, sig);
  RSA_free(r);
  if (!success)
    return false;

  // sign serialized claim
  key_message* psk = new(key_message);
  if (!private_key_to_public_key(key, psk))
    return false;
  out->set_allocated_signing_key(psk);
  out->set_signature((void*)sig, sig_size);
  return true;
}

bool verify_signed_claim(const signed_claim_message& signed_claim, const key_message& key) {

  if (!signed_claim.has_serialized_claim_message() || !signed_claim.has_signing_key() ||
      !signed_claim.has_signing_algorithm() || !signed_claim.has_signature())
    return false;

  string serialized_claim;
  serialized_claim.assign((char*)signed_claim.serialized_claim_message().data(),
    signed_claim.serialized_claim_message().size());
  claim_message c;
  if (!c.ParseFromString(serialized_claim))
    return false;

  if (!c.has_claim_format())
    return false;
  if (c.claim_format() != "vse-clause" && c.claim_format() != "vse-attestation") {
    printf("%s should be vse-clause or vse-attestation\n", c.claim_format().c_str());        
    return false;
  }

  time_point t_now; 
  time_point t_nb;
  time_point t_na;

  if (!time_now(&t_now))
    return false;
  if (!string_to_time(c.not_before(), &t_nb))
    return false;
  if (!string_to_time(c.not_after(), &t_na))
    return false;

  if (compare_time(t_now, t_nb) <  0)
     return false;
  if (compare_time(t_na, t_now) < 0)
     return false;

  if (signed_claim.signing_algorithm() != "rsa-2048-sha256-pkcs-sign")
    return false;

  RSA* r = RSA_new();
  if (!key_to_RSA(key, r))
    return false;

  bool success = rsa_sha256_verify(r, (int)signed_claim.serialized_claim_message().size(),
      (byte*)signed_claim.serialized_claim_message().data(), (int)signed_claim.signature().size(),
      (byte*)signed_claim.signature().data());
  RSA_free(r);

  return success;
}

bool vse_attestation(string& descript, string& enclave_type, string& enclave_id,
      vse_clause& cl, string* serialized_attestation) {
  attestation at;

  at.set_description(descript);
  at.set_enclave_type(enclave_type);
  int digest_size = digest_output_byte_size("sha-256");
  int size_out= digest_size;
  byte m[size_out];
  memset(m, 0, size_out);
  if (!Getmeasurement(enclave_type, enclave_id, &size_out, m))
    return false;
  at.set_measurement((void*)m, size_out);
  time_point t_now;
  if (!time_now(&t_now))
    return false;
  string time_str;
  if (!time_to_string(t_now, &time_str))
    return false;
  vse_clause* cn = new(vse_clause);
  cn->CopyFrom(cl);
  at.set_allocated_clause(cn);
  at.set_time(time_str);
  string serialized;
  at.SerializeToString(serialized_attestation);
  return true;
}

void print_storage_info(const storage_info_message& smi) {
  printf("\nStorage info:\n");
  if (smi.has_storage_type())
    printf("Storage type: %s\n", smi.storage_type().c_str());
  if (smi.has_storage_descriptor())
    printf("Storage descriptor: %s\n", smi.storage_descriptor().c_str());
  if (smi.has_address())
    printf("address: %s\n", smi.address().c_str());
  if (smi.has_storage_key())
    print_key(smi.storage_key());
}

void print_trusted_service_message(const trusted_service_message& tsm) {
  printf("\nTrusted service\n");
  if (tsm.has_trusted_service_address())
    printf("Service address: %s\n", tsm.trusted_service_address().c_str());
  if (tsm.has_trusted_service_key())
    print_key(tsm.trusted_service_key());
}

void print_protected_blob(protected_blob_message& pb) {
  if (pb.has_encrypted_key()) {
    printf("encrypted_key (%d): ", (int)pb.encrypted_key().size());
    print_bytes((int)pb.encrypted_key().size(), (byte*)pb.encrypted_key().data());
    printf("\n");
  }
  if (pb.has_encrypted_data()) {
    printf("encrypted_data (%d): ", (int)pb.encrypted_data().size());
    print_bytes((int)pb.encrypted_data().size(), (byte*)pb.encrypted_data().data());
    printf("\n");
  }
}

int add_ext(X509 *cert, int nid, const char *value) {
  X509_EXTENSION *ex;
  X509V3_CTX ctx;

  // This sets the 'context' of the extensions.
  X509V3_set_ctx_nodb(&ctx);

  X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
  ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
  if(!ex)
    return 0;

  X509_add_ext(cert,ex, -1);
  X509_EXTENSION_free(ex);
  return 1;
}

// Caller should have allocated X509
// name is some printable version of the measurement
bool produce_artifact(key_message& signing_key, string& issuer_name_str, string& issuer_organization_str,
                      key_message& subject_key, string& subject_name_str, string& subject_organization_str,
                      uint64_t sn, double secs_duration, X509* x509, bool is_root) {

  RSA* signing_rsa_key = RSA_new();
  if (!key_to_RSA(signing_key, signing_rsa_key))
    return false;
  EVP_PKEY* signing_pkey = EVP_PKEY_new();
  EVP_PKEY_set1_RSA(signing_pkey, signing_rsa_key);
  X509_set_pubkey(x509, signing_pkey);

  RSA* subject_rsa_key = RSA_new();
  if (!key_to_RSA(subject_key, subject_rsa_key))
    return false;
  EVP_PKEY* subject_pkey = EVP_PKEY_new();
  EVP_PKEY_set1_RSA(subject_pkey, subject_rsa_key);
  X509_set_pubkey(x509, subject_pkey);

  ASN1_INTEGER* a = ASN1_INTEGER_new();
  ASN1_INTEGER_set_uint64(a, sn);
  X509_set_serialNumber(x509, a);

  X509_NAME* subject_name =  X509_NAME_new();
  X509_NAME_add_entry_by_txt(subject_name, "CN", MBSTRING_ASC,
                            (unsigned char *)subject_name_str.c_str(), -1, -1, 0);
  X509_NAME_add_entry_by_txt(subject_name, "O", MBSTRING_ASC,
                        (const byte*)subject_organization_str.c_str(), -1, -1, 0);
  X509_set_subject_name(x509, subject_name);

  X509_NAME* issuer_name =  X509_NAME_new();
  X509_NAME_add_entry_by_txt(issuer_name, "CN", MBSTRING_ASC,
                            (unsigned char *)issuer_name_str.c_str(), -1, -1, 0);
  X509_NAME_add_entry_by_txt(issuer_name, "O", MBSTRING_ASC,
                        (const byte*)issuer_organization_str.c_str(), -1, -1, 0);
  X509_set_issuer_name(x509, issuer_name);

  time_t t_start = time(NULL);
  ASN1_TIME* tm_start= ASN1_TIME_new();
  ASN1_TIME_set(tm_start, t_start);
  int offset_day = (int) (secs_duration / 86400.0);
  long offset_sec = ((long)secs_duration) - ((long)offset_day * 86400);
  ASN1_TIME* tm_end = ASN1_TIME_adj(NULL, t_start, offset_day, offset_sec);
  X509_set1_notBefore(x509, tm_start);
  X509_set1_notAfter(x509, tm_end);

  add_ext(x509, NID_key_usage, "critical,keyCertSign,digitalSignature,cRLSign");
  add_ext(x509,  NID_ext_key_usage, "clientAuth,serverAuth");
  // add_ext(x509, NID_subject_key_identifier, "hash");
  if (is_root) {
    add_ext(x509, NID_basic_constraints, "critical,CA:TRUE");
  }

  X509_sign(x509, signing_pkey, EVP_sha256());

  ASN1_INTEGER_free(a);
  ASN1_TIME_free(tm_start);
  ASN1_TIME_free(tm_end);
  RSA_free(signing_rsa_key);
  RSA_free(subject_rsa_key);
  X509_NAME_free(subject_name);
  X509_NAME_free(issuer_name);
  EVP_PKEY_free(signing_pkey);
  EVP_PKEY_free(subject_pkey);
  return true;
}

bool verify_artifact(X509& cert, key_message& verify_key, 
    string* issuer_name_str, string* issuer_description_str,
    key_message* subject_key, string* subject_name_str, string* subject_organization_str,
    uint64_t* sn) {

  RSA* verify_rsa_key = RSA_new();
  if (!key_to_RSA(verify_key, verify_rsa_key))
    return false;
  EVP_PKEY* verify_pkey = EVP_PKEY_new();
  EVP_PKEY_set1_RSA(verify_pkey, verify_rsa_key);

  EVP_PKEY* subject_pkey = X509_get_pubkey(&cert);
  RSA* subject_rsa_key= EVP_PKEY_get1_RSA(subject_pkey);
  if (!RSA_to_key(subject_rsa_key, subject_key))
    return false;

  bool success = (X509_verify(&cert, verify_pkey) == 1);

  X509_NAME* subject_name = X509_get_subject_name(&cert);
  char name_buf[1024];
  if (X509_NAME_get_text_by_NID(subject_name, NID_commonName, name_buf, 1024) < 0)
    success = false;
  else {
    subject_name_str->assign((const char*) name_buf);
  }
 
  RSA_free(verify_rsa_key);
  RSA_free(subject_rsa_key);
  EVP_PKEY_free(verify_pkey);
  EVP_PKEY_free(subject_pkey);
  X509_NAME_free(subject_name);
  return success;;
}


bool asn1_to_x509(string& in, X509 *x) {
  int len = in.size();

  byte* p = (byte*) in.data();
  d2i_X509(&x, (const byte**)&p, len);
  if (x == nullptr)
    return false;
  return true;
}

bool x509_to_asn1(X509 *x, string* out) {
  int len = i2d_X509(x, nullptr);
  byte buf[len];
  byte* p = buf;

  i2d_X509(x, (byte**)&p);
  out->assign((char*)buf, len);
  return true;
}
