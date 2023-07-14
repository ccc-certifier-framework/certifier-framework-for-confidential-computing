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

#include <inttypes.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/x509v3.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/ec.h>

#include "support.h"
#include "certifier.pb.h"

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <string>

using std::string;
using namespace certifier::framework;
using namespace certifier::utilities;

// -----------------------------------------------------------------------

class name_size {
public:
  const char* name_;
  int size_;
};

name_size cipher_block_byte_name_size[] = {
  {"aes-256", 16},
  {"aes-256-cbc-hmac-sha256", 16},
  {"aes-256-cbc-hmac-sha384", 16},
  {"aes-256-gcm", 16},
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
  {"rsa-4096-sha384-pkcs-sign", 512},
  {"rsa-4096-private", 512},
  {"rsa-4096-public", 512},
  {"ecc-384-public", 48},
  {"ecc-384-private", 48},
  {"ecc-256-public", 32},
  {"ecc-256-private", 32},
};

name_size cipher_key_byte_name_size[] = {
  {"aes-256", 32},
  {"aes-256-cbc-hmac-sha256", 64},
  {"aes-256-cbc-hmac-sha384", 96},
  {"aes-256-gcm", 32},
  {"rsa-2048-sha256-pkcs-sign", 256},
  {"rsa-2048", 256},
  {"rsa-1024-sha256-pkcs-sign", 128},
  {"rsa-1024", 128},
  {"rsa-2048-private", 256},
  {"rsa-2048-public", 256},
  {"rsa-1024-private", 128},
  {"rsa-1024-public", 128},
  {"rsa-3072-sha384-pkcs-sign", 384},
  {"rsa-3072-private", 384},
  {"rsa-3072-public", 384},
  {"rsa-4096-sha384-pkcs-sign", 512},
  {"rsa-4096-private", 512},
  {"rsa-4096-public", 512},
};

name_size digest_byte_name_size[] = {
  {"sha256", 32},
  {"sha-256", 32},
  {"sha-384", 48},
  {"sha-512", 64},
};

name_size mac_byte_name_size[] = {
  {"hmac-sha256", 32},
  {"aes-256-cbc-hmac-sha256", 32},
  {"aes-256-cbc-hmac-sha384", 48},
  {"aes-256-gcm", 16},
};

int certifier::utilities::cipher_block_byte_size(const char* alg_name) {
  int size = sizeof(cipher_block_byte_name_size) / sizeof(cipher_block_byte_name_size[0]);

  for (int i = 0; i < size; i++) {
    if (strcmp(alg_name, cipher_block_byte_name_size[i].name_) == 0)
      return cipher_block_byte_name_size[i].size_;
  }
  return -1;
}

int certifier::utilities::cipher_key_byte_size(const char* alg_name) {
  int size = sizeof(cipher_key_byte_name_size) / sizeof(cipher_key_byte_name_size[0]);

  for (int i = 0; i < size; i++) {
    if (strcmp(alg_name, cipher_key_byte_name_size[i].name_) == 0)
      return cipher_key_byte_name_size[i].size_;
  }
  return -1;
}

int certifier::utilities::digest_output_byte_size(const char* alg_name) {
  int size = sizeof(digest_byte_name_size) / sizeof(digest_byte_name_size[0]);

  for (int i = 0; i < size; i++) {
    if (strcmp(alg_name, digest_byte_name_size[i].name_) == 0)
      return digest_byte_name_size[i].size_;
  }
  return -1;
}

int certifier::utilities::mac_output_byte_size(const char* alg_name) {
  int size = sizeof(mac_byte_name_size) / sizeof(mac_byte_name_size[0]);

  for (int i = 0; i < size; i++) {
    if (strcmp(alg_name, mac_byte_name_size[i].name_) == 0)
      return mac_byte_name_size[i].size_;
  }
  return -1;
}

bool certifier::utilities::write_file(const string& file_name, int size, byte* data) {
  int out = open(file_name.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0644);
  if (out < 0)
    return false;
  if (write(out, data, size) < 0) {
    printf("write_file: write failed\n");
    close(out);
    return false;
  }
  close(out);
  return true;
}

int certifier::utilities::file_size(const string& file_name) {
  struct stat file_info;

  if (stat(file_name.c_str(), &file_info) != 0)
    return -1;
  if (!S_ISREG(file_info.st_mode))
    return -1;
  return (int)file_info.st_size;
}

bool certifier::utilities::read_file(const string& file_name, int* size, byte* data) {
  struct stat file_info;

  if (stat(file_name.c_str(), &file_info) != 0) {
    printf("read_file: Can't stat\n");
    return false;
  }
  if (!S_ISREG(file_info.st_mode)) {
    return false;
  }
  int bytes_in_file = (int)file_info.st_size;
  if (bytes_in_file > *size) {
    printf("read_file: Buffer too small\n");
    return false;
  }
  int fd = ::open(file_name.c_str(), O_RDONLY);
  if (fd < 0) {
    printf("read_file: open failed\n");
    return false;
  }
  int n = (int)read(fd, data, bytes_in_file);
  close(fd);
  *size = n;
  return true;
}

bool certifier::utilities::read_file_into_string(const string& file_name, string* out) {
  int size = file_size(file_name);
  if (size < 0) {
    printf("read_file_into_string: Can't size input file\n");
    return false;
  }
  byte buf[size];
  if (!read_file(file_name, &size, buf)) {
    printf("read_file_into_string: Can't read file\n");
    return false;
  }

  out->assign((char*)buf, size);
  return true;
}

// -----------------------------------------------------------------------

bool certifier::utilities::time_t_to_tm_time(time_t* t, struct tm *tm_time) {
  gmtime_r(t, tm_time);
  return true;
}

bool certifier::utilities::tm_time_to_time_point(struct tm* tm_time, time_point* tp) {
  tp->set_year(tm_time->tm_year + 1900);
  tp->set_month(tm_time->tm_mon + 1);
  tp->set_day(tm_time->tm_mday);
  tp->set_hour(tm_time->tm_hour);
  tp->set_minute(tm_time->tm_min);
  tp->set_seconds(tm_time->tm_sec);
  return true;
}

bool certifier::utilities::asn1_time_to_tm_time(const ASN1_TIME* s, struct tm *tm_time) {
  if (1 != ASN1_TIME_to_tm(s, tm_time))
    return false;
  return true;
}

bool certifier::utilities::get_not_before_from_cert(X509* c, time_point* tp) {
  const ASN1_TIME* asc_time = X509_getm_notBefore(c);
  if (asc_time == nullptr)
    return false;
  struct tm tm_time;
  if (!asn1_time_to_tm_time(asc_time, &tm_time))
    return false;
  if (!tm_time_to_time_point(&tm_time, tp))
    return false;
  return true;
}

bool certifier::utilities::get_not_after_from_cert(X509* c, time_point* tp) {
  const ASN1_TIME* asc_time = X509_getm_notAfter(c);
  if (asc_time == nullptr)
    return false;
  struct tm tm_time;
  if (!asn1_time_to_tm_time(asc_time, &tm_time))
    return false;
  if (!tm_time_to_time_point(&tm_time, tp))
    return false;
  return true;
}

bool certifier::utilities::time_now(time_point* t) {
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

bool certifier::utilities::time_to_string(time_point& t, string* s) {
  char t_buf[128];

  // YYYY-MM-DDTHH:mm:ss.sssZ
  int n = sprintf(t_buf, "%04d-%02d-%02dT%02d:%02d:%8.5lfZ",
      t.year(), t.month(),t.day(),
      t.hour(), t.minute(), t.seconds());
  s->assign((const char*)t_buf);
  return true;
}

bool certifier::utilities::string_to_time(const string& s, time_point* t) {
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
int certifier::utilities::compare_time(time_point& t1, time_point& t2) {
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

bool certifier::utilities::add_interval_to_time_point(time_point& t_in, double hours,
      time_point* t_out) {
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

void certifier::utilities::print_time_point(time_point& t) {
  printf("%02d-%02d-%02dT%02d:%02d:%8.5lfZ\n", t.year(), t.month(),
    t.day(), t.hour(), t.minute(), t.seconds());
}

void certifier::utilities::print_property(const property& prop) {
  printf("%s: ", prop.property_name().c_str());

  if (prop.value_type() == "int") {
    if (prop.comparator() == "=") {
      printf(" = ");
    } else if (prop.comparator() == ">=") {
      printf(" >= ");
    }
    printf("%" PRIu64, prop.int_value());
  } else if (prop.value_type() == "string") {
    printf("%s", prop.string_value().c_str());
  } else {
    printf("property type: %s\n", prop.value_type().c_str());
    return;
  }
  printf("\n");
}

void certifier::utilities::print_platform(const platform& pl) {
  printf("platform: %s\n", pl.platform_type().c_str());
  if (pl.has_key()) {
    printf("  attest_key: ");
    print_key_descriptor(pl.attest_key());
    printf("\n");
  } else {
    printf("  no attest key\n");
  }
  for (int i = 0; i < pl.props().props_size(); i++) {
    printf("  ");
    print_property(pl.props().props(i));
  }
}

void certifier::utilities::print_environment(const environment& env) {
  printf("environment\n");
  print_platform_descriptor(env.the_platform());
  printf("\n");
  printf("measurement: ");
  print_bytes(env.the_measurement().size(), (byte*)env.the_measurement().data());
  printf("\n");
}

// -----------------------------------------------------------------------

// Encryption is ssl
//    Set up a context
//    Initialize the encryption operation
//    Providing plaintext bytes to be encrypted
//    Finalizing the encryption operation
//    During initialization we will provide an EVP_CIPHER object.
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

bool certifier::utilities::digest_message(const char* alg, const byte* message,
    int message_len, byte* digest, unsigned int digest_len) {

  int n = digest_output_byte_size(alg);
  if (n < 0)
    return false;
  if (n > (int)digest_len)
    return false;

  EVP_MD_CTX *mdctx;

  if (strcmp(alg, "sha-256") == 0 || strcmp(alg, "sha256") == 0) {
    if((mdctx = EVP_MD_CTX_new()) == NULL)
      return false;
    if(1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL))
      return false;
  } else if (strcmp(alg, "sha-384") == 0) {
    if((mdctx = EVP_MD_CTX_new()) == NULL)
      return false;
    if(1 != EVP_DigestInit_ex(mdctx, EVP_sha384(), NULL))
      return false;
  } else if (strcmp(alg, "sha-512")  == 0) {
    if((mdctx = EVP_MD_CTX_new()) == NULL)
      return false;
    if(1 != EVP_DigestInit_ex(mdctx, EVP_sha512(), NULL))
      return false;
  } else {
    return false;
  }

  if(1 != EVP_DigestUpdate(mdctx, message, message_len))
    return false;
  if(1 != EVP_DigestFinal_ex(mdctx, digest, &digest_len))
    return false;
  EVP_MD_CTX_free(mdctx);

  return true;
}

bool aes_256_cbc_sha256_encrypt(byte* in, int in_len, byte *key,
            byte *iv, byte *out, int* out_size) {
  int blk_size =  cipher_block_byte_size("aes-256-cbc-hmac-sha256");
  int key_size =  cipher_key_byte_size("aes-256-cbc-hmac-sha256");
  int mac_size =  mac_output_byte_size("aes-256-cbc-hmac-sha256");
  int cipher_size = *out_size - blk_size;

  memset(out, 0, *out_size);

  if (!encrypt(in, in_len, key, iv, out + block_size, &cipher_size)) {
    printf("aes_256_cbc_sha256_encrypt: encrypt failed\n");
    return false;
  }
  memcpy(out, iv, block_size);
  cipher_size += block_size;
  unsigned int hmac_size = mac_size;
  HMAC(EVP_sha256(), &key[key_size / 2], mac_size, out, cipher_size, out + cipher_size, &hmac_size);
  *out_size = cipher_size + hmac_size;

  return true;
}

bool aes_256_cbc_sha256_decrypt(byte* in, int in_len, byte *key,
            byte *out, int* out_size) {
  int blk_size =  cipher_block_byte_size("aes-256-cbc-hmac-sha256");
  int key_size =  cipher_key_byte_size("aes-256-cbc-hmac-sha256");
  int mac_size =  mac_output_byte_size("aes-256-cbc-hmac-sha256");
  int cipher_size = *out_size - blk_size;

  int plain_size = *out_size - blk_size - mac_size;
  int msg_with_iv_size = in_len - mac_size;
  unsigned int hmac_size = mac_size;

  byte hmac_out[hmac_size];
  HMAC(EVP_sha256(), &key[key_size / 2], mac_size, in, msg_with_iv_size, (byte*)hmac_out, &hmac_size);
  if (memcmp(hmac_out, in + msg_with_iv_size, mac_size) != 0) {
    printf("aes_256_cbc_sha256_decrypt: HMAC failed\n");
    return false;
  }

  if (!decrypt(in + block_size, msg_with_iv_size - block_size, key, in, out, &plain_size)) {
    printf("aes_256_cbc_sha256_decrypt: decrypt failed\n");
    return false;
  }
  *out_size = plain_size;
  return (memcmp(hmac_out, in + msg_with_iv_size, mac_size) == 0);
}

bool aes_256_cbc_sha384_encrypt(byte* in, int in_len, byte *key,
            byte *iv, byte *out, int* out_size) {
  int blk_size =  cipher_block_byte_size("aes-256-cbc-hmac-sha384");
  int key_size =  cipher_key_byte_size("aes-256-cbc-hmac-sha384");
  int mac_size =  mac_output_byte_size("aes-256-cbc-hmac-sha384");
  int cipher_size = *out_size - blk_size;

  memset(out, 0, *out_size);

  if (!encrypt(in, in_len, key, iv, out + block_size, &cipher_size)) {
    printf("aes_256_cbc_sha384_encrypt: encrypt failed\n");
    return false;
  }
  memcpy(out, iv, block_size);
  cipher_size += block_size;
  unsigned int hmac_size = mac_size;
  HMAC(EVP_sha384(), &key[key_size / 2], mac_size, out, cipher_size, out + cipher_size, &hmac_size);
  *out_size = cipher_size + hmac_size;

  return true;
}

bool aes_256_cbc_sha384_decrypt(byte* in, int in_len, byte *key,
            byte *out, int* out_size) {
  int blk_size =  cipher_block_byte_size("aes-256-cbc-hmac-sha384");
  int key_size =  cipher_key_byte_size("aes-256-cbc-hmac-sha384");
  int mac_size =  mac_output_byte_size("aes-256-cbc-hmac-sha384");
  int cipher_size = *out_size - blk_size;

  int plain_size = *out_size - blk_size - mac_size;
  int msg_with_iv_size = in_len - mac_size;
  unsigned int hmac_size = mac_size;

  byte hmac_out[hmac_size];
  HMAC(EVP_sha384(), &key[key_size / 2], mac_size, in, msg_with_iv_size, (byte*)hmac_out, &hmac_size);
  if (memcmp(hmac_out, in + msg_with_iv_size, mac_size) != 0) {
    printf("aes_256_cbc_sha384_decrypt: HMAC failed\n");
    return false;
  }

  if (!decrypt(in + block_size, msg_with_iv_size - block_size, key, in, out, &plain_size)) {
    printf("aes_256_cbc_sha384_decrypt: decrypt failed\n");
    return false;
  }
  *out_size = plain_size;
  return (memcmp(hmac_out, in + msg_with_iv_size, mac_size) == 0);
}

// We use 128 bit tag
bool aes_256_gcm_encrypt(byte* in, int in_len, byte *key,
            byte *iv, byte *out, int* out_size) {
  EVP_CIPHER_CTX *ctx = nullptr;
  int len;
  int ciphertext_len;
  int blk_size =  cipher_block_byte_size("aes-256");
  int key_size =  cipher_key_byte_size("aes-256");
  int tag_len = 0;
  byte tag[16];
  int aad_len = 0;
  byte* aad = nullptr;
  bool ret = true;

  if(!(ctx = EVP_CIPHER_CTX_new())) {
    return false;
  }

  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr)) {
    ret = false;
    goto done;
  }

  // set IV length
  if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, blk_size, nullptr)) {
    ret = false;
    goto done;
  }
  if(1 != EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv)) {
    ret = false;
    goto done;
  }

  memcpy(out, iv, blk_size);

  if(1 != EVP_EncryptUpdate(ctx, nullptr, &len, aad, aad_len)) {
    ret = false;
    goto done;
  }
  if(1 != EVP_EncryptUpdate(ctx, out + blk_size, &len, in, in_len)) {
    ret = false;
    goto done;
  }
  ciphertext_len = len + blk_size;

  // Finalize
  if(1 != EVP_EncryptFinal_ex(ctx, out + len, &len)) {
    ret = false;
    goto done;
  }
  ciphertext_len += len;

  tag_len = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, blk_size, tag);
  if(tag_len <= 0) {
    ret = false;
    goto done;
  }

  // append tag
  memcpy(out + ciphertext_len, tag, blk_size);
  *out_size = ciphertext_len + blk_size;

done:
  if (ctx != nullptr) {
    EVP_CIPHER_CTX_free(ctx);
    ctx = nullptr;
  }
  return ret;
}

// We use 128 bit tag
bool aes_256_gcm_decrypt(byte* in, int in_len, byte *key,
            byte *out, int* out_size) {
  EVP_CIPHER_CTX *ctx = nullptr;
  int blk_size =  cipher_block_byte_size("aes-256");
  int key_size =  cipher_key_byte_size("aes-256");
  byte* iv = in;
  bool ret = true;
  byte* tag = in + in_len - blk_size;
  int aad_len = 0;
  byte* aad = nullptr;
  int len;
  int plaintext_len;
  int stream_len = in_len - 2 * blk_size;
  int err = 0;

  if(!(ctx = EVP_CIPHER_CTX_new())) {
    return false;
  }
  if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr)) {
    ret = false;
    goto done;
  }
  if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, blk_size, nullptr)) {
    ret = false;
    goto done;
  }
  if(!EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv)) {
    ret = false;
    goto done;
  }

  if(!EVP_DecryptUpdate(ctx, nullptr, &len, aad, aad_len)) {
    ret = false;
    goto done;
  }
  if(!EVP_DecryptUpdate(ctx, out, &len, in + blk_size, stream_len)) {
    ret = false;
    goto done;
  }
  plaintext_len = len;

  if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, blk_size, tag)) {
    ret = false;
    goto done;
  }

  // Finalize
  err = EVP_DecryptFinal_ex(ctx, in + in_len - blk_size, &len);
  if (err <= 0) {
    ret = false;
    goto done;
  }

  *out_size = plaintext_len;

done:
  if (ctx != nullptr)
    EVP_CIPHER_CTX_free(ctx);
  return ret;
}

bool certifier::utilities::authenticated_encrypt(const char* alg_name, byte* in,
            int in_len, byte *key, byte *iv, byte *out, int* out_size) {

  if (strcmp(alg_name, "aes-256-cbc-hmac-sha256") == 0) {
    return aes_256_cbc_sha256_encrypt(in, in_len, key, iv, out, out_size);
  } else if (strcmp(alg_name, "aes-256-cbc-hmac-sha384") == 0) {
    return aes_256_cbc_sha384_encrypt(in, in_len, key, iv, out, out_size);
  } else if (strcmp(alg_name, "aes-256-gcm") == 0) {
    return aes_256_gcm_encrypt(in, in_len, key, iv, out, out_size);
  } else {
    printf("authenticated_decrypt: unsupported algorithm %s\n", alg_name);
    return false;
  }
}

bool certifier::utilities::authenticated_decrypt(const char* alg_name, byte* in,
            int in_len, byte *key, byte *out, int* out_size) {

  if (strcmp(alg_name, "aes-256-cbc-hmac-sha256") == 0) {
    return aes_256_cbc_sha256_decrypt(in, in_len, key, out, out_size);
  } else if (strcmp(alg_name, "aes-256-cbc-hmac-sha384") == 0) {
    return aes_256_cbc_sha384_decrypt(in, in_len, key, out, out_size);
  } else if (strcmp(alg_name, "aes-256-gcm") == 0) {
    return aes_256_gcm_decrypt(in, in_len, key, out, out_size);
  } else {
    printf("authenticated_decrypt: unsupported algorithm %s\n", alg_name);
    return false;
  }
}

const int rsa_alg_type = 1;
const int ecc_alg_type = 2;
bool certifier::utilities::private_key_to_public_key(const key_message& in,
      key_message* out) {

  int n_bytes = 0;
  int alg_type = 0;
  if (in.key_type() == "rsa-2048-private") {
    alg_type = rsa_alg_type;
    out->set_key_type("rsa-2048-public");
    n_bytes = cipher_block_byte_size("rsa-2048-public");
  } else if (in.key_type() == "rsa-1024-private") {
    alg_type = rsa_alg_type;
    out->set_key_type("rsa-1024-public");
    n_bytes = cipher_block_byte_size("rsa-1024-public");
  } else if (in.key_type() == "rsa-3072-private") {
    alg_type = rsa_alg_type;
    out->set_key_type("rsa-3072-public");
    n_bytes = cipher_block_byte_size("rsa-3072-public");
  } else if (in.key_type() == "rsa-4096-private") {
    alg_type = rsa_alg_type;
    out->set_key_type("rsa-4096-public");
    n_bytes = cipher_block_byte_size("rsa-4096-public");
  } else if (in.key_type() == "ecc-384-private") {
    alg_type = ecc_alg_type;
    out->set_key_type("ecc-384-public");
    n_bytes = cipher_block_byte_size("ecc-384-public");
  } else if (in.key_type() == "ecc-256-private") {
    alg_type = ecc_alg_type;
    out->set_key_type("ecc-256-public");
    n_bytes = cipher_block_byte_size("ecc-256-public");
  } else {
    // Shut compiler warning about n_bytes set-but-not-used
    printf("private_key_to_public_key: bad key type (n_bytes=%d)\n", n_bytes);
    return false;
  }

  out->set_key_name(in.key_name());
  out->set_key_format(in.key_format());
  out->set_not_before(in.not_before());
  out->set_not_after(in.not_after());
  out->set_certificate(in.certificate().data(), in.certificate().size());

  if (alg_type == rsa_alg_type) {
    rsa_message* rk = new rsa_message;
    rk->set_public_modulus(in.rsa_key().public_modulus().data(),
        in.rsa_key().public_modulus().size());
    rk->set_public_exponent(in.rsa_key().public_exponent().data(),
        in.rsa_key().public_exponent().size());
    out->set_allocated_rsa_key(rk);
    return true;
  } else if (alg_type == ecc_alg_type) {
    ecc_message* ek = new ecc_message;
    ek->CopyFrom(in.ecc_key());
    ek->mutable_private_multiplier()->clear();
    out->set_allocated_ecc_key(ek);
    return true;
  } else {
    printf("private_key_to_public_key: bad key type\n");
    return false;
  }
}

bool make_certifier_rsa_key(int n,  key_message* k) {
  if (k == nullptr)
    return false;

  RSA* r = RSA_new();
  if (!generate_new_rsa_key(n, r)) {
    printf("make_certifier_rsa_key: Can't generate RSA key\n");
    return false;
  }

  if (n == 2048) {
    k->set_key_type("rsa-2048-private");
  } else if (n == 1024) {
    k->set_key_type("rsa-1024-private");
  } else if (n == 4096) {
    k->set_key_type("rsa-4096-private");
  } else if (n == 3072) {
    k->set_key_type("rsa-3072-private");
  } else {
    RSA_free(r);
    return false;
  }
  k->set_key_name("test-key-2");
  k->set_key_format("vse-key");
  if (!RSA_to_key(r, k)) {
    return false;
  }
  RSA_free(r);
  return true;
}

bool rsa_public_encrypt(RSA* key, byte* data, int data_len, byte *encrypted, int* size_out) {
  int n = RSA_public_encrypt(data_len, data, encrypted, key, RSA_PKCS1_PADDING);
  if (n <= 0) {
    printf("rsa_public_encrypt: RSA_public_encrypt failed %d, %d\n", data_len, *size_out);
    return false;
  }
  *size_out = n; 
  return true;
}

bool rsa_private_decrypt(RSA* key, byte* enc_data, int data_len,  byte* decrypted, int* size_out) {
  int  n = RSA_private_decrypt(data_len, enc_data, decrypted, key, RSA_PKCS1_PADDING);
  if (n <= 0) {
    printf("rsa_private_decrypt: RSA_private_decrypt failed %d, %d\n", data_len, *size_out);
    return false;
  }
  *size_out = n; 
  return true;
}

//  PKCS compliant signer
bool rsa_sha256_sign(RSA* key, int to_sign_size, byte* to_sign, int* sig_size, byte* sig) {
  return rsa_sign("sha-256", key, to_sign_size, to_sign, sig_size, sig);
}

bool rsa_sha256_verify(RSA*key, int size, byte* msg, int sig_size, byte* sig) {
  return rsa_verify("sha-256", key, size, msg , sig_size, sig);
}

bool rsa_sign(const char* alg, RSA* key, int size, byte* msg, int* sig_size, byte* sig) {

  EVP_MD_CTX* sign_ctx = EVP_MD_CTX_create();
  EVP_PKEY* private_key  = EVP_PKEY_new();
  EVP_PKEY_assign_RSA(private_key, key);

  unsigned int size_digest = 0;
  if (strcmp("sha-256", alg) == 0) {
    if (EVP_DigestSignInit(sign_ctx, nullptr, EVP_sha256(), nullptr, private_key) <= 0) {
        printf("rsa_sign: EVP_DigestSignInit failed\n");
        return false;
    }
    if (EVP_DigestSignUpdate(sign_ctx, msg, size) <= 0) {
        printf("rsa_sign: EVP_DigestSignUpdate failed\n");
      return false;
    }
    size_t t = *sig_size;
    if (EVP_DigestSignFinal(sign_ctx, sig, &t) <= 0) {
        printf("rsa_sign: EVP_DigestSignFinal failed\n");
        return false;
    }
    *sig_size = t;
  } else if(strcmp("sha-384", alg) == 0) {
    if (EVP_DigestSignInit(sign_ctx, nullptr, EVP_sha384(), nullptr, private_key) <= 0) {
        printf("rsa_sign: EVP_DigestSignInit failed\n");
        return false;
    }
    if (EVP_DigestSignUpdate(sign_ctx, msg, size) <= 0) {
        printf("rsa_sign: EVP_DigestSignUpdate failed\n");
      return false;
    }
    size_t t = *sig_size;
    if (EVP_DigestSignFinal(sign_ctx, sig, &t) <= 0) {
        printf("rsa_sign: EVP_DigestSignFinal failed\n");
        return false;
    }
    *sig_size = t;
  } else {
    printf("rsa_sign: unsuported digest\n");
    return false;
  }
  EVP_MD_CTX_destroy(sign_ctx);

  return true;
}

bool rsa_verify(const char* alg, RSA *key, int size, byte* msg, int sig_size, byte* sig) {

  if (strcmp("sha-256", alg) == 0) {
    unsigned int size_digest = digest_output_byte_size("sha-256");
    byte digest[size_digest];
    memset(digest, 0, size_digest);

    if (!digest_message("sha-256", (const byte*) msg, size, digest, size_digest)) {
      printf("rsa_verify: digest_message failed\n");
      return false;
    }
    int size_decrypted = RSA_size(key);
    byte decrypted[size_decrypted];
    memset(decrypted, 0, size_decrypted);
    int n = RSA_public_encrypt(sig_size, sig, decrypted, key, RSA_NO_PADDING);
    if (n < 0) {
      printf("rsa_verify: RSA_public_encrypt failed\n");
      return false;
    }
    if (memcmp(digest, &decrypted[n - size_digest], size_digest) != 0) {
      printf("rsa_verify: digests don't match\n");
      return false;
    }

    const int check_size = 16;
    byte check_buf[16] = {
      0x00, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    };
    if (memcmp(check_buf, decrypted, check_size) != 0) {
      printf("rsa_verify: Bad header\n");
      return false;
    }
    return memcmp(digest, &decrypted[n - size_digest], size_digest) == 0;
  } else if (strcmp("sha-384", alg) == 0) {
    unsigned int size_digest = digest_output_byte_size("sha-384");
    byte digest[size_digest];
    memset(digest, 0, size_digest);
    if (!digest_message("sha-384", (const byte*) msg, size, digest, size_digest)) {
      printf("digest_message failed\n");
      return false;
    }
    int size_decrypted = RSA_size(key);
    byte decrypted[size_decrypted];
    memset(decrypted, 0, size_decrypted);
    int n = RSA_public_encrypt(sig_size, sig, decrypted, key, RSA_NO_PADDING);
    if (n < 0) {
      printf("rsa_verify: RSA_public_encrypt failed\n");
      return false;
    }
    const int check_size = 16;
    byte check_buf[16] = {
      0x00, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    };
    if (memcmp(check_buf, decrypted, check_size) != 0) {
      printf("rsa_verify: Bad header\n");
      return false;
    }
    return memcmp(digest, &decrypted[n - size_digest], size_digest) == 0;
  } else {
    printf("rsa_verify: unsupported digest\n");
    return false;
  }
}

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

  bool private_key = true;
  int key_size_bits = 0;
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
  } else if (k.key_type() == "rsa-4096-private") {
    key_size_bits= 4096;
    private_key = true;
  } else if (k.key_type() == "rsa-4096-public") {
    key_size_bits= 4096;
    private_key = false;
  } else if (k.key_type() == "rsa-3072-private") {
    key_size_bits= 3072;
    private_key = true;
  } else if (k.key_type() == "rsa-3072-public") {
    key_size_bits= 3072;
    private_key = false;
  } else {
    // Shut compiler warning about key_size_bits set-but-not-used
    return (key_size_bits != 0);
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
  if (private_key) {
    BIGNUM *p = nullptr;
    BIGNUM *q = nullptr;
    BIGNUM *dmp1 = nullptr;
    BIGNUM *dmq1 = nullptr;
    BIGNUM *iqmp = nullptr;
    if (rsa_key_data.has_private_p()) {
      p = BN_bin2bn((const byte*) rsa_key_data.private_p().data(),
                (int)rsa_key_data.private_p().size(), NULL);
    }
    if (rsa_key_data.has_private_q()) {
      q = BN_bin2bn((const byte*) rsa_key_data.private_q().data(),
                (int)rsa_key_data.private_q().size(), NULL);
    }
    if (rsa_key_data.has_private_dp()) {
      dmp1 = BN_bin2bn((const byte*) rsa_key_data.private_dp().data(),
                (int)rsa_key_data.private_dp().size(), NULL);
    }
    if (rsa_key_data.has_private_dq()) {
      dmq1 = BN_bin2bn((const byte*) rsa_key_data.private_dq().data(),
                (int)rsa_key_data.private_dq().size(), NULL);
    }
    if (rsa_key_data.has_private_iqmp()) {
      iqmp = BN_bin2bn((const byte*) rsa_key_data.private_iqmp().data(),
                (int)rsa_key_data.private_iqmp().size(), NULL);
    }
    if (1 != RSA_set0_factors(r, p, q)) {
      return false;
    }
    if (1 != RSA_set0_crt_params(r, dmp1, dmq1, iqmp)) {
      return false;
    }
  }
  return true;
}

bool RSA_to_key(const RSA* r, key_message* k) {
  const BIGNUM* m = nullptr;
  const BIGNUM* e = nullptr;
  const BIGNUM* d = nullptr;
  const BIGNUM* p = nullptr;
  const BIGNUM* q = nullptr;
  const BIGNUM* dmp1 = nullptr;
  const BIGNUM* dmq1 = nullptr;
  const BIGNUM* iqmp = nullptr;
  
  k->set_key_format("vse-key");
  RSA_get0_key(r, &m, &e, &d);
  RSA_get0_factors(r, &p, &q);
  RSA_get0_crt_params(r, &dmp1, &dmq1, &iqmp);

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
  } else if (rsa_size == 4096) {
    if (d == nullptr)
      k->set_key_type("rsa-4096-public");
    else
      k->set_key_type("rsa-4096-private");
  } else if (rsa_size == 3072) {
    if (d == nullptr)
      k->set_key_type("rsa-3072-public");
    else
      k->set_key_type("rsa-3072-private");
  } else {
    return false;
  }
  rsa_message* rsa= new(rsa_message);
  k->set_allocated_rsa_key(rsa);

  int i;
  int size;
  if (m != nullptr) {
    size = BN_num_bytes(m);
    byte m_b[size];
    memset(m_b, 0, size);
    i = BN_bn2bin(m, m_b);
    rsa->set_public_modulus((void*)m_b, i);
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

    size = BN_num_bytes(p);
    byte p_b[size];
    memset(p_b, 0, size);
    i = BN_bn2bin(p, p_b);
    rsa->set_private_p((void*)p_b, i);

    size = BN_num_bytes(q);
    byte q_b[size];
    memset(q_b, 0, size);
    i = BN_bn2bin(q, q_b);
    rsa->set_private_q((void*)q_b, i);

    size = BN_num_bytes(dmp1);
    byte dmp1_b[size];
    memset(dmp1_b, 0, size);
    i = BN_bn2bin(dmp1, dmp1_b);
    rsa->set_private_dp((void*)dmp1_b, i);

    size = BN_num_bytes(dmq1);
    byte dmq1_b[size];
    memset(dmq1_b, 0, size);
    i = BN_bn2bin(dmq1, dmq1_b);
    rsa->set_private_dq((void*)dmq1_b, i);

    size = BN_num_bytes(iqmp);
    byte iqmp_b[size];
    memset(iqmp_b, 0, size);
    i = BN_bn2bin(iqmp, iqmp_b);
    rsa->set_private_iqmp((void*)iqmp_b, i);
  }
  return true;
}

void print_point(const point_message& pt) {
  if (!pt.has_x() || !pt.has_y())
    return;

  BIGNUM* x = BN_new();
  BIGNUM* y = BN_new();

  BN_bin2bn((byte*)pt.x().data(), pt.x().size(), x);
  BN_bin2bn((byte*)pt.y().data(), pt.y().size(), y);
  printf("(");
  BN_print_fp(stdout, x);
  printf(", ");
  BN_print_fp(stdout, y);
  printf(")");

  BN_free(x);
  BN_free(y);
}

void certifier::utilities::print_ecc_key(const ecc_message& em) {

  if (em.has_curve_name()) {
    printf("Curve name: %s\n", em.curve_name().c_str());
  }

  if (em.has_public_point()) {
    printf("Public point:\n");
    print_point(em.public_point());
    printf("\n");
  }

  if (em.has_base_point()) {
    printf("Base   point:\n");
    print_point(em.base_point());
    printf("\n");
  }

  if (em.has_order_of_base_point()) {
    BIGNUM* order = BN_new();
    BN_bin2bn((byte*)em.order_of_base_point().data(), em.order_of_base_point().size(), order);
    printf("order: ");
    BN_print_fp(stdout, order);
    printf("\n");
    BN_free(order);
  }

  if (em.has_private_multiplier()) {
    BIGNUM* private_mult = BN_new();

    BN_bin2bn((byte*)em.private_multiplier().data(), em.private_multiplier().size(), private_mult);
    printf("private multiplier: ");
    BN_print_fp(stdout, private_mult);
    printf("\n");

    BN_free(private_mult);
  } else {
    printf("No private multiplier\n");
  }

  if (em.has_curve_p() && em.has_curve_p() && em.has_curve_p()) {
    BIGNUM* p = BN_new();
    BIGNUM* a = BN_new();
    BIGNUM* b = BN_new();
  
    BN_bin2bn((byte*)em.curve_p().data(), em.curve_p().size(), p);
    BN_bin2bn((byte*)em.curve_a().data(), em.curve_a().size(), a);
    BN_bin2bn((byte*)em.curve_b().data(), em.curve_b().size(), b);

    printf("Curve parameters:\n");
    printf("  p: ");
    BN_print_fp(stdout, p);
    printf("\n");
    printf("  a: ");
    BN_print_fp(stdout, a);
    printf("\n");
    printf("  b: ");
    BN_print_fp(stdout, b);
    printf("\n");

    BN_free(p);
    BN_free(a);
    BN_free(b);
  }
}

//  ECC encrypt
//    G is generator, x is private key P=xG ia public key
//    Encrypt
//      Embed message m in P_m.  Pick random k.  Send (kG, kP + P_m)
//    Decrypt
//      compute Q=xkG = kP.  Subtract Q from kP + P_m = P_m.  Extract message from P_m.
bool ecc_sign(const char* alg, EC_KEY* key, int size, byte* msg, int* size_out, byte* out) {
  unsigned int len = (unsigned int)digest_output_byte_size(alg);
  byte digest[len];

  int blk_len = ECDSA_size(key);
  if (*size_out < 2 * blk_len) {
    printf("ecc_sign: size_out too small %d %d\n", *size_out, blk_len);
    return false;
  }

  if (!digest_message(alg, msg, size, digest, len)) {
    printf("ecc_sign: digest fails\n");
    return false;
  }
  unsigned int sz = (unsigned int) *size_out;
  if (ECDSA_sign(0, digest, len, out, &sz, key) != 1) {
    printf("ecc_sign: ECDSA_sign fails\n");
    return false;
  }
  *size_out = (int) sz;
  return true;
}

bool ecc_verify(const char* alg, EC_KEY* key, int size, byte* msg, int size_sig, byte* sig) {
  unsigned int len = (unsigned int)digest_output_byte_size(alg);
  byte digest[len];

  if (!digest_message(alg, msg, size, digest, len)) {
    printf("ecc_verify: %s digest failed %d\n", alg, len);
    return false;
  }
  int res = ECDSA_verify(0, digest, len, sig, size_sig, key);
  if (res != 1) {
    printf("ecc_verify: ECDSA_failed %d %d\n", len, size_sig);
    return false;
  }
  return true;
}

EC_KEY* certifier::utilities::generate_new_ecc_key(int num_bits) {

  EC_KEY* ecc_key = nullptr;
  if (num_bits == 384) {
    ecc_key = EC_KEY_new_by_curve_name(NID_secp384r1);
  } else if (num_bits == 256) {
    ecc_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  } else {
    printf("generate_new_ecc_key: Only P-256 and P-384 supported\n");
    return nullptr;
  }
  if (ecc_key == nullptr) {
    printf("generate_new_ecc_key: Can't get curve by name\n");
    return nullptr;
  }

  if (1 != EC_KEY_generate_key(ecc_key)) {
    printf("generate_new_ecc_key: Can't generate key\n");
    return nullptr;
  }

  BN_CTX* ctx = BN_CTX_new();
  const EC_GROUP* group = EC_KEY_get0_group(ecc_key);
  if (group == nullptr) {
    printf("generate_new_ecc_key: Can't get group (1)\n");
    return nullptr;
  }
  BIGNUM* pt_x = BN_new();
  BIGNUM* pt_y = BN_new();
  const EC_POINT* pt = EC_KEY_get0_public_key(ecc_key);
  EC_POINT_get_affine_coordinates_GFp(group, pt, pt_x, pt_y, ctx); 
  BN_CTX_free(ctx);

  return ecc_key;
}

// Todo: free k on error
EC_KEY* certifier::utilities::key_to_ECC(const key_message& k) {

  EC_KEY* ecc_key = nullptr;
  if (k.key_type() == "ecc-384-private" || k.key_type() == "ecc-384-public") {
    ecc_key = EC_KEY_new_by_curve_name(NID_secp384r1);
  } else if (k.key_type() == "ecc-256-private" || k.key_type() == "ecc-256-public") {
    ecc_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  } else {
    printf("key_to_ECC: wrong type %s\n", k.key_type().c_str());
    return nullptr;
  }
  if (ecc_key == nullptr) {
    printf("key_to_ECC: Can't get curve by name\n");
    return nullptr;
  }

  // set private multiplier
  const BIGNUM* priv_mult =  BN_bin2bn((byte*)(k.ecc_key().private_multiplier().data()),
                (int)(k.ecc_key().private_multiplier().size()), NULL);
  if (priv_mult == nullptr) {
    printf("key_to_ECC: not private mult\n");
    return nullptr;
  }
  if (EC_KEY_set_private_key(ecc_key, priv_mult) != 1) {
    printf("key_to_ECC: not can't set\n");
    return nullptr;
  }

  // set public point
  const EC_GROUP* group = EC_KEY_get0_group(ecc_key);
  if (group == nullptr) {
    printf("key_to_ECC: Can't get group (1)\n");
    return nullptr;
  }
  const BIGNUM* p_pt_x =  BN_bin2bn((byte*)(k.ecc_key().public_point().x().data()),
                (int)(k.ecc_key().public_point().x().size()), NULL);
  const BIGNUM* p_pt_y =  BN_bin2bn((byte*)(k.ecc_key().public_point().y().data()),
                (int)(k.ecc_key().public_point().y().size()), NULL);
  if (p_pt_x == nullptr || p_pt_y == nullptr) {
    printf("key_to_ECC: pts are null\n");
    return nullptr;
  }

  EC_POINT* pt = EC_POINT_new(group);
  if (pt == nullptr) {
    printf("key_to_ECC: no pt in group\n");
    return nullptr;
  }
  BN_CTX* ctx = BN_CTX_new();
  if (ctx == nullptr) {
    return nullptr;
  }
  if (EC_POINT_set_affine_coordinates_GFp(group, pt, p_pt_x, p_pt_y, ctx) != 1) {
    printf("key_to_ECC: can't set affine\n");
    return nullptr;
  }
  if (EC_KEY_set_public_key(ecc_key, pt) != 1) {
    printf("key_to_ECC: can't set public\n");
    return nullptr;
  }
  BN_CTX_free(ctx);

  return ecc_key;
}

bool certifier::utilities::ECC_to_key(const EC_KEY* ecc_key, key_message* k) {
  k->set_key_format("vse_key");

  ecc_message* ek = new ecc_message;
  if (ek == nullptr)
    return false;

  if (ecc_key == nullptr) {
    return false;
  }

  BN_CTX* ctx = BN_CTX_new();
  if (ctx == nullptr)
    return false;

  const EC_GROUP* group = EC_KEY_get0_group(ecc_key);
  if (group == nullptr) {
    printf("ECC_to_key: Can't get group (2)\n");
    return false;
  }

  BIGNUM* p = BN_new();
  BIGNUM* a = BN_new();
  BIGNUM* b = BN_new();
  if (EC_GROUP_get_curve_GFp(group, p, a, b, ctx) <= 0) {
    BN_CTX_free(ctx);
    return false;
  }

  int modulus_size = BN_num_bytes(p);

  if (modulus_size == 48) {
    k->set_key_type("ecc-384-public");
    ek->set_curve_name("P-384");
  } else if (modulus_size == 32) {
    k->set_key_type("ecc-256-public");
    ek->set_curve_name("P-256");
  } else {
    printf("ECC_to_key: Modulus size not supported: %d\n", modulus_size);
    return false;
  }

  // set p, a, b
  int sz  = BN_num_bytes(p);
  byte p_buf[sz];
  sz  = BN_bn2bin(p, p_buf);
  ek->mutable_curve_p()->assign((char*)p_buf, sz);

  sz  = BN_num_bytes(a);
  byte a_buf[sz];
  sz  = BN_bn2bin(a, a_buf);
  ek->mutable_curve_a()->assign((char*)a_buf, sz);

  sz  = BN_num_bytes(b);
  byte b_buf[sz];
  sz  = BN_bn2bin(b, b_buf);
  ek->mutable_curve_b()->assign((char*)b_buf, sz);

  BN_free(p);
  BN_free(a);
  BN_free(b);

  // set base_point
  const EC_POINT* generator = EC_GROUP_get0_generator(group);
  if (generator == nullptr) {
    printf("ECC_to_key: Can't get base point\n");
    BN_CTX_free(ctx);
    return false;
  }
  BIGNUM* x = BN_new();
  BIGNUM* y = BN_new();
  if (EC_POINT_get_affine_coordinates_GFp(group,
        generator, x, y, ctx) != 1) {
    printf("ECC_to_key: Can't get affine coordinates\n");
    BN_CTX_free(ctx);
    return false;
  }

  sz  = BN_num_bytes(x);
  byte x_buf[sz];
  sz  = BN_bn2bin(x, x_buf);
  point_message* b_pt= new point_message;
  ek->set_allocated_base_point(b_pt);
  b_pt->set_x((void*)x_buf, sz);

  sz  = BN_num_bytes(y);
  byte y_buf[sz];
  sz  = BN_bn2bin(y, y_buf);
  b_pt->set_y((void*)y_buf, sz);
  BN_free(x);
  BN_free(y);

  // set public_point
  const EC_POINT* pub_pt= EC_KEY_get0_public_key(ecc_key);
  if (pub_pt == nullptr) {
    printf("ECC_to_key: Can't get public point\n");
    BN_CTX_free(ctx);
    return false;
  }

  BIGNUM* xx = BN_new();
  BIGNUM* yy = BN_new();
  if (EC_POINT_get_affine_coordinates_GFp(group,
        pub_pt, xx, yy, ctx) != 1) {
    printf("ECC_to_key: Can't get affine coordinates\n");
    BN_CTX_free(ctx);
    return false;
  }
  sz  = BN_num_bytes(xx);
  byte xx_buf[sz];
  sz  = BN_bn2bin(xx, xx_buf);
  point_message* p_pt= new point_message;
  ek->set_allocated_public_point(p_pt);
  p_pt->set_x((void*)xx_buf, sz);
  sz  = BN_num_bytes(yy);
  byte yy_buf[sz];
  sz  = BN_bn2bin(yy, yy_buf);
  p_pt->set_y((void*)yy_buf, sz);
  BN_free(xx);
  BN_free(yy);

  // set order_of_base_point
  BIGNUM* order = BN_new();
  if (EC_GROUP_get_order(group, order, ctx) != 1) {
    printf("ECC_to_key: Can't get order\n");
    BN_free(order);
    BN_CTX_free(ctx);
    return false;
  }
  sz  = BN_num_bytes(order);
  byte order_buf[sz];
  sz  = BN_bn2bin(order, order_buf);
  ek->set_order_of_base_point((void*)order_buf, sz);
  BN_free(order);

  // set private_multiplier
  const BIGNUM* pk = EC_KEY_get0_private_key(ecc_key);
  if (pk != nullptr) {
    if (modulus_size == 48) {
      k->set_key_type("ecc-384-private");
    } else if (modulus_size == 32) {
      k->set_key_type("ecc-256-private");
    } else {
      return false;
    }
    sz  = BN_num_bytes(pk);
    byte pm_buf[sz];
    sz  = BN_bn2bin(pk, pm_buf);
    ek->set_private_multiplier((void*)pm_buf, sz);
  }

  k->set_allocated_ecc_key(ek);
  BN_CTX_free(ctx);
  return true;
}

bool make_certifier_ecc_key(int n,  key_message* k) {
  if (k == nullptr)
    return false;
  if (n == 384) {
    k->set_key_type("ecc-384-private");
  } else if (n == 256) {
    k->set_key_type("ecc-256-private");
  } else {
    printf("make_certifier_ecc_key: unsupported key size\n");
    return false;
  }

  EC_KEY* ek = generate_new_ecc_key(n);
  if (ek == nullptr)
    return false;

  k->set_key_name("test-key-2");
  k->set_key_format("vse-key");
  if (!ECC_to_key(ek, k)) {
    return false;
  }
  EC_KEY_free(ek);
  return true;
}

// -----------------------------------------------------------------------

bool certifier::utilities::get_random(int num_bits, byte* out) {
  bool ret = true;
  int k = 0;
  int n = ((num_bits + num_bits_in_byte - 1) / num_bits_in_byte);

  int in = open("/dev/random", O_RDONLY, 0644);
  while (k < n) {
    int m = read(in, out + k, n - k);
    if (m < 0) {
      ret = false;
      break;
    }
    k += m;
  }
  close(in);
  return ret;
}

// may want to check leading 0's
bool same_point(const point_message& pt1, const point_message& pt2) {
  if (pt1.x().size() != pt2.x().size())
    return false;
  if (pt1.y().size() != pt2.y().size())
    return false;
  if (memcmp(pt1.x().data(),pt1.x().data(), pt1.x().size()) != 0)
    return false;
  if (memcmp(pt1.y().data(),pt1.y().data(), pt1.y().size()) != 0)
    return false;
  return true;
}

bool same_key(const key_message& k1, const key_message& k2) {
  if (k1.key_type() != k2.key_type())
    return false;
  if (k1.key_type() == "rsa-2048-private" || k1.key_type() == "rsa-2048-public" ||
      k1.key_type() == "rsa-1024-private" || k1.key_type() == "rsa-1024-public" ||
      k1.key_type() == "rsa-3072-private" || k1.key_type() == "rsa-3072-public" ||
      k1.key_type() == "rsa-4096-private" || k1.key_type() == "rsa-4096-public") {
    string b1, b2;
    if (!k1.has_rsa_key() || !k2.has_rsa_key())
      return false;
    if (k1.rsa_key().public_modulus() != k2.rsa_key().public_modulus())
      return false;
    if (k1.rsa_key().public_exponent() != k2.rsa_key().public_exponent())
      return false;
    return true;
  } else if (k1.key_type() == "aes-256-cbc-hmac-sha256" ||
            k1.key_type() == "aes-256-cbc" || k1.key_type() == "aes-256") {
    if (!k1.has_secret_key_bits())
      return false;
    if (k1.secret_key_bits().size() != k2.secret_key_bits().size())
      return false;
    return (memcmp(k1.secret_key_bits().data(), k2.secret_key_bits().data(), k1.secret_key_bits().size()) == 0);
  } else if (k1.key_type() == "ecc-384-public" || k1.key_type() == "ecc-384-private") {
    const ecc_message& em1 = k1.ecc_key();
    const ecc_message& em2 = k2.ecc_key();
    if (em1.curve_p().size() != em2.curve_p().size() ||
        memcmp(em1.curve_p().data(),em2.curve_p().data(), em1.curve_p().size()) != 0)
      return false;
    if (em1.curve_a().size() != em2.curve_a().size() ||
          memcmp(em1.curve_a().data(),em1.curve_a().data(), em2.curve_a().size()) != 0)
      return false;
    if (em1.curve_b().size() != em2.curve_b().size() ||
           memcmp(em1.curve_b().data(),em1.curve_b().data(), em2.curve_b().size()) != 0)
      return false;
    if (!same_point(em1.base_point(), em2.base_point()))
      return false;
    if (!same_point(em1.public_point(), em2.public_point()))
      return false;
    return true;
  } else if (k1.key_type() == "ecc-256-public" || k1.key_type() == "ecc-256-private") {
    const ecc_message& em1 = k1.ecc_key();
    const ecc_message& em2 = k2.ecc_key();
    if (em1.curve_p().size() != em2.curve_p().size() ||
        memcmp(em1.curve_p().data(),em2.curve_p().data(), em1.curve_p().size()) != 0)
      return false;
    if (em1.curve_a().size() != em2.curve_a().size() ||
          memcmp(em1.curve_a().data(),em1.curve_a().data(), em2.curve_a().size()) != 0)
      return false;
    if (em1.curve_b().size() != em2.curve_b().size() ||
           memcmp(em1.curve_b().data(),em1.curve_b().data(), em2.curve_b().size()) != 0)
      return false;
    if (!same_point(em1.base_point(), em2.base_point()))
      return false;
    if (!same_point(em1.public_point(), em2.public_point()))
      return false;
    return true;
  } else {
    return false;
  }
  return true;
}

bool same_measurement(const string& m1, const string& m2) {
  if (m1.size() != m2.size())
    return false;
  if (memcmp((byte*)m1.data(), (byte*)m2.data(), m1.size()) != 0)
    return false;
  return true;
}

bool same_property(const property& p1, const property& p2) {
  if (p1.property_name() != p2.property_name())
    return false;
  if (p1.value_type() != p2.value_type())
    return false;
  if (p1.comparator() != p2.comparator())
    return false;
  if (p1.value_type() == "int")
    return p1.int_value() == p2.int_value();
  if (p1.value_type() == "string")
    return p1.string_value() == p2.string_value();
  return true;
}

const property* find_property(const string& name, const properties& p) {
  for (int i = 0; i < p.props_size(); i++) {
    if (p.props(i).property_name() == name)
      return &p.props(i);
  }
  return nullptr;
}

bool satisfying_property(const property& p1, const property& p2) {
  if (p1.comparator() == "=")
    return same_property(p1, p2);
  if (p1.comparator() != ">=" || p1.property_name() != p2.property_name() ||
      p1.value_type() != p2.value_type() || p1.value_type() != "int") {
    return false;
  }
  return p2.int_value() >= p1.int_value();
}

bool satisfying_properties(const properties& p1, const properties& p2) {
  for (int i = 0; i < p1.props_size(); i++) {
    const property* pp2 = find_property(p1.props(i).property_name(), p2);
    if (pp2 == nullptr) {
      printf("Can't find %s\n", p1.props(i).property_name().c_str());
      return false;
    }
    if (!satisfying_property(p1.props(i), *pp2)) {
      printf("mismatch\n");
      print_property(p1.props(i)); printf("\n");
      print_property(*pp2); printf("\n");
      return false;
    }
  }
  return true;
}

bool satisfying_platform(const platform& p1, const platform& p2) {

  if (p1.platform_type() != p2.platform_type())
    return false;
  if (p1.has_key() && p2.has_key()) {
    if (!same_key(p1.attest_key(), p2.attest_key()))
      return false;
  }

  return satisfying_properties(p1.props(), p2.props());
}

bool same_properties(const properties& p1, const properties& p2) {
  for (int i = 0; i < p1.props_size(); i++) {
    const property* pp2 = find_property(p1.props(i).property_name(), p2);
    if (pp2 == nullptr)
      return false;
    if (!same_property(p1.props(i), *pp2))
      return false;
  }
  return true;
}

bool same_platform(const platform& p1, const platform& p2) {

  if (p1.platform_type() != p2.platform_type()) {
    return false;
  }
  if (p1.has_key() && p2.has_key()) {
    if (!same_key(p1.attest_key(), p2.attest_key())) {
      printf("same_platform fails: keys dont match\n");
      print_key(p1.attest_key()); printf("\n");
      print_key(p2.attest_key()); printf("\n");
      return false;
    }
  }

  return same_properties(p1.props(), p2.props());
}

bool same_environment(const environment& e1, const environment& e2) {
  if (!same_measurement(e1.the_measurement(), e2.the_measurement()))
    return false;
  return same_platform(e1.the_platform(), e2.the_platform());
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

  if (e1.entity_type() == "platform")
    return same_platform(e1.platform_ent(), e2.platform_ent());

  if (e1.entity_type() == "environment")
    return same_environment(e1.environment_ent(), e2.environment_ent());

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

bool make_measurement_entity(const string& measurement, entity_message* ent) {
  ent->set_entity_type("measurement");
  string* m = new string(measurement);
  ent->set_allocated_measurement(m);
  return true;
}

bool make_platform_entity(platform& plat, entity_message* ent) {
  ent->set_entity_type("platform");
  ent->mutable_platform_ent()->CopyFrom(plat);
  return true;
}

bool make_platform(const string& type, const properties& p, const key_message* at,
      platform* plat) {
  plat->set_platform_type(type);
  if (at != nullptr) {
    plat->mutable_attest_key()->CopyFrom(*at);
    plat->set_has_key(true);
  } else {
    plat->set_has_key(false);
  }
  for (int i = 0; i < p.props_size(); i++) {
    plat->mutable_props()->add_props()->CopyFrom(p.props(i));
  }

  return true;
}

bool make_property(string& name, string& type, string& cmp, uint64_t int_value,
    string& string_value, property* prop) {
  prop->set_property_name(name);
  prop->set_comparator(cmp);
  if (type == "int") {
    prop->set_value_type("int");
    prop->set_int_value(int_value);
  } else if (type == "string") {
    prop->set_value_type("string");
    prop->set_string_value(string_value);
  } else {
    printf("make_property: unrecognized type: %s\n", type.c_str());
    return false;
  }
  printf("\n");

  return true;
}

bool make_environment_entity(environment& env, entity_message* ent) {
  ent->set_entity_type("environment");
  ent->mutable_environment_ent()->CopyFrom(env);
  return true;
}

bool make_environment(const platform& plat, const string& measurement,
      environment* env) {
  env->mutable_the_platform()->CopyFrom(plat);
  env->set_the_measurement(measurement);
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

// -----------------------------------------------------------------------

void certifier::utilities::print_bytes(int n, byte* buf) {
  for(int i = 0; i < n; i++)
    printf("%02x", buf[i]);
}

void certifier::utilities::print_rsa_key(const rsa_message& rsa) {
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

void certifier::utilities::print_key(const key_message& k) {
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
    print_ecc_key(k.ecc_key());
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
      k.key_type() == "rsa-3072-private" || k.key_type() == "rsa-3072-public" ||
      k.key_type() == "rsa-1024-private" || k.key_type() == "rsa-1024-public" ||
      k.key_type() == "rsa-4096-private" || k.key_type() == "rsa-4096-public") {
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
      printf("]");
    }
  } else if (k.key_type() == "ecc-384-private" || k.key_type() == "ecc-384-public" ||
        k.key_type() == "ecc-256-private" || k.key_type() == "ecc-256-public") {
    printf("Key[ecc, ");
    if (k.has_key_name()) {
      printf("%s, ", k.key_name().c_str());
    }
    if (k.has_ecc_key()) {
      printf("%s-", k.ecc_key().curve_name().c_str());
      print_bytes(k.ecc_key().base_point().x().size(), (byte*)k.ecc_key().base_point().x().data());
      printf("_");
      print_bytes(k.ecc_key().base_point().y().size(), (byte*)k.ecc_key().base_point().y().data());
      printf("]");
    }
  } else {
    printf(" unsupported type %s ", k.key_type().c_str());
  }
}

void print_property_descriptor(const property& p) {
  printf("%s: ", p.property_name().c_str());
  if (p.value_type() == "int") {
    if (p.comparator() != "")
      printf(" %s", p.comparator().c_str());
    printf(" %" PRIu64, p.int_value());
  } else if (p.value_type() == "string") {
    printf(" %s", p.string_value().c_str());
  } else {
    return;
  }
}

void print_platform_descriptor(const platform& pl) {
    printf("platform[%s", pl.platform_type().c_str());
    if (pl.has_key()) {
      printf(", key: ");
      print_key_descriptor(pl.attest_key());
    } else {
      printf(", no key");
    }
    for (int i = 0; i < pl.props().props_size(); i++) {
      printf(", ");
      print_property_descriptor(pl.props().props(i));
    }
    printf("]");
}

void print_environment_descriptor(const environment& env) {
    printf("environment[");
    print_platform_descriptor(env.the_platform());
    printf(", measurement: ");
    print_bytes(env.the_measurement().size(), (byte*)env.the_measurement().data());
    printf("]");
}

void print_entity_descriptor(const entity_message& e) {
  if (e.entity_type() == "key" && e.has_key()) {
    print_key_descriptor(e.key());
  } else if (e.entity_type() == "measurement" && e.has_measurement()) {
    printf("Measurement[");
    print_bytes((int)e.measurement().size(), (byte*)e.measurement().data());
    printf("] ");
  } else if (e.entity_type() == "platform" && e.has_platform_ent()) {
    print_platform_descriptor(e.platform_ent());
  } else if (e.entity_type() == "environment" && e.has_environment_ent()) {
    print_environment_descriptor(e.environment_ent());
  } else {
    printf("entity_type: %s\n", e.entity_type().c_str());
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

void certifier::utilities::print_entity(const entity_message& em) {
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

bool make_signed_claim( const char* alg, const claim_message& claim, const key_message& key,
    signed_claim_message* out) {

  string serialized_claim;
  if(!claim.SerializeToString(&serialized_claim)) {
    printf("make_signed_claim: serialize claim failed\n");
    return false;
  }

  out->set_signing_algorithm(alg);
  out->set_serialized_claim_message((void*)serialized_claim.data(), serialized_claim.size());

  int sig_size = 0;
  bool success = false;
  if (strcmp(alg, "rsa-2048-sha256-pkcs-sign") == 0) {
    RSA* r = RSA_new();
    if (!key_to_RSA(key, r)) {
      printf("make_signed_claim: key_to_RSA failed\n");
      return false;
    }

    sig_size = RSA_size(r);
    byte sig[sig_size];
    success = rsa_sha256_sign(r, serialized_claim.size(), (byte*)serialized_claim.data(),
      &sig_size, sig);
    RSA_free(r);

    // sign serialized claim
    key_message* psk = new key_message;
    if (!private_key_to_public_key(key, psk)) {
      printf("make_signed_claim: private_key_to_public_key failed\n");
      return false;
    }
    out->set_allocated_signing_key(psk);
    out->set_signing_algorithm(alg);
    out->set_signature((void*)sig, sig_size);
  } else if (strcmp(alg, "rsa-3072-sha384-pkcs-sign") == 0) {
    RSA* r = RSA_new();
    if (!key_to_RSA(key, r)) {
      printf("make_signed_claim: key_to_RSA failed\n");
      return false;
    }

    sig_size = RSA_size(r);
    byte sig[sig_size];
    success = rsa_sign("sha-384", r, serialized_claim.size(), (byte*)serialized_claim.data(),
      &sig_size, sig);
    if (!success) {
      printf("make_signed_claim: rsa_sign failed\n");
      return false;
    }
    RSA_free(r);

    // sign serialized claim
    key_message* psk = new key_message;
    if (!private_key_to_public_key(key, psk)) {
      printf("make_signed_claim: private_key_to_public_key failed\n");
      return false;
    }
    out->set_allocated_signing_key(psk);
    out->set_signing_algorithm(alg);
    out->set_signature((void*)sig, sig_size);
  } else if (strcmp(alg, "rsa-4096-sha384-pkcs-sign") == 0) {
    RSA* r = RSA_new();
    if (!key_to_RSA(key, r)) {
      printf("make_signed_claim: key_to_RSA failed\n");
      return false;
    }

    sig_size = RSA_size(r);
    byte sig[sig_size];
    success = rsa_sign("sha-384", r, serialized_claim.size(), (byte*)serialized_claim.data(),
      &sig_size, sig);
    if (!success) {
      printf("make_signed_claim: rsa_sign failed\n");
    }
    RSA_free(r);

    // sign serialized claim
    key_message* psk = new key_message;
    if (!private_key_to_public_key(key, psk)) {
      printf("make_signed_claim: private_key_to_public_key failed\n");
      return false;
    }
    out->set_allocated_signing_key(psk);
    out->set_signing_algorithm(alg);
    out->set_signature((void*)sig, sig_size);
  } else if (strcmp(alg, "ecc-384-sha384-pkcs-sign") == 0) {
    EC_KEY* k = key_to_ECC(key);
    if (k == nullptr) {
      printf("make_signed_claim: to_ECC failed\n");
      return false;
    }
    sig_size = 2 * ECDSA_size(k);
    byte sig[sig_size];

    success = ecc_sign("sha-384", k, serialized_claim.size(), (byte*)serialized_claim.data(),
      &sig_size, sig);
    EC_KEY_free(k);

    // sign serialized claim
    key_message* psk = new key_message;
    if (!private_key_to_public_key(key, psk)) {
      printf("make_signed_claim: private_key_to_public_key failed\n");
      return false;
    }
    out->set_allocated_signing_key(psk);
    out->set_signature((void*)sig, sig_size);
  } else if (strcmp(alg, "ecc-256-sha256-pkcs-sign") == 0) {
    EC_KEY* k = key_to_ECC(key);
    if (k == nullptr) {
      printf("make_signed_claim: to_ECC failed\n");
      return false;
    }
    sig_size = 2 * ECDSA_size(k);
    byte sig[sig_size];

    success = ecc_sign("sha-256", k, serialized_claim.size(), (byte*)serialized_claim.data(),
      &sig_size, sig);
    EC_KEY_free(k);

    // sign serialized claim
    key_message* psk = new key_message;
    if (!private_key_to_public_key(key, psk))
      return false;
    out->set_allocated_signing_key(psk);
    out->set_signature((void*)sig, sig_size);
  } else {
    return false;
  }
  return success;
}

bool verify_signed_claim(const signed_claim_message& signed_claim, const key_message& key) {

  if (!signed_claim.has_serialized_claim_message()) {
    printf("verify_signed_claim: no serialized claim\n");
    return false;
  }
  if (!signed_claim.has_signing_key()) {
    printf("verify_signed_claim: no signing key\n");
    return false;
  }
  if (!signed_claim.has_signing_algorithm()) {
    printf("verify_signed_claim: no signing alg\n");
    return false;
  }
  if (!signed_claim.has_signature()) {
    printf("verify_signed_claim: no signature\n");
    return false;
  }

  string serialized_claim;
  serialized_claim.assign((char*)signed_claim.serialized_claim_message().data(),
    signed_claim.serialized_claim_message().size());
  claim_message c;
  if (!c.ParseFromString(serialized_claim)) {
    printf("verify_signed_claim: can't deserialize signed claim\n");
    return false;
  }

  if (!c.has_claim_format()) {
    printf("verify_signed_claim: not claim format\n");
    return false;
  }
  if (c.claim_format() != "vse-clause" && c.claim_format() != "vse-attestation") {
    printf("verify_signed_claim: %s should be vse-clause or vse-attestation\n",
        c.claim_format().c_str());
    return false;
  }

  time_point t_now; 
  time_point t_nb;
  time_point t_na;

  if (!time_now(&t_now)) {
    printf("verify_signed_claim: time_now failed\n");
    return false;
  }
  if (!string_to_time(c.not_before(), &t_nb)) {
    printf("verify_signed_claim: string_to_time failed\n");
    return false;
  }
  if (!string_to_time(c.not_after(), &t_na)) {
    printf("verify_signed_claim: string_to_time failed\n");
    return false;
  }

  if (compare_time(t_now, t_nb) <  0) {
    printf("verify_signed_claim: Bad time compare 1\n");
    return false;
  }
  if (compare_time(t_na, t_now) < 0) {
    printf("verify_signed_claim: Bad time compare 2\n");
     return false;
  }

  bool success = false;
  if (signed_claim.signing_algorithm() == "rsa-2048-sha256-pkcs-sign") {
    RSA* r = RSA_new();
    if (!key_to_RSA(key, r)) {
      printf("verify_signed_claim: key_to_RSA failed\n");
      return false;
    }
    success = rsa_sha256_verify(r, (int)signed_claim.serialized_claim_message().size(),
        (byte*)signed_claim.serialized_claim_message().data(), (int)signed_claim.signature().size(),
        (byte*)signed_claim.signature().data());
    RSA_free(r);
  } else if (signed_claim.signing_algorithm() == "rsa-3072-sha384-pkcs-sign") {
    RSA* r = RSA_new();
    if (!key_to_RSA(key, r)) {
      printf("verify_signed_claim: key_to_RSA failed\n");
      return false;
    }
    success = rsa_verify("sha-384", r, (int)signed_claim.serialized_claim_message().size(),
        (byte*)signed_claim.serialized_claim_message().data(), (int)signed_claim.signature().size(),
        (byte*)signed_claim.signature().data());
    RSA_free(r);
  } else if (signed_claim.signing_algorithm() == "rsa-4096-sha384-pkcs-sign") {
    RSA* r = RSA_new();
    if (!key_to_RSA(key, r)) {
      printf("verify_signed_claim: key_to_RSA failed\n");
      return false;
    }
    success = rsa_verify("sha-384", r, (int)signed_claim.serialized_claim_message().size(),
        (byte*)signed_claim.serialized_claim_message().data(), (int)signed_claim.signature().size(),
        (byte*)signed_claim.signature().data());
    RSA_free(r);
  } else if (signed_claim.signing_algorithm() == "ecc-384-sha384-pkcs-sign") {
    EC_KEY* k = key_to_ECC(key);
    if (k == nullptr) {
      printf("verify_signed_claim: key_to_ECC failed\n");
      return false;
    }
    success = ecc_verify("sha-384", k, (int)signed_claim.serialized_claim_message().size(),
        (byte*)signed_claim.serialized_claim_message().data(), (int)signed_claim.signature().size(),
        (byte*)signed_claim.signature().data());
    EC_KEY_free(k);
  } else if (signed_claim.signing_algorithm() == "ecc-256-sha256-pkcs-sign") {
    EC_KEY* k = key_to_ECC(key);
    if (k == nullptr) {
      return false;
    }
    success = ecc_verify("sha-256", k, (int)signed_claim.serialized_claim_message().size(),
        (byte*)signed_claim.serialized_claim_message().data(), (int)signed_claim.signature().size(),
        (byte*)signed_claim.signature().data());
    EC_KEY_free(k);
  } else {
    printf("verify_signed_claim: unsupported signing algorithm\n");
    return false;
  }

  return success;
}

// -----------------------------------------------------------------------

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

// -----------------------------------------------------------------------

int add_ext(X509 *cert, int nid, const char *value) {
  X509_EXTENSION *ex;
  X509V3_CTX ctx;

  // This sets the 'context' of the extensions.
  X509V3_set_ctx_nodb(&ctx);

  X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
  ex = X509V3_EXT_nconf_nid(NULL, &ctx, nid, value);
  if(!ex)
    return 0;

  X509_add_ext(cert,ex, -1);
  X509_EXTENSION_free(ex);
  return 1;
}

// Caller should have allocated X509
// name is some printable version of the measurement
bool certifier::utilities::produce_artifact(
                      key_message& signing_key, string& issuer_name_str,
                      string& issuer_organization_str, key_message& subject_key,
                      string& subject_name_str, string& subject_organization_str,
                      uint64_t sn, double secs_duration, X509* x509, bool is_root) {

  ASN1_INTEGER* a = ASN1_INTEGER_new();
  ASN1_INTEGER_set_uint64(a, sn);
  X509_set_serialNumber(x509, a);
  X509_set_version(x509, 2L);

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

  EVP_PKEY* signing_pkey = EVP_PKEY_new();
  if (signing_key.key_type() == "rsa-1024-private" ||
      signing_key.key_type() == "rsa-2048-private" ||
      signing_key.key_type() == "rsa-3072-private" ||
      signing_key.key_type() == "rsa-4096-private") {
    RSA* signing_rsa_key = RSA_new();
    if (!key_to_RSA(signing_key, signing_rsa_key)) {
      printf("produce_artifact: can't get rsa signing key\n");
      return false;
    }
    EVP_PKEY_set1_RSA(signing_pkey, signing_rsa_key);
    X509_set_pubkey(x509, signing_pkey);

    EVP_PKEY* subject_pkey = EVP_PKEY_new();
    if (subject_key.key_type() == "rsa-1024-public" ||
        subject_key.key_type() == "rsa-2048-public" ||
        subject_key.key_type() == "rsa-4096-public" ||
        subject_key.key_type() == "rsa-3072-public" ||
        subject_key.key_type() == "rsa-1024-private" ||
        subject_key.key_type() == "rsa-2048-private" ||
        subject_key.key_type() == "rsa-3072-private" ||
        subject_key.key_type() == "rsa-4096-private") {
      RSA* subject_rsa_key = RSA_new();
      if (!key_to_RSA(subject_key, subject_rsa_key)) {
        printf("produce_artifact: can't get rsa subject key\n");
        return false;
      }
      EVP_PKEY_set1_RSA(subject_pkey, subject_rsa_key);
      X509_set_pubkey(x509, subject_pkey);
      RSA_free(subject_rsa_key);
    } else if (subject_key.key_type() == "ecc-384-public" ||
               subject_key.key_type() == "ecc-384-private" ||
               subject_key.key_type() == "ecc-256-public" ||
               subject_key.key_type() == "ecc-256-private") {
      EC_KEY* subject_ecc_key = key_to_ECC(subject_key);
      if (subject_ecc_key == nullptr) {
        printf("produce_artifact: can't get subject key\n");
        return false;
      }
      EVP_PKEY_set1_EC_KEY(subject_pkey, subject_ecc_key);
      X509_set_pubkey(x509, subject_pkey);
      EC_KEY_free(subject_ecc_key);
    } else {
        printf("produce_artifact: unknown public key type %s\n",
          subject_key.key_type().c_str());
        return false;
    }
    if (signing_key.key_type() == "rsa-4096-private" ||
        signing_key.key_type() == "ecc-384-private") {
      X509_sign(x509, signing_pkey, EVP_sha384());
    } else {
      X509_sign(x509, signing_pkey, EVP_sha256());
    }
    EVP_PKEY_free(signing_pkey);
    EVP_PKEY_free(subject_pkey);
    RSA_free(signing_rsa_key);
  } else if (signing_key.key_type() == "ecc-384-private" ||
            signing_key.key_type() == "ecc-256-private") {
    EC_KEY* signing_ecc_key = key_to_ECC(signing_key);
    if (signing_ecc_key == nullptr) {
      printf("produce_artifact: can't get signing key\n");
      return false;
    }
    EVP_PKEY* signing_pkey = EVP_PKEY_new();
    EVP_PKEY_set1_EC_KEY(signing_pkey, signing_ecc_key);
    X509_set_pubkey(x509, signing_pkey);

    EVP_PKEY* subject_pkey = EVP_PKEY_new();
    if (subject_key.key_type() == "rsa-1024-public" ||
        subject_key.key_type() == "rsa-2048-public" ||
        subject_key.key_type() == "rsa-3072-public" ||
        subject_key.key_type() == "rsa-4096-public" ||
        subject_key.key_type() == "rsa-1024-private" ||
        subject_key.key_type() == "rsa-2048-private" ||
        subject_key.key_type() == "rsa-3072-private" ||
        subject_key.key_type() == "rsa-4096-private") {
      RSA* subject_rsa_key = RSA_new();
      if (!key_to_RSA(subject_key, subject_rsa_key)) {
        printf("produce_artifact: can't get rsa subject key\n");
        return false;
      }
      EVP_PKEY_set1_RSA(subject_pkey, subject_rsa_key);
      X509_set_pubkey(x509, subject_pkey);
      RSA_free(subject_rsa_key);
    } else if (subject_key.key_type() == "ecc-384-public" ||
               subject_key.key_type() == "ecc-384-private" ||
               subject_key.key_type() == "ecc-256-public" ||
               subject_key.key_type() == "ecc-256-private") {
      EC_KEY* subject_ecc_key = key_to_ECC(subject_key);
      if (subject_ecc_key == nullptr) {
        printf("produce_artifact: can't get subject key\n");
        return false;
      }
      EVP_PKEY_set1_EC_KEY(subject_pkey, subject_ecc_key);
      X509_set_pubkey(x509, subject_pkey);
      EC_KEY_free(subject_ecc_key);
    } else {
        printf("produce_artifact: unknown public key type %s\n",
          subject_key.key_type().c_str());
        return false;
    }
    X509_sign(x509, signing_pkey, EVP_sha384());
    EVP_PKEY_free(signing_pkey);
    EVP_PKEY_free(subject_pkey);
  } else {
    printf("produce_artifact: Unsupported algorithm\n");
    return false;
  }

  ASN1_INTEGER_free(a);
  ASN1_TIME_free(tm_start);
  ASN1_TIME_free(tm_end);
  X509_NAME_free(subject_name);
  X509_NAME_free(issuer_name);
  return true;
}

bool certifier::utilities::verify_artifact(X509& cert, key_message& verify_key,
    string* issuer_name_str, string* issuer_description_str,
    key_message* subject_key, string* subject_name_str, string* subject_organization_str,
    uint64_t* sn) {

  bool success = false;
  if (verify_key.key_type() == "rsa-1024-public" ||
      verify_key.key_type() == "rsa-1024-private" ||
      verify_key.key_type() == "rsa-2048-public" ||
      verify_key.key_type() == "rsa-2048-private" ||
      verify_key.key_type() == "rsa-3072-public" ||
      verify_key.key_type() == "rsa-3072-private" ||
      verify_key.key_type() == "rsa-4096-public" ||
      verify_key.key_type() == "rsa-4096-private") {
    EVP_PKEY* verify_pkey = EVP_PKEY_new();
    RSA* verify_rsa_key = RSA_new();
    if (!key_to_RSA(verify_key, verify_rsa_key))
      return false;
    EVP_PKEY_set1_RSA(verify_pkey, verify_rsa_key);

    EVP_PKEY* subject_pkey = X509_get_pubkey(&cert);
    RSA* subject_rsa_key= EVP_PKEY_get1_RSA(subject_pkey);
    if (!RSA_to_key(subject_rsa_key, subject_key))
      return false;
    success = (X509_verify(&cert, verify_pkey) == 1);
    RSA_free(verify_rsa_key);
    RSA_free(subject_rsa_key);
    EVP_PKEY_free(verify_pkey);
    EVP_PKEY_free(subject_pkey);
  // Todo: Make this work
  } else if (verify_key.key_type() == "ecc-384-public" ||
             verify_key.key_type() == "ecc-384-private" ||
             verify_key.key_type() == "ecc-256-public" ||
             verify_key.key_type() == "ecc-256-private") {
    EVP_PKEY* verify_pkey = EVP_PKEY_new();
    EC_KEY* verify_ecc_key = key_to_ECC(verify_key);
    if (verify_ecc_key == nullptr) 
      return false;
    EVP_PKEY_set1_EC_KEY(verify_pkey, verify_ecc_key);

    EVP_PKEY* subject_pkey = X509_get_pubkey(&cert);
    EC_KEY* subject_ecc_key= EVP_PKEY_get1_EC_KEY(subject_pkey);
    if (!ECC_to_key(subject_ecc_key, subject_key))
      return false;
    success = (X509_verify(&cert, verify_pkey) == 1);
    EC_KEY_free(verify_ecc_key);
    EC_KEY_free(subject_ecc_key);
    EVP_PKEY_free(verify_pkey);
    EVP_PKEY_free(subject_pkey);
  } else {
    printf("Unsupported key type\n");
    return false;
  }

  // Todo: report other cert values
  X509_NAME* subject_name = X509_get_subject_name(&cert);
  const int max_buf = 2048;
  char name_buf[max_buf];
  if (X509_NAME_get_text_by_NID(subject_name, NID_commonName, name_buf, max_buf) < 0)
    success = false;
  else {
    subject_name_str->assign((const char*) name_buf);
  }
 
  // X509_NAME_free(subject_name);
  return success;
}

// -----------------------------------------------------------------------

bool certifier::utilities::asn1_to_x509(const string& in, X509 *x) {
  int len = in.size();

  byte* p = (byte*) in.data();
  d2i_X509(&x, (const byte**)&p, len);
  if (x == nullptr)
    return false;
  return true;
}

bool certifier::utilities::x509_to_asn1(X509 *x, string* out) {
  int len = i2d_X509(x, nullptr);
  byte buf[len];
  byte* p = buf;

  i2d_X509(x, (byte**)&p);
  out->assign((char*)buf, len);
  return true;
}

// -----------------------------------------------------------------------

//  Blocking read of pipe, socket, SSL connection with
//  size prefix

// little endian only
const int max_pipe_size = 65536;
int sized_pipe_write(int fd, int size, byte* buf) {
  if (size > max_pipe_size)
    return -1;
  if (write(fd, (byte*)&size, sizeof(int)) < (int)sizeof(int))
    return -1;
  if (write(fd, buf, size) < size)
    return -1;
  return size;
}

// little endian only
int sized_pipe_read(int fd, string* out) {
  int size = 0;
  if (read(fd, (byte*)&size, sizeof(int)) < (int)sizeof(int)) {
    printf("sized_pipe_read: bad read size \n");
    return -1;
  }
  if (size > max_pipe_size) {
    printf("sized_pipe_read: larger than pipe buffer\n");
    return -1;
  }

  byte buf[size];
  int cur_size = 0;
  int n = 0;
  while (cur_size < size) {
    n = read(fd, &buf[cur_size], size - cur_size);
    if (n < 0) {
      printf("sized_pipe_read: read failed\n");
      return -1;
    }
    cur_size += n;
  }

  out->clear();
  out->assign((char*)buf, size);
  return n;
}

// little endian only
int sized_ssl_write(SSL* ssl, int size, byte* buf) {
  if (SSL_write(ssl, (byte*)&size, sizeof(int)) < (int)sizeof(int))
    return -1;
  if (SSL_write(ssl, buf, size) < size)
    return -1;
  return size;
}

// little endian only
int sized_ssl_read(SSL* ssl, string* out) {
  out->clear();
  int size = 0;
  int n = SSL_read(ssl, (byte*)&size, sizeof(int));
  if (n < 0)
    return n;

  int total = 0;
  const int read_stride = 8192;
  byte buf[read_stride];

  while(total < size) {
    if ((size - total) > read_stride)
      n = SSL_read(ssl, buf, read_stride);
    else
      n = SSL_read(ssl, buf, size - total);
    if (n < 0) {
      return n;
    } else {
      out->append((char*)buf, n);
      total += n;
    }
  }
  return total;
}

// little endian only
int certifier::utilities::sized_socket_read(int fd, string* out) {
  out->clear();
  int n = 0;
  int size = 0;
  int total = 0;
  const int read_stride = 8192;
  byte buf[read_stride];

  if (read(fd, (byte*)&size, sizeof(int)) < (int)sizeof(int))
    return -1;

  while(total < size) {
    if ((size - total) > read_stride)
      n = read(fd, buf, read_stride);
    else
      n = read(fd, buf, size - total);
    if (n <= 0) {
      return -1;
    } else {
      out->append((char*)buf, n);
      total += n;
    }
  }
  return total;
}

// little endian only
int certifier::utilities::sized_socket_write(int fd, int size, byte* buf) {
  if (write(fd, (byte*)&size, sizeof(int)) < (int)sizeof(int))
    return -1;
  if (write(fd, buf, size) < size)
    return -1;
  return size;
}

// -----------------------------------------------------------------------

bool key_from_pkey(EVP_PKEY* pkey, const string& name, key_message* k) {

  if (pkey == nullptr)
    return false;
  if (EVP_PKEY_base_id(pkey) == EVP_PKEY_RSA) {
    int size = EVP_PKEY_bits(pkey);
    RSA* rsa_key= EVP_PKEY_get1_RSA(pkey);
    if (!RSA_to_key(rsa_key, k)) {
      printf("key_from_pkey: RSA_to_key failed\n");
      return false;
    }
    switch(size) {
    case 1024:
      k->set_key_type("rsa-1024-public");
      break;
    case 2048:
      k->set_key_type("rsa-2048-public");
      break;
    case 3072:
      k->set_key_type("rsa-3072-public");
      break;
    case 4096:
      k->set_key_type("rsa-4096-public");
      break;
    default:
      return false;
    }
    // RSA_free(rsa_key);
  } else if (EVP_PKEY_base_id(pkey) == EVP_PKEY_EC) {
    int size = EVP_PKEY_bits(pkey);
    EC_KEY* ecc_key= EVP_PKEY_get1_EC_KEY(pkey);
    if (!ECC_to_key(ecc_key, k)) {
      printf("key_from_pkey: ECC_to_key failed\n");
      return false;
    }
    if (size == 384) {
      k->set_key_type("ecc-384-public");
    } else if (size == 256) {
      k->set_key_type("ecc-256-public");
    } else {
      return false;
    }
    // EC_KEY_free(ecc_key);
  } else {
    printf("key_from_pkey: unsupported key type\n");
    return false;
  }

  k->set_key_name(name);
  k->set_key_format("vse-key");
  return true;
}

cert_keys_seen_list::cert_keys_seen_list(int max_size) {
  max_size_ = max_size;
  entries_ = new cert_keys_seen* [max_size];
  size_ = 0;
}

cert_keys_seen_list::~cert_keys_seen_list() {
  for (int i = 0; i < size_; i++) {
    delete entries_[i];
  }
  delete entries_;
}

key_message* cert_keys_seen_list::find_key_seen(const string& name) {
  for (int i= 0; i < size_; i++) {
    if (entries_[i]->issuer_name_ == name)
      return entries_[i]->k_;
  }
  return nullptr;
}

bool cert_keys_seen_list::add_key_seen(key_message* k) {
  if (size_ >= (max_size_ - 1))
    return false;
  entries_[size_] = new cert_keys_seen;
  entries_[size_]->issuer_name_.assign(k->key_name());
  entries_[size_]->k_ = k;
  size_++;
  return true;
}

key_message* get_issuer_key(X509* x, cert_keys_seen_list& list) {
  string str_issuer_name;

  const int max_buf = 2048;
  char name_buf[max_buf];
  X509_NAME* issuer_name = X509_get_issuer_name(x);
  if (X509_NAME_get_text_by_NID(issuer_name, NID_commonName, name_buf, max_buf) < 0) {
    printf("get_issuer_key: Can't get name from NID\n");
    return nullptr;
  }
  str_issuer_name.assign((const char*) name_buf);
  // X509_NAME_free(issuer_name);
  return list.find_key_seen(str_issuer_name);
}

EVP_PKEY* pkey_from_key(const key_message& k) {
  EVP_PKEY* pkey = EVP_PKEY_new();

  if (k.key_type() == "rsa-1024-public" || k.key_type() == "rsa-1024-private" ||
      k.key_type() == "rsa-3072-public" || k.key_type() == "rsa-3072-private" ||
      k.key_type() == "rsa-2048-public" || k.key_type() == "rsa-2048-private" ||
      k.key_type() == "rsa-4096-public" || k.key_type() == "rsa-4096-private") {
    RSA* rsa_key = RSA_new();
    if (!key_to_RSA(k, rsa_key)) {
      printf("pkey_from_key: Can't translate key to RSA key\n");
      EVP_PKEY_free(pkey);
      return nullptr;
    }
    if (1 != EVP_PKEY_assign_RSA(pkey, rsa_key)) {
      printf("pkey_from_key: Can't set RSA key\n");
      EVP_PKEY_free(pkey);
      return nullptr;
    }
    return pkey;
  } else if (k.key_type() == "ecc-384-public" ||
             k.key_type() == "ecc-384-private" ||
             k.key_type() == "ecc-256-public" ||
             k.key_type() == "ecc-256-private") {
    EC_KEY* ecc_key = key_to_ECC(k);
    if (ecc_key == nullptr) {
      EVP_PKEY_free(pkey);
      return nullptr;
    }
    EVP_PKEY_assign_EC_KEY(pkey, ecc_key);
    return pkey;
  } else {
    printf("pkey_from_key: Unsupported key type\n");
    EVP_PKEY_free(pkey);
    return nullptr;
  }
}

// make a public key from the X509 cert's subject key
bool x509_to_public_key(X509* x, key_message* k) {
  EVP_PKEY* subject_pkey = X509_get_pubkey(x);
  if (subject_pkey == nullptr) {
    printf("x509_to_public_key: subject_pkey is null\n");
    return false;
  }

  if (EVP_PKEY_base_id(subject_pkey) == EVP_PKEY_RSA) {
    int size = EVP_PKEY_bits(subject_pkey); 
    RSA* subject_rsa_key= EVP_PKEY_get1_RSA(subject_pkey);
    if (!RSA_to_key(subject_rsa_key, k)) {
      printf("x509_to_public_key: RSA_to_key failed\n");
      return false;
    }
    switch(size) {
    case 1024:
      k->set_key_type("rsa-1024-public");
      break;
    case 2048:
      k->set_key_type("rsa-2048-public");
      break;
    case 3072:
      k->set_key_type("rsa-3072-public");
      break;
    case 4096:
      k->set_key_type("rsa-4096-public");
      break;
    default:
      printf("x509_to_public_key: bad key type\n");
      return false;
    }
    // free subject_rsa_key?
  } else if (EVP_PKEY_base_id(subject_pkey) == EVP_PKEY_EC) {
    int size = EVP_PKEY_bits(subject_pkey); 
    EC_KEY* subject_ecc_key = EVP_PKEY_get1_EC_KEY(subject_pkey);
    if (!ECC_to_key(subject_ecc_key, k)) {
      return false;
    }
    if (size == 384) {
      k->set_key_type("ecc-384-public");
    } else if (size == 256) {
      k->set_key_type("ecc-256-public");
    } else {
      return false;
    }
    // Todo: free subject_ecc_key?
  } else {
    printf("x509_to_public_key: bad pkey type\n");
    return false;
  }

  X509_NAME* subject_name = X509_get_subject_name(x);
  const int max_buf = 2048;
  char name_buf[max_buf];
  memset(name_buf, 0, max_buf);
  if (X509_NAME_get_text_by_NID(subject_name, NID_commonName, name_buf, max_buf) < 0) {
    printf("x509_to_public_key: can't get subject_name\n");
    return false;
  }
  k->set_key_name((const char*) name_buf);
  k->set_key_format("vse-key");
  EVP_PKEY_free(subject_pkey);
  return true;
}

bool certifier::utilities::make_root_key_with_cert(string& type, string& name,
      string& issuer_name, key_message* k) {
  string root_name("root");

  if (type == "rsa-4096-private" || type == "rsa-2048-private" || type == "rsa-3072-private"|| type == "rsa-1024-private") {
    int n = 2048;
    if (type == "rsa-2048-private")
      n = 2048;
    else if (type == "rsa-1024-private")
      n = 1024;
    else if (type == "rsa-3072-private")
      n = 3072;
    else if (type == "rsa-4096-private")
      n = 4096;

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
  } else if (type == "ecc-384-private") {
    if (!make_certifier_ecc_key(384,  k))
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
  } else if (type == "ecc-256-private") {
    if (!make_certifier_ecc_key(256,  k))
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

bool construct_vse_attestation_from_cert(const key_message& subj,
      const key_message& signer, vse_clause* cl) {
  string str_says("says");
  string str_prop("is-trusted-for-attestation");

  entity_message subj_ent;
  if (!make_key_entity(subj, &subj_ent)) {
    printf("construct_vse_attestation_from_cert: Can't make subject entity\n");
    return false;
  }
  vse_clause* c1 = new vse_clause;
  if (!make_unary_vse_clause(subj_ent, str_prop, c1)) {
    printf("construct_vse_attestation_from_cert: Can't construct unary clause\n");
    return false;
  }
  entity_message signer_ent;
  if (!make_key_entity(signer, &signer_ent)) {
    printf("construct_vse_attestation_from_cert: Can't make signer entity\n");
    return false;
  }
  if (!make_indirect_vse_clause(signer_ent, str_says, *c1, cl)) {
    printf("construct_vse_attestation_from_cert: Can't construct indirect clause\n");
    return false;
  }

  return true;
}

// -----------------------------------------------------------------------

