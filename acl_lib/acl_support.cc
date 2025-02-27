// Copyright 2014-2020 John Manferdelli, All Rights Reserved.
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
// File: acl_support.cc

#include "stdio.h"
#include <unistd.h>
#include "sys/fcntl.h"
#include "sys/stat.h"

#include "acl_support.h"

const char* Enc_method_aes_128                   = "aes-128";
const char* Enc_method_aes_256                   = "aes-256";
const char* Enc_method_aes_256_cbc               = "aes-256-cbc";
const char* Enc_method_aes_128_cbc_hmac_sha256   = "aes-128-cbc-hmac-sha256";
const char* Enc_method_aes_256_cbc_hmac_sha256   = "aes-256-cbc-hmac-sha256";
const char* Enc_method_aes_256_cbc_hmac_sha384   = "aes-256-cbc-hmac-sha384";
const char* Enc_method_aes_256_gcm               = "aes-256-gcm";

const char* Enc_method_ecc_256_private           = "ecc-256-private";
const char* Enc_method_ecc_256_public            = "ecc-256-public";
const char* Enc_method_ecc_256_sha256_pkcs_sign  = "ecc-256-sha256-pkcs-sign";
const char* Enc_method_ecc_384                   = "ecc-384";
const char* Enc_method_ecc_384_private           = "ecc-384-private";
const char* Enc_method_ecc_384_public            = "ecc-384-public";
const char* Enc_method_ecc_384_sha384_pkcs_sign  = "ecc-384-sha384-pkcs-sign";
const char* Enc_method_rsa_1024                  = "rsa-1024";
const char* Enc_method_rsa_1024_private          = "rsa-1024-private";
const char* Enc_method_rsa_1024_public           = "rsa-1024-public";
const char* Enc_method_rsa_1024_sha256_pkcs_sign = "rsa-1024-sha256-pkcs-sign";
const char* Enc_method_rsa_2048                  = "rsa-2048";
const char* Enc_method_rsa_2048_private          = "rsa-2048-private";
const char* Enc_method_rsa_2048_public           = "rsa-2048-public";
const char* Enc_method_rsa_2048_sha256_pkcs_sign = "rsa-2048-sha256-pkcs-sign";
const char* Enc_method_rsa_3072                  = "rsa-3072";
const char* Enc_method_rsa_3072_private          = "rsa-3072-private";
const char* Enc_method_rsa_3072_public           = "rsa-3072-public";
const char* Enc_method_rsa_3072_sha384_pkcs_sign = "rsa-3072-sha384-pkcs-sign";
const char* Enc_method_rsa_4096                  = "rsa-4096";
const char* Enc_method_rsa_4096_private          = "rsa-4096-private";
const char* Enc_method_rsa_4096_public           = "rsa-4096-public";
const char* Enc_method_rsa_4096_sha384_pkcs_sign = "rsa-4096-sha384-pkcs-sign";
const char* Digest_method_sha256                 = "sha256";
const char* Digest_method_sha_256                = "sha-256";
const char* Digest_method_sha_384                = "sha-384";
const char* Digest_method_sha_512                = "sha-512";
const char* Integrity_method_aes_256_cbc_hmac_sha256 = "aes-256-cbc-hmac-sha256";
const char* Integrity_method_aes_256_cbc_hmac_sha384 = "aes-256-cbc-hmac-sha384";
const char* Integrity_method_aes_256_gcm             = "aes-256-gcm";
const char* Integrity_method_hmac_sha256             = "hmac-sha256";
    
name_size cipher_block_byte_name_size[] = {
    { Enc_method_aes_256                    , 16 },
    { Enc_method_aes_256_cbc_hmac_sha256    , 16 },
    { Enc_method_aes_256_cbc_hmac_sha384    , 16 },
    { Enc_method_aes_256_gcm                , 16 },
    { Enc_method_aes_128                    , 16 },
    { Enc_method_aes_128_cbc_hmac_sha256    , 16 },
    { Enc_method_rsa_2048_sha256_pkcs_sign  , 256 },
    { Enc_method_rsa_2048                   , 256 },
    { Enc_method_rsa_1024_sha256_pkcs_sign  , 128 },
    { Enc_method_rsa_1024                   , 128 },
    { Enc_method_rsa_1024_private           , 128 },
    { Enc_method_rsa_1024_public            , 128 },
    { Enc_method_rsa_2048_private           , 256 },
    { Enc_method_rsa_2048_public            , 256 },
    { Enc_method_rsa_4096_sha384_pkcs_sign  , 512 },
    { Enc_method_rsa_4096_private           , 512 },
    { Enc_method_rsa_4096_public            , 512 },
    { Enc_method_ecc_384_public             , 48 },
    { Enc_method_ecc_384_private            , 48 },
    { Enc_method_ecc_256_public             , 32 },
    { Enc_method_ecc_256_private            , 32 },
};

name_size cipher_key_byte_name_size[] = {
    { Enc_method_aes_256                    , 32 },
    { Enc_method_aes_256_cbc_hmac_sha256    , 64 },
    { Enc_method_aes_256_cbc_hmac_sha384    , 80 },
    { Enc_method_aes_256_gcm                , 32 },
    { Enc_method_rsa_2048_sha256_pkcs_sign  , 256 },
    { Enc_method_rsa_2048                   , 256 },
    { Enc_method_rsa_1024_sha256_pkcs_sign  , 128 },
    { Enc_method_rsa_1024                   , 128 },
    { Enc_method_rsa_2048_private           , 256 },
    { Enc_method_rsa_2048_public            , 256 },
    { Enc_method_rsa_1024_private           , 128 },
    { Enc_method_rsa_1024_public            , 128 },
    { Enc_method_rsa_3072_sha384_pkcs_sign  , 384 },
    { Enc_method_rsa_3072_private           , 384 },
    { Enc_method_rsa_3072_public            , 384 },
    { Enc_method_rsa_4096_sha384_pkcs_sign  , 512 },
    { Enc_method_rsa_4096_private           , 512 },
    { Enc_method_rsa_4096_sha384_pkcs_sign  , 512 },
    { Enc_method_rsa_4096_private           , 512 },
    { Enc_method_rsa_4096_public            , 512 },
};

name_size digest_byte_name_size[] = {
    { Digest_method_sha256   , 32 },
    { Digest_method_sha_256  , 32 },
    { Digest_method_sha_384  , 48 },
    { Digest_method_sha_512  , 64 },
};

name_size mac_byte_name_size[] = {
    { Integrity_method_hmac_sha256       , 32 },
    { Enc_method_aes_256_cbc_hmac_sha256 , 32 },
    { Enc_method_aes_256_cbc_hmac_sha384 , 48 },
    { Enc_method_aes_256_gcm             , 16 },
};


time_point::time_point() {
  year_ = 0;
  month_ = 0;
  day_in_month_ = 0;
  hour_ = 0;
  minutes_ = 0;
  seconds_ = 0.0;
}

bool time_point::time_now() {
  time_t now;
  struct tm current_time;

  time(&now);
  gmtime_r(&now, &current_time);
  if (!unix_tm_to_time_point(&current_time))
    return false;
  return true;
}

bool time_point::add_interval_to_time(time_point& from, double seconds_later) {
  // This doesn't do leap years, seconds, month or other stuff... correctly
  year_ = from.year_;
  day_in_month_ = from.day_in_month_;
  month_= from.month_;
  minutes_= from.minutes_;
  hour_= from.hour_;
  seconds_= from.seconds_;

  int days = seconds_later / (double)seconds_in_day;
  seconds_later -= (double) (days * seconds_in_day);
  int yrs = days /365;
  days -= yrs * 365;
  year_ += yrs;
  int months = days / 30; // not right;
  days -= months * 30;
  month_ +=  months;
  day_in_month_ += days;
  int mins = (int)seconds_later / 60.0;
  seconds_later -= (double) (mins * 60);
  int hrs = (int)mins / 60.0;
  mins -= hrs * 60;
  hour_ += hrs;
  minutes_ += mins;
  seconds_+= seconds_later;
  // now fix overflows
  if (seconds_ >= 60.0) {
    seconds_ -= 60.0;
    minutes_ += 1;
  }
  if (minutes_ >= 60) {
    minutes_ -= 60;
    hour_ += 1;
  }
  if (hour_ >= 24) {
    day_in_month_ += 1;
    hour_ -= 24;
  }
  if(day_in_month_ > 30) {
    month_ += 1;
    day_in_month_ -= 30;
  }
  if (month_ > 12) {
    year_ += 1;
    month_ -= 12;
  }
  return true;
}

const char* s_months[] = {
  "January", "February", "March", "April", "May", "June",
  "July", "August", "September", "October", "November", "December"
};
void time_point::print_time() {
  int m = month_ - 1;
  if (m < 0 || m > 11)
    return;
  printf("%d %s %d, %02d:%02d:%lfZ", day_in_month_, s_months[m], year_,
      hour_, minutes_, seconds_);
}

bool time_point::encode_time(string* the_time) {
  int m = month_ - 1;
  if (m < 0 || m > 11)
    return false;
  char time_str[256];
  *time_str = '\0';
  snprintf(time_str,255, "%d %s %d, %02d:%02d:%lfZ", day_in_month_, s_months[m], year_,
      hour_, minutes_, seconds_);
  m = strlen(time_str);
  *the_time = time_str;
  return true;
}

const char* m_months[12] = {
  "January", "February", "March", "April", "May", "June",
  "July", "August", "September", "October", "November", "December"
};
int month_from_name(char* mn) {
  for(int i = 0; i < 12; i++) {
    if (strcmp(mn, m_months[i]) == 0)
      return i;
  }
  return -1;
}
bool time_point::decode_time(string& encoded_time) {
  int dm, yr, hr, min;
  double sec;
  char s[20];
  sscanf(encoded_time.c_str(), "%d %s %d, %02d:%02d:%lfZ", &dm, s, &yr,
      &hr, &min, &sec);
  int mm = month_from_name(s);
  if (mm < 0)
   return false;
  mm++;
  year_ = yr;
  month_ = mm;
  day_in_month_ = dm;
  hour_ = hr;
  minutes_ = min;
  seconds_ = sec;
  return true;
}

bool time_point::time_point_to_unix_tm(struct tm* time_now) {
  return false;
}

bool time_point::unix_tm_to_time_point(struct tm* the_time) {
  year_ = the_time->tm_year + 1900;
  month_ = the_time->tm_mon + 1;
  day_in_month_ = the_time->tm_mday;
  hour_ = the_time->tm_hour;
  minutes_ = the_time->tm_min;
  seconds_ = the_time->tm_sec;
  return true;
}

int compare_time_points(time_point& l, time_point& r) {
  if (l.year_ > r.year_)
    return 1;
  if (l.year_ < r.year_)
    return -1;
  if (l.month_ > r.month_)
    return 1;
  if (l.month_ < r.month_)
    return -1;
  if (l.day_in_month_ > r.day_in_month_)
    return 1;
  if (l.day_in_month_ < r.day_in_month_)
    return -1;
  if (l.hour_ > r.hour_)
    return 1;
  if (l.hour_ < r.hour_)
    return -1;
  if (l.minutes_ > r.minutes_)
    return 1;
  if (l.minutes_ < r.minutes_)
    return -1;
  if (l.seconds_ > r.seconds_)
    return 1;
  if (l.seconds_ < r.seconds_)
    return -1;
  return 0;
}

int bits_to_bytes(int n) {
  return NBITSINBYTE * n;
}

int bytes_to_bits(int n) {
  return (n + NBITSINBYTE - 1) / NBITSINBYTE;
}

int bits_to_uint64(int n) {
  return NBITSINUINT64 * n;
}

int uint64_to_bits(int n) {
  return (n + NBITSINUINT64 - 1) / NBITSINUINT64;
}

static byte s_hex_values1[10] = {
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9
};
static byte s_hex_values2[6] = {
  10, 11, 12, 13, 14, 15
};
byte hex_value(char a) {
  if (a >= '0' && a <= '9')
    return s_hex_values1[a - '0'];
  if (a >= 'A' && a <= 'F')
    return s_hex_values2[a - 'A'];
  if (a >= 'a' && a <= 'f')
    return s_hex_values2[a - 'a'];
  return 0;
}  

bool valid_hex(char* s) {
  char a;
  while (*s != '\0') {
    a = *(s++);
    if (a >= '0' && a <= '9')
      continue;
    if (a >= 'A' && a <= 'F')
      continue;
    if (a >= 'a' && a <= 'f')
      continue;
    return false;
  }
  return true;
}

bool hex_to_bytes(string& h, string* b) {
  b->clear();
  if (!valid_hex((char*)h.c_str()))
    return false;
  int h_size = strlen(h.c_str());

  // if odd first 4 bits is 0
  byte b1, b2;
  int k;
  if ((h_size % 2) != 0) {
    b1 = 0;
    b2 = hex_value(h[0]);
    k = 1;
    b->append(1, (char)b2);
  } else {
    k = 0;
  }
  for (int i = k; i < h_size; i += 2) {
    b1 = hex_value(h[i]);
    b2 = hex_value(h[i + 1]);
    b1 = (b1 << 4) | b2;
    b->append(1, b1);
  }
  return true;
}

static char s_hex_chars[16] = {
  '0', '1', '2', '3', '4', '5', '6', '7',
  '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
};
char hex_char(byte b) {
  if (b > 16)
    return '0';
  return s_hex_chars[b];
}

bool bytes_to_hex(string& b, string* h) {
  // always returns even number of hex characters
  h->clear();
  int b_size = b.size();
  char c1, c2;
  byte b1, b2;
  for (int i = 0; i < b_size; i++) {
    b1 = (b[i] >> 4) & 0x0f;
    b2 = b[i] & 0x0f;
    c1 = hex_char(b1);
    c2 = hex_char(b2);
    h->append(1, c1);
    h->append(1, c2);
  }
  h->append(1, '\0');
  return true;
}

static const char* web_safe_base64_characters =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
bool valid_base64(char* s) {
  char a;
  while (*s != '\0') {
    a = *(s++);
    if (a >= '0' && a <= '9')
      continue;
    if (a >= 'A' && a <= 'Z')
      continue;
    if (a >= 'a' && a <= 'z')
      continue;
    if (a == '-' || a == '_' || a == '=')
      continue;
    return false;
  }
  return true;
}
byte base64_value(char a) {
  for (int i = 0; i < (int)strlen(web_safe_base64_characters); i++) {
    if (a == web_safe_base64_characters[i])
      return i;
  }
  return -1;
}
char base64_char(byte a) {
  if (a >= 0x3f)
   return ' ';
  return web_safe_base64_characters[(int)a];
}
bool base64_to_bytes(string& b64, string* b) {
  if (!valid_base64((char*)b64.c_str()))
    return false;
  b->clear();
  int b64_size = strlen(b64.c_str());
  if (((int)b->capacity()) < ((b64_size / 4) * 3 + 1))
    return false;
  int i;
  byte x1, x2, x3, x4, z;
  for (i = 0; i < (b64_size - 4); i += 4) {
    x1 = base64_value(b64[i]);
    x2 = base64_value(b64[i + 1]);
    x3 = base64_value(b64[i + 2]);
    x4 = base64_value(b64[i + 3]);
    z = (x1 << 2) | (x2 >> 4);
    b->append(1, (char)z);
    x2 &= 0x0f;
    z = (x2 << 4) | (x3 >> 2);
    b->append(1, (char)z);
    x3 &= 0x03;
    z = (x3 << 6) | x4;
    b->append(1, (char)z);
  }
  // the possibilities for the remaining base64 characters are
  //  c1 (6 bits), c2 (2 bits), =, =
  //  c1 (6 bits), c2 (6 bits), c3 (4bits), =
  // sanity check
  if ((b64_size - i) != 4)
    return false;
  if (b64[b64_size - 1] == '=' && b64[b64_size - 2] != '=') {
    x1 = base64_value(b64[b64_size - 4]);
    x2 = base64_value(b64[b64_size - 3]);
    x3 = base64_value(b64[b64_size - 2]);
    z = (x1 << 2) | (x2 >> 4);
    b->append(1, (char)z);
    z = (x2 << 4) | x3;
    b->append(1, (char)z);
  } else if (b64[b64_size - 1] == '=' && b64[b64_size - 2] == '=') {
    x1 = base64_value((char)b64[b64_size - 4]);
    x2 = base64_value((char)b64[b64_size - 3]);
    z = (x1 << 2) | x2;
    b->append(1, (char)z);
  } else {
    x1 = base64_value((char)b64[b64_size - 4]);
    x2 = base64_value((char)b64[b64_size - 3]);
    x3 = base64_value((char)b64[b64_size - 2]);
    x4 = base64_value((char)b64[b64_size - 1]);
    z = (x1 << 2) | (x2 >> 4);
    b->append(1, (char)z);
    x2 &= 0x0f;
    z = (x2 << 4) | (x3 >> 2);
    b->append(1, (char)z);
    x3 &= 0x03;
    z = (x3 << 6) | x4;
    b->append(1, (char)z);
  }
  return true;
}

bool bytes_to_base64(string& b, string* b64) {
  b64->clear();
  int b_size = b.size();
  byte x1, x2, x3, z;
  char c;
  int i;
  for (i = 0; i < (b_size - 3); i += 3) {
    x1 = b[i];
    z = x1 >> 2;
    c = base64_char(z);
    b64->append(1, c);
    x2 = b[i + 1];
    z = (x1 & 0x03) << 4 | x2>>4;
    c = base64_char(z);
    b64->append(1, c);
    x3 = b[i + 2];
    z = (x2 & 0x0f) << 2 | x3 >> 6; 
    c = base64_char(z);
    b64->append(1, c);
    z = x3 & 0x3f;
    c = base64_char(z);
    b64->append(1, c);
  }
  // there can be 1, 2 or 3 bytes left
  if ((b_size - i) == 1) {
    x1 = b[i];
    z = x1 >> 2;
    c = base64_char(z);
    b64->append(1, c);
    z = (x1 & 0x03);
    c = base64_char(z);
    b64->append(1, c);
    b64->append(2, '=');
  } else if ((b_size - i) == 2) {
    x1 = b[i];
    x2 = b[i + 1];
    z = x1 >> 2;
    c = base64_char(z);
    b64->append(1, c);
    z = (x1 & 0x03) << 4 | x2 >> 4;
    c = base64_char(z);
    b64->append(1, c);
    z =  x2 & 0x0f;
    c = base64_char(z);
    b64->append(1, c);
    b64->append(1, '=');
  } else if ((b_size - i) == 3) {
    x1 = b[i];
    x2 = b[i + 1];
    x3 = b[i + 2];
    z = x1 >> 2;
    c = base64_char(z);
    b64->append(1, c);
    z = (x1 & 0x03) << 4 | x2 >> 4;
    c = base64_char(z);
    b64->append(1, c);
    z =  (x2 & 0x0f) << 2 | x3 >> 6;
    c = base64_char(z);
    b64->append(1, c);
    z =  x3 & 0x03f;
    c = base64_char(z);
    b64->append(1, c);
  }
  b64->append(1, '\0');
  return true;
}

void print_bytes(int n, byte* in) {
  int i;

  for(i = 0; i < n; i++) {
    printf("%02x",in[i]);
    if ((i%32)== 31)
      printf("\n");
  }
  if ((i%32) != 0)
    printf("\n");
}

void reverse_bytes(int size, byte* in, byte* out) {
  for (int i = 0; i < size; i++)
    out[size - 1 - i] = in[i];
}

bool have_intel_rd_rand() {
  uint32_t arg = 1;
  uint32_t rd_rand_enabled;

#if defined(X64)
  asm volatile(
      "\tmovl    %[arg], %%eax\n"
      "\tcpuid\n"
      "\tmovl    %%ecx, %[rd_rand_enabled]\n"
      : [rd_rand_enabled] "=m"(rd_rand_enabled)
      : [arg] "m"(arg)
      : "%eax", "%ebx", "%ecx", "%edx");
  if (((rd_rand_enabled >> 30) & 1) != 0) {
    return true;
  }
#endif
  return false;
} 
    
bool have_intel_aes_ni() {
  uint32_t arg = 1;
  uint32_t rd_aesni_enabled;
    
#if defined(X64)
  asm volatile(
      "\tmovl    %[arg], %%eax\n"
      "\tcpuid\n"
      "\tmovl    %%ecx, %[rd_aesni_enabled]\n"
      : [rd_aesni_enabled] "=m"(rd_aesni_enabled)
      : [arg] "m"(arg)
      : "%eax", "%ebx", "%ecx", "%edx");
  if (((rd_aesni_enabled >> 25) & 1) != 0) {
    return true;
  }
#endif
  return false;
}

random_source::random_source() {
  initialized_ = false;
  have_rd_rand_ = have_intel_rd_rand();
}

bool random_source::have_intel_rd_rand() { 
  return have_rd_rand_;
}

bool random_source::start_random_source() {
  fd_ = ::open("/dev/urandom", O_RDONLY);
  initialized_ = fd_ > 0;
  return initialized_;
}

#if defined(X64)
#define HAVE_RD_RAND
#endif
int random_source::get_random_bytes(int n, byte* b) {
  if (!initialized_)
    return -1;
#ifdef HAVE_RD_RAND
  int m = n;
  if (have_rd_rand_) {
    uint32_t out;
  
    while (m > 0) {
      asm volatile(
          "\trdrand %%edx\n"
          "\tmovl   %%edx, %[out]\n"
          : [out] "=m"(out)::"%edx");
      memcpy(b, (byte*)&out, sizeof(uint32_t));
      m -= sizeof(uint32_t);
      b += sizeof(uint32_t);
    }
    return n;
  }
#endif
  return read(fd_, b, (ssize_t)n);
}


bool random_source::close_random_source() {
  if (!initialized_)
    return true;
  close(fd_);
  initialized_ = false;
  return true;
}

bool global_crypto_initialized = false;
random_source global_crypto_random_source;

int crypto_get_random_bytes(int num_bytes, byte* buf) {
  if (!global_crypto_initialized)
    return -1;
  return global_crypto_random_source.get_random_bytes(num_bytes, buf);
}

bool init_crypto() {
  if (!global_crypto_random_source.start_random_source())
    return false;
  global_crypto_initialized = true;
  return true;
}

void close_crypto() {
  if (global_crypto_initialized)
    global_crypto_random_source.close_random_source();
}

key_message* make_symmetric_key(string& alg, string& name,
      const string& not_before, const string& not_after,
      const string& key_bits) {
  key_message* km = new(key_message);

  km->set_key_name(name);
  km->set_key_type(alg);
  km->set_key_format("vse");
  km->set_secret_key_bits(key_bits);
  km->set_not_before(not_before);
  km->set_not_after(not_after);

  return km;
}

void print_binary_blob(const binary_blob_message& m) {
  printf("Binary blob: ");
  print_bytes((int)m.blob().size(), (byte*)m.blob().data());
}

void print_encrypted_message(const encrypted_message& m) {
  printf("Encrypted message:\n");
  if (m.has_encryption_identifier())
    printf("  Scheme id   : %s\n", m.encryption_identifier().c_str());
  if (m.has_message_identifier())
    printf("  Message id  : %s\n", m.message_identifier().c_str());
  if (m.has_source() && m.has_destination())
    printf("  Source      : %s, destination: %s\n", m.source().c_str(), m.destination().c_str());
  if (m.has_date())
    printf("  Date        : %s\n", m.date().c_str());
  if (m.has_buffer()) {
    printf("  Buffer      : ");
    print_bytes((int)m.buffer().size(), (byte*)m.buffer().data());
  }
}

void print_signature_message(const signature_message& m) {
  printf("Signature message\n");
  printf("    algorithm : %s\n", m.encryption_algorithm_name().c_str());
  printf("    key name  : %s\n", m.key_name().c_str());
  printf("    signature : ");
  print_bytes((int)m.signature().size(), (byte*)m.signature().data());
  printf("    signer    : %s\n", m.signer_name().c_str());
}

// -----------------------------------------------------------------------------

bool write_file(const string &file_name, int size, byte* data) {
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

bool write_file_from_string(const string &file_name, const string &in) {
  return write_file(file_name, in.size(), (byte *)in.data());
}

int file_size(const string &file_name) {
  struct stat file_info;

  if (stat(file_name.c_str(), &file_info) != 0)
    return -1;
  if (!S_ISREG(file_info.st_mode))
    return -1;
  return (int)file_info.st_size;
}

bool read_file(const string &file_name, int* size, byte* data) {
  struct stat file_info;

  if (stat(file_name.c_str(), &file_info) != 0) {
    printf("%s() error, line: %d, read_file, Can't stat\n", __func__, __LINE__);
    return false;
  }
  if (!S_ISREG(file_info.st_mode)) {
    printf("%s() error, line: %d, read_file, not a regular file\n",
           __func__, __LINE__);
    return false;
  }
  int bytes_in_file = (int)file_info.st_size;
  if (bytes_in_file > *size) {
    printf("%s() error, line: %d, read_file, Buffer too small\n",
           __func__, __LINE__);
    return false;
  }
  int fd = ::open(file_name.c_str(), O_RDONLY);
  if (fd < 0) {
    printf("%s() error, line: %d, read_file, open failed\n",
           __func__, __LINE__);
    return false;
  }
  int n = (int)read(fd, data, bytes_in_file);
  close(fd);
  *size = n;
  return true;
}

bool read_file_into_string(const string &file_name, string* out) {
  int size = file_size(file_name);
  if (size < 0) {
    printf("%s() error, line: %d, read_file_into_string: Can't size input file "
           "%s\n", __func__, __LINE__, file_name.c_str());
    return false;
  }
  byte buf[size];
  if (!read_file(file_name, &size, buf)) {
    printf("%s() error, line: %d, read_file_into_string: Can't read file %s\n",
           __func__, __LINE__, file_name.c_str()); return false;
  }

  out->assign((char *)buf, size);
  return true;
}

// -----------------------------------------------------------------------

bool time_t_to_tm_time(time_t *t, struct tm *tm_time) {
  gmtime_r(t, tm_time);
  return true;
}

bool tm_time_to_time_point(struct tm * tm_time, time_point *tp) {
  tp->year_ =(tm_time->tm_year + 1900);
  tp->month_= tm_time->tm_mon + 1;
  tp->day_in_month_ = (tm_time->tm_mday);
  tp->hour_ = (tm_time->tm_hour);
  tp->minutes_ = (tm_time->tm_min);
  tp->seconds_ = (tm_time->tm_sec);
  return true;
}

bool asn1_time_to_tm_time(const ASN1_TIME *s, struct tm * tm_time) {
  if (1 != ASN1_TIME_to_tm(s, tm_time)) {
    printf("%s() error, line: %d, ASN1_TIME_to_tm_time() failed\n",
           __func__, __LINE__);
    return false;
  }
  return true;
}

bool get_not_before_from_cert(X509 *c, time_point *tp) {
  const ASN1_TIME *asc_time = X509_getm_notBefore(c);
  if (asc_time == nullptr) {
    printf("%s() error, line: %d, get_not_before_from_cert() failed\n",
           __func__, __LINE__);
    return false;
  }
  struct tm tm_time;
  if (!asn1_time_to_tm_time(asc_time, &tm_time)) {
    printf("%s() error, line: %d, asn1_time_to_tm_time() failed\n",
           __func__, __LINE__);
    return false;
  }
  if (!tm_time_to_time_point(&tm_time, tp)) {
    printf("%s() error, line: %d, tm_time_to_time_point failed\n",
           __func__, __LINE__);
    return false;
  }
  return true;
}

bool get_not_after_from_cert(X509 *c, time_point *tp) {
  const ASN1_TIME *asc_time = X509_getm_notAfter(c);
  if (asc_time == nullptr) {
    printf("%s() error, line: %d, X509_getm_notAfter failed\n",
           __func__, __LINE__);
    return false;
  }
  struct tm tm_time;
  if (!asn1_time_to_tm_time(asc_time, &tm_time)) {
    printf("%s() error, line: %d, asn1_time_to_tm_time failed\n",
           __func__, __LINE__);
    return false;
  }
  if (!tm_time_to_time_point(&tm_time, tp)) {
    printf("%s() error, line: %d, tm_time_to_time_point failed\n",
           __func__, __LINE__);
    return false;
  }
  return true;
}

// 1 if t1 > t2
// 0 if t1 == t2
// -1 if t1 < t2
int compare_time(time_point &t1, time_point &t2) {
  if (t1.year_ > t2.year_)
    return 1;
  if (t1.year_ < t2.year_)
    return -1;
  if (t1.month_ > t2.month_)
    return 1;
  if (t1.month_ < t2.month_)
    return -1;
  if (t1.day_in_month_ > t2.day_in_month_)
    return 1;
  if (t1.day_in_month_ < t2.day_in_month_)
    return -1;
  if (t1.hour_ > t2.hour_)
    return 1;
  if (t1.hour_ < t2.hour_)
    return -1;
  if (t1.minutes_> t2.minutes_)
    return 1;
  if (t1.minutes_ < t2.minutes_)
    return -1;
  if (t1.seconds_ > t2.seconds_)
    return 1;
  if (t1.seconds_ < t2.seconds_)
    return -1;
  return 0;
}

// Encryption is ssl
//    Set up a context
//    Initialize the encryption operation
//    Providing plaintext bytes to be encrypted
//    Finalizing the encryption operation
//    During initialization we will provide an EVP_CIPHER object.
//      In this case we are using EVP_aes_256_cbc(),
//      which uses the AES algorithm with a 256-bit key in
//      CBC mode.

bool encrypt(byte *in, int in_len, byte *key, byte *iv,
             byte *out, int * out_size) {
  EVP_CIPHER_CTX *ctx = nullptr;
  int len = 0;
  int out_len = 0;
  bool ret = true;

  if (!(ctx = EVP_CIPHER_CTX_new())) {
    printf("%s() error, line: %d, EVP_CIPHER_CTX_new() failed\n",
           __func__, __LINE__);
    ret = false;
    goto done;
  }
  if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
    printf("%s() error, line: %d, EVP_EncryptInit_ex() failed\n",
           __func__, __LINE__);
    ret = false;
    goto done;
  }
  if (1 != EVP_EncryptUpdate(ctx, out, &len, in, in_len)) {
    printf("%s() error, line: %d, EVP_EncryptUpdate() failed\n",
           __func__, __LINE__);
    ret = false;
    goto done;
  }
  out_len = len;
  if (1 != EVP_EncryptFinal_ex(ctx, out + len, &len)) {
    printf("%s() error, line: %d, EVP_EncryptFinal_ex() failed\n",
           __func__, __LINE__);
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

bool decrypt(byte *in, int in_len, byte *key, byte *iv,
             byte *out, int * size_out) {
  EVP_CIPHER_CTX *ctx = nullptr;
  int len = 0;
  int out_len = 0;
  bool ret = true;

  if (!(ctx = EVP_CIPHER_CTX_new())) {
    printf("%s() error, line: %d, EVP_CIPHER_CTX_new() failed\n",
           __func__, __LINE__);
    ret = false;
    goto done;
  }
  if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
    printf("%s() error, line: %d, EVP_DecryptInit failed\n",
           __func__, __LINE__);
    ret = false;
    goto done;
  }
  if (1 != EVP_DecryptUpdate(ctx, out, &len, in, in_len)) {
    printf("%s() error, line: %d, EVP_DecryptUpdate failed\n",
           __func__, __LINE__);
    ret = false;
    goto done;
  }
  out_len = len;
  if (1 != EVP_DecryptFinal_ex(ctx, out + len, &len)) {
    printf("%s() error, line: %d, EVP_DecryptFinal failed\n",
           __func__, __LINE__);
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

int cipher_block_byte_size(const char *alg_name) {
  int size = sizeof(cipher_block_byte_name_size)
             / sizeof(cipher_block_byte_name_size[0]);

  for (int i = 0; i < size; i++) {
    if (strcmp(alg_name, cipher_block_byte_name_size[i].name_) == 0)
      return cipher_block_byte_name_size[i].size_;
  }
  return -1;
}

int cipher_key_byte_size(const char *alg_name) {
  int size =
      sizeof(cipher_key_byte_name_size) / sizeof(cipher_key_byte_name_size[0]);

  for (int i = 0; i < size; i++) {
    if (strcmp(alg_name, cipher_key_byte_name_size[i].name_) == 0)
      return cipher_key_byte_name_size[i].size_;
  }
  return -1;
}

int digest_output_byte_size(const char *alg_name) {
  int size = sizeof(digest_byte_name_size) / sizeof(digest_byte_name_size[0]);

  for (int i = 0; i < size; i++) {
    if (strcmp(alg_name, digest_byte_name_size[i].name_) == 0)
      return digest_byte_name_size[i].size_;
  }
  return -1;
}

int mac_output_byte_size(const char *alg_name) {
  int size = sizeof(mac_byte_name_size) / sizeof(mac_byte_name_size[0]);

  for (int i = 0; i < size; i++) {
    if (strcmp(alg_name, mac_byte_name_size[i].name_) == 0)
      return mac_byte_name_size[i].size_;
  }
  return -1;
}


bool digest_message(const char* alg, const byte* message, int message_len,
                    byte* digest, unsigned int digest_len) {

  int n = digest_output_byte_size(alg);
  if (n < 0) {
    printf("%s() error, line: %d, digest_output_byte_size failed\n",
           __func__, __LINE__);
    return false;
  }
  if (n > (int)digest_len) {
    printf("%s() error, line: %d, digest_len wrong\n", __func__, __LINE__);
    return false;
  }

  EVP_MD_CTX* mdctx;

  if (strcmp(alg, Digest_method_sha_256) == 0
      || strcmp(alg, Digest_method_sha256) == 0) {
    if ((mdctx = EVP_MD_CTX_new()) == NULL) {
      printf("%s() error, line: %d, EVP_MD_CTX_new failed\n",
             __func__, __LINE__);
      return false;
    }
    if (1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL)) {
      printf("%s() error, line: %d, EVP_DigestInit failed\n",
             __func__, __LINE__);
      return false;
    }
  } else if (strcmp(alg, Digest_method_sha_384) == 0) {
    if ((mdctx = EVP_MD_CTX_new()) == NULL) {
      printf("%s() error, line: %d, EVP_MD_CTX_new failed\n",
             __func__, __LINE__);
      return false;
    }
    if (1 != EVP_DigestInit_ex(mdctx, EVP_sha384(), NULL)) {
      printf("%s() error, line: %d, EVP_DigestInit failed\n",
             __func__, __LINE__);
      return false;
    }
  } else if (strcmp(alg, Digest_method_sha_512) == 0) {
    if ((mdctx = EVP_MD_CTX_new()) == NULL) {
      printf("%s() error, line: %d, EVP_MD_CTX_new failed\n",
             __func__, __LINE__);
      return false;
    }
    if (1 != EVP_DigestInit_ex(mdctx, EVP_sha512(), NULL)) {
      printf("%s() error, line: %d, EVP_DigestInit failed\n",
             __func__, __LINE__);
      return false;
    }
  } else {
    printf("%s() error, line: %d, unknown hash \n", __func__, __LINE__);
    return false;
  }

  if (1 != EVP_DigestUpdate(mdctx, message, message_len)) {
    printf("%s() error, line: %d, EVP_DigestUpdate failed\n",
           __func__, __LINE__);
    return false;
  }
  if (1 != EVP_DigestFinal_ex(mdctx, digest, &digest_len)) {
    printf("%s() error, line: %d, EVP_DigestFinal_ex failed\n",
           __func__, __LINE__);
    return false;
  }
  EVP_MD_CTX_free(mdctx);

  return true;
}

bool aes_256_cbc_sha256_encrypt(byte *in, int in_len, byte *key, byte *iv,
                                byte *out, int * out_size) {
  int blk_size = cipher_block_byte_size(Enc_method_aes_256_cbc_hmac_sha256);
  int key_size = cipher_key_byte_size(Enc_method_aes_256_cbc_hmac_sha256);
  int mac_size = mac_output_byte_size(Enc_method_aes_256_cbc_hmac_sha256);
  int cipher_size = *out_size - blk_size;

  memset(out, 0, *out_size);

  if (!encrypt(in, in_len, key, iv, out + blk_size, &cipher_size)) {
    printf("%s() error, line: %d, aes_256_cbc_sha256_encrypt: encrypt failed\n",
           __func__, __LINE__);
    return false;
  }
  memcpy(out, iv, blk_size);
  cipher_size += blk_size;
  unsigned int hmac_size = mac_size;
  HMAC(EVP_sha256(), &key[key_size / 2], mac_size, out,
       cipher_size, out + cipher_size, &hmac_size);
  *out_size = cipher_size + hmac_size;

  return true;
}

bool aes_256_cbc_sha256_decrypt(byte *in, int in_len, byte *key, byte *out,
                                int * out_size) {
  int blk_size = cipher_block_byte_size(Enc_method_aes_256_cbc_hmac_sha256);
  int key_size = cipher_key_byte_size(Enc_method_aes_256_cbc_hmac_sha256);
  int mac_size = mac_output_byte_size(Enc_method_aes_256_cbc_hmac_sha256);
  int cipher_size = *out_size - blk_size;

  int plain_size = *out_size - blk_size - mac_size;
  int msg_with_iv_size = in_len - mac_size;
  unsigned int hmac_size = mac_size;

  byte hmac_out[hmac_size];
  HMAC(EVP_sha256(), &key[key_size / 2], mac_size, in,
       msg_with_iv_size, (byte *)hmac_out, &hmac_size);
  if (memcmp(hmac_out, in + msg_with_iv_size, mac_size) != 0) {
    printf("%s() error, line: %d, aes_256_cbc_sha256_decrypt: HMAC failed\n",
           __func__, __LINE__);
    return false;
  }

  if (!decrypt(in + blk_size, msg_with_iv_size - blk_size, key, in,
               out, &plain_size)) {
    printf("%s() error, line: %d, aes_256_cbc_sha256_decrypt: decrypt failed\n",
           __func__, __LINE__);
    return false;
  }
  *out_size = plain_size;
  return (memcmp(hmac_out, in + msg_with_iv_size, mac_size) == 0);
}

bool aes_256_cbc_sha384_encrypt(byte *in, int   in_len, byte *key, byte *iv,
                                byte *out, int * out_size) {
  int blk_size = cipher_block_byte_size(Enc_method_aes_256_cbc_hmac_sha384);
  int key_size = cipher_key_byte_size(Enc_method_aes_256_cbc_hmac_sha384);
  int mac_size = mac_output_byte_size(Enc_method_aes_256_cbc_hmac_sha384);
  int cipher_size = *out_size - blk_size;

  memset(out, 0, *out_size);

  if (!encrypt(in, in_len, key, iv, out + blk_size, &cipher_size)) {
    printf("%s() error, line: %d, aes_256_cbc_sha384_encrypt: encrypt failed\n",
           __func__, __LINE__);
    return false;
  }
  memcpy(out, iv, blk_size);
  cipher_size += blk_size;
  unsigned int hmac_size = mac_size;
  HMAC(EVP_sha384(), &key[key_size / 2], mac_size, out,
       cipher_size, out + cipher_size, &hmac_size);
  *out_size = cipher_size + hmac_size;

  return true;
}

bool aes_256_cbc_sha384_decrypt(byte *in, int in_len, byte *key,
                                byte *out, int * out_size) {
  int blk_size = cipher_block_byte_size(Enc_method_aes_256_cbc_hmac_sha384);
  int key_size = cipher_key_byte_size(Enc_method_aes_256_cbc_hmac_sha384);
  int mac_size = mac_output_byte_size(Enc_method_aes_256_cbc_hmac_sha384);
  int cipher_size = *out_size - blk_size;

  int          plain_size = *out_size - blk_size - mac_size;
  int          msg_with_iv_size = in_len - mac_size;
  unsigned int hmac_size = mac_size;

  byte hmac_out[hmac_size];
  HMAC(EVP_sha384(), &key[key_size / 2], mac_size, in,
       msg_with_iv_size, (byte *)hmac_out, &hmac_size);
  if (memcmp(hmac_out, in + msg_with_iv_size, mac_size) != 0) {
    printf("%s() error, line: %d, aes_256_cbc_sha384_decrypt: HMAC failed\n",
           __func__, __LINE__);
    return false;
  }

  if (!decrypt(in + blk_size, msg_with_iv_size - blk_size, key,
               in, out, &plain_size)) {
    printf("%s() error, line: %d, aes_256_cbc_sha384_decrypt: decrypt failed\n",
           __func__, __LINE__);
    return false;
  }
  *out_size = plain_size;
  return (memcmp(hmac_out, in + msg_with_iv_size, mac_size) == 0);
}

// We use 128 bit tag
bool aes_256_gcm_encrypt(byte *in, int in_len, byte *key, byte *iv,
                         byte *out, int * out_size) {
  EVP_CIPHER_CTX *ctx = nullptr;
  int len;
  int ciphertext_len;
  int blk_size = cipher_block_byte_size(Enc_method_aes_256);
  int key_size = cipher_key_byte_size(Enc_method_aes_256);
  int tag_len = 0;
  byte tag[16];
  int aad_len = 0;
  byte* aad = nullptr;
  bool ret = true;

  if (!(ctx = EVP_CIPHER_CTX_new())) {
    printf("%s() error, line: %d, EVP_CIPHER_CTX_new failed\n",
           __func__, __LINE__);
    return false;
  }

  if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr)) {
    printf("%s() error, line: %d, EVP_EncryptInit_ex failed\n",
           __func__, __LINE__);
    ret = false;
    goto done;
  }

  // set IV length
  if (1
      != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, blk_size, nullptr)) {
    printf("%s() error, line: %d, EVP_CIPHER_CTX_ctrl failed\n",
           __func__, __LINE__);
    ret = false;
    goto done;
  }
  if (1 != EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv)) {
    printf("%s() error, line: %d, EVP_EncryptInit_ex failed\n",
           __func__, __LINE__);
    ret = false;
    goto done;
  }

  memcpy(out, iv, blk_size);

  if (1 != EVP_EncryptUpdate(ctx, nullptr, &len, aad, aad_len)) {
    printf("%s() error, line: %d, EVP_EncryptUpdate failed\n",
           __func__, __LINE__);
    ret = false;
    goto done;
  }
  if (1 != EVP_EncryptUpdate(ctx, out + blk_size, &len, in, in_len)) {
    printf("%s() error, line: %d, EVP_EncryptUpdate failed\n",
           __func__, __LINE__);
    ret = false;
    goto done;
  }
  ciphertext_len = len + blk_size;

  // Finalize
  if (1 != EVP_EncryptFinal_ex(ctx, out + len, &len)) {
    printf("%s() error, line: %d, EVP_EncryptFinal_ex failed\n",
           __func__, __LINE__);
    ret = false;
    goto done;
  }
  ciphertext_len += len;

  tag_len = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, blk_size, tag);
  if (tag_len <= 0) {
    printf("%s() error, line: %d, EVP_CIPHER_CTX_ctrl failed\n",
           __func__, __LINE__);
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
bool aes_256_gcm_decrypt(byte *in, int in_len, byte *key,
                         byte *out, int * out_size) {
  EVP_CIPHER_CTX *ctx = nullptr;
  int blk_size = cipher_block_byte_size(Enc_method_aes_256);
  int key_size = cipher_key_byte_size(Enc_method_aes_256);
  byte* iv = in;
  bool ret = true;
  byte* tag = in + in_len - blk_size;
  int aad_len = 0;
  byte* aad = nullptr;
  int len;
  int plaintext_len;
  int stream_len = in_len - 2 * blk_size;
  int err = 0;

  if (!(ctx = EVP_CIPHER_CTX_new())) {
    printf("%s() error, line: %d, EVP_CIPHER_CTX_new failed\n",
           __func__, __LINE__);
    return false;
  }
  if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr)) {
    printf("%s() error, line: %d, EVP_DecryptInit_ex failed\n",
           __func__, __LINE__);
    ret = false;
    goto done;
  }
  if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, blk_size, nullptr)) {
    printf("%s() error, line: %d, EVP_CIPHER_CTX_ctrl failed\n",
           __func__, __LINE__);
    ret = false;
    goto done;
  }
  if (!EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv)) {
    printf("%s() error, line: %d, EVP_DecryptInit_ex failed\n",
           __func__, __LINE__);
    ret = false;
    goto done;
  }

  if (!EVP_DecryptUpdate(ctx, nullptr, &len, aad, aad_len)) {
    printf("%s() error, line: %d, EVP_DecryptUpdate failed\n",
           __func__, __LINE__);
    ret = false;
    goto done;
  }
  if (!EVP_DecryptUpdate(ctx, out, &len, in + blk_size, stream_len)) {
    printf("%s() error, line: %d, EVP_DecryptUpdate failed\n",
           __func__, __LINE__);
    ret = false;
    goto done;
  }
  plaintext_len = len;

  if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, blk_size, tag)) {
    printf("%s() error, line: %d, EVP_CIPHER_CTX_ctrl failed\n",
           __func__, __LINE__);
    ret = false;
    goto done;
  }

  // Finalize
  err = EVP_DecryptFinal_ex(ctx, in + in_len - blk_size, &len);
  if (err <= 0) {
    printf("%s() error, line: %d, EVP_DecryptFinal failed\n",
           __func__, __LINE__);
    ret = false;
    goto done;
  }

  *out_size = plaintext_len;

done:
  if (ctx != nullptr)
    EVP_CIPHER_CTX_free(ctx);
  return ret;
}

bool authenticated_encrypt(const char *alg_name, byte* in, int in_len, byte* key, int key_len,
                           byte* iv, int iv_len, byte* out, int* out_size) {

  int key_size = cipher_key_byte_size(alg_name);
  if (key_size > key_len) {
    printf("%s() error, line: %d, authenticated_encrypt: key length too short\n"
           "%s\n", __func__, __LINE__, alg_name);
    return false;
  }
  if (strcmp(alg_name, "aes-256-cbc-hmac-sha256") == 0) {
    return aes_256_cbc_sha256_encrypt(in, in_len, key, iv, out, out_size);
  } else if (strcmp(alg_name, Enc_method_aes_256_cbc_hmac_sha384) == 0) {
    return aes_256_cbc_sha384_encrypt(in, in_len, key, iv, out, out_size);
  } else if (strcmp(alg_name, Enc_method_aes_256_gcm) == 0) {
    return aes_256_gcm_encrypt(in, in_len, key, iv, out, out_size);
  } else {
    printf("%s() error, line: %d, authenticated_decrypt: unsupported algorithm "
           "%s\n", __func__, __LINE__, alg_name);
    return false;
  }
}

bool authenticated_decrypt(const char *alg_name, byte* in, int in_len, byte* key,
                           int key_len, byte* out, int* out_size) {
  int key_size = cipher_key_byte_size(alg_name);
  if (key_size > key_len) {
    printf("%s() error, line: %d, authenticated_decrypt: key length too short\n"
           "%s\n", __func__, __LINE__, alg_name);
    return false;
  }

  if (strcmp(alg_name, Enc_method_aes_256_cbc_hmac_sha256) == 0) {
    return aes_256_cbc_sha256_decrypt(in, in_len, key, out, out_size);
  } else if (strcmp(alg_name, Enc_method_aes_256_cbc_hmac_sha384) == 0) {
    return aes_256_cbc_sha384_decrypt(in, in_len, key, out, out_size);
  } else if (strcmp(alg_name, Enc_method_aes_256_gcm) == 0) {
    return aes_256_gcm_decrypt(in, in_len, key, out, out_size);
  } else {
    printf("%s() error, line: %d, authenticated_decrypt: unsupported algorithm "
           "%s\n", __func__, __LINE__, alg_name);
    return false;
  }
}

const int rsa_alg_type = 1;
const int ecc_alg_type = 2;
bool private_key_to_public_key(const key_message &in, key_message* out) {

  int n_bytes = 0;
  int alg_type = 0;
  if (in.key_type() == Enc_method_rsa_2048_private) {
    alg_type = rsa_alg_type;
    out->set_key_type(Enc_method_rsa_2048_public);
    n_bytes = cipher_block_byte_size(Enc_method_rsa_2048_public);
  } else if (in.key_type() == Enc_method_rsa_1024_private) {
    alg_type = rsa_alg_type;
    out->set_key_type(Enc_method_rsa_1024_public);
    n_bytes = cipher_block_byte_size(Enc_method_rsa_1024_public);
  } else if (in.key_type() == Enc_method_rsa_3072_private) {
    alg_type = rsa_alg_type;
    out->set_key_type(Enc_method_rsa_3072_public);
    n_bytes = cipher_block_byte_size(Enc_method_rsa_3072_public);
  } else if (in.key_type() == Enc_method_rsa_4096_private) {
    alg_type = rsa_alg_type;
    out->set_key_type(Enc_method_rsa_4096_public);
    n_bytes = cipher_block_byte_size(Enc_method_rsa_4096_public);
  } else if (in.key_type() == Enc_method_ecc_384_private) {
    alg_type = ecc_alg_type;
    out->set_key_type(Enc_method_ecc_384_public);
    n_bytes = cipher_block_byte_size(Enc_method_ecc_384_public);
  } else if (in.key_type() == Enc_method_ecc_256_private) {
    alg_type = ecc_alg_type;
    out->set_key_type(Enc_method_ecc_256_public);
    n_bytes = cipher_block_byte_size(Enc_method_ecc_256_public);
  } else {
    printf("%s() error, line %d, private_key_to_public_key: bad key type "
           "(n_bytes=%d)\n", __func__, __LINE__, n_bytes);

    return false;
  }

  out->set_key_name(in.key_name());
  out->set_not_before(in.not_before());
  out->set_not_after(in.not_after());
  out->set_certificate(in.certificate().data(), in.certificate().size());

  if (alg_type == rsa_alg_type) {
    rsa_message *rk = new rsa_message;
    rk->set_public_modulus(in.rsa_key().public_modulus().data(),
                           in.rsa_key().public_modulus().size());
    rk->set_public_exponent(in.rsa_key().public_exponent().data(),
                            in.rsa_key().public_exponent().size());
    out->set_allocated_rsa_key(rk);
    return true;
  } else if (alg_type == ecc_alg_type) {
    ecc_message *ek = new ecc_message;
    ek->CopyFrom(in.ecc_key());
    ek->mutable_private_multiplier()->clear();
    out->set_allocated_ecc_key(ek);
    return true;
  } else {
    printf("%s() error, line: %d, private_key_to_public_key: bad key type\n",
           __func__, __LINE__);
    return false;
  }
}

bool make_certifier_rsa_key(int n, key_message *k) {
  if (k == nullptr) {
    return false;
  }

  RSA *r = RSA_new();
  if (!generate_new_rsa_key(n, r)) {
    printf("%s() error, line: %d, make_certifier_rsa_key: Can't generate RSA "
           "key\n", __func__, __LINE__);
    return false;
  }

  if (n == 2048) {
    k->set_key_type(Enc_method_rsa_2048_private);
  } else if (n == 1024) {
    k->set_key_type(Enc_method_rsa_1024_private);
  } else if (n == 4096) {
    k->set_key_type(Enc_method_rsa_4096_private);
  } else if (n == 3072) {
    k->set_key_type(Enc_method_rsa_3072_private);
  } else {
    printf("%s() error, line: %d, bad modulus size failed\n",
           __func__, __LINE__);
    RSA_free(r);
    return false;
  }
  k->set_key_name("test-key-2");
  if (!RSA_to_key(r, k)) {
    printf("%s() error, line: %d, RSA_to_key failed\n", __func__, __LINE__);
    return false;
  }
  RSA_free(r);
  return true;
}

bool rsa_public_encrypt(RSA * key, byte *data, int data_len,
                        byte *encrypted, int * size_out) {
  int n = RSA_public_encrypt(data_len, data, encrypted, key, RSA_PKCS1_PADDING);
  if (n <= 0) {
    printf("%s() error, line: %d, rsa_public_encrypt: RSA_public_encrypt "
           "failed %d, %d\n", __func__, __LINE__, data_len, *size_out);
    return false;
  }
  *size_out = n;
  return true;
}

bool rsa_private_decrypt(RSA * key, byte *enc_data, int data_len,
                         byte *decrypted, int * size_out) {
  int n = RSA_private_decrypt(data_len, enc_data, decrypted,
                              key, RSA_PKCS1_PADDING);
  if (n <= 0) {
    printf("%s() error, line: %d, rsa_private_decrypt: RSA_private_decrypt "
           "failed %d, %d\n",
           __func__, __LINE__, data_len, *size_out);
    return false;
  }
  *size_out = n;
  return true;
}

//  PKCS compliant signer
bool rsa_sha256_sign(RSA * key, int to_sign_size, byte* to_sign,
                     int* sig_size, byte* sig) {
  return rsa_sign(Digest_method_sha_256, key, to_sign_size,
                   to_sign, sig_size, sig);
}

bool rsa_sha256_verify(RSA *key, int size, byte *msg, int sig_size, byte *sig) {
  return rsa_verify(Digest_method_sha_256, key, size, msg, sig_size, sig);
}

bool rsa_sign(const char *alg, RSA* key, int size,
              byte* msg, int* sig_size, byte* sig) {

  EVP_PKEY *private_key = EVP_PKEY_new();
  if (private_key == nullptr) {
    printf("%s() error, line: %d, rsa_sign: EVP_PKEY_new failed\n",
           __func__, __LINE__);
    return false;
  }
  EVP_PKEY_assign_RSA(private_key, key);
  char* digest_method = nullptr;

  EVP_MD_CTX *sign_ctx = EVP_MD_CTX_create();
  if (sign_ctx == nullptr) {
    printf("%s() error, line: %d, rsa_sign: EVP_MD_CTX_create() failed\n",
           __func__, __LINE__);
    return false;
  }

  unsigned int size_digest = 0;
  if (strcmp(Digest_method_sha_256, alg) == 0) {
    if (EVP_DigestSignInit(sign_ctx, nullptr, EVP_sha256(),
                           nullptr, private_key) <= 0) {
      printf("%s() error, line: %d, rsa_sign: EVP_DigestSignInit() failed\n",
             __func__, __LINE__);
      return false;
    }
    if (EVP_DigestSignUpdate(sign_ctx, msg, size) <= 0) {
      printf("%s() error, line: %d, rsa_sign: EVP_DigestSignUpdate() failed\n",
             __func__, __LINE__);
      return false;
    }
    size_t t = *sig_size;
    if (EVP_DigestSignFinal(sign_ctx, sig, &t) <= 0) {
      printf("%s() error, line: %d, rsa_sign: EVP_DigestSignFinal() failed\n",
             __func__, __LINE__);
      return false;
    }
    *sig_size = t;
  } else if (strcmp(Digest_method_sha_384, alg) == 0) {
    if (EVP_DigestSignInit(sign_ctx, nullptr, EVP_sha384(), nullptr, private_key) <= 0) {
      printf("%s() error, line: %d, rsa_sign: EVP_DigestSignInit() failed\n",
             __func__, __LINE__);
      return false;
    }
    if (EVP_DigestSignUpdate(sign_ctx, msg, size) <= 0) {
      printf("%s() error, line: %d, rsa_sign: EVP_DigestSignUpdate() failed\n",
             __func__, __LINE__);
      return false;
    }
    size_t t = *sig_size;
    if (EVP_DigestSignFinal(sign_ctx, sig, &t) <= 0) {
      printf("%s() error, line: %d, rsa_sign: EVP_DigestSignFinal() failed\n",
             __func__, __LINE__);
      return false;
    }
    *sig_size = t;
  } else {
    printf("%s() error, line: %d, rsa_sign: unsuported digest %s\n",
           __func__, __LINE__, alg);
    return false;
  }
  EVP_MD_CTX_destroy(sign_ctx);

  return true;
}

bool rsa_verify(const char *alg, RSA* key, int size, byte* msg,
                int sig_size, byte* sig) {

  if (strcmp(Digest_method_sha_256, alg) == 0) {
    unsigned int size_digest = digest_output_byte_size(Digest_method_sha_256);
    byte digest[size_digest];
    memset(digest, 0, size_digest);

    if (!digest_message(Digest_method_sha_256, (const byte *)msg, size,
                        digest, size_digest)) {
      printf("%s() error, line: %d, rsa_verify: digest_message failed\n",
             __func__, __LINE__);
      return false;
    }
    int  size_decrypted = RSA_size(key);
    byte decrypted[size_decrypted];
    memset(decrypted, 0, size_decrypted);
    int n = RSA_public_encrypt(sig_size, sig, decrypted, key, RSA_NO_PADDING);
    if (n < 0) {
      printf("%s() error, line: %d, rsa_verify: RSA_public_encrypt failed\n",
             __func__, __LINE__);
      return false;
    }
    if (memcmp(digest, &decrypted[n - size_digest], size_digest) != 0) {
      printf("%s() error, line: %d, rsa_verify: digests don't match\n",
             __func__, __LINE__);
      return false;
    }

    const int check_size = 16;
    byte check_buf[16] = {
        0x00,
        0x01,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
    };
    if (memcmp(check_buf, decrypted, check_size) != 0) {
      printf("%s() error, line: %d, rsa_verify: Bad header\n",
             __func__, __LINE__);
      return false;
    }
    return memcmp(digest, &decrypted[n - size_digest], size_digest) == 0;
  } else if (strcmp(Digest_method_sha_384, alg) == 0) {
    unsigned int size_digest = digest_output_byte_size(Digest_method_sha_384);
    byte digest[size_digest];
    memset(digest, 0, size_digest);
    if (!digest_message(Digest_method_sha_384, (const byte *)msg, size,
                        digest, size_digest)) {
      printf("%s() error, line: %d, digest_message failed\n",
             __func__, __LINE__);
      return false;
    }
    int  size_decrypted = RSA_size(key);
    byte decrypted[size_decrypted];
    memset(decrypted, 0, size_decrypted);
    int n = RSA_public_encrypt(sig_size, sig, decrypted, key, RSA_NO_PADDING);
    if (n < 0) {
      printf("%s() error, line: %d, rsa_verify: RSA_public_encrypt failed\n",
             __func__, __LINE__);
      return false;
    }
    const int check_size = 16;
    byte check_buf[16] = {
        0x00,
        0x01,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
    };
    if (memcmp(check_buf, decrypted, check_size) != 0) {
      printf("%s() error, line: %d, rsa_verify: Bad header\n",
             __func__, __LINE__);
      return false;
    }
    return memcmp(digest, &decrypted[n - size_digest], size_digest) == 0;
  } else {
    printf("%s() error, line: %d, rsa_verify: unsupported digest\n",
           __func__, __LINE__);
    return false;
  }
}

bool generate_new_rsa_key(int num_bits, RSA *r) {
  bool ret = true;
  BIGNUM* bne = NULL;
  uint32_t e = RSA_F4;

  bne = BN_new();
  if (bne == nullptr) {
    printf("%s() error, line: %d, BN_new failed\n", __func__, __LINE__);
    return false;
  }
  if (1 != BN_set_word(bne, e)) {
    printf("%s() error, line: %d, BN_set_word  failed\n", __func__, __LINE__);
    ret = false;
    goto done;
  }
  if (1 != RSA_generate_key_ex(r, num_bits, bne, NULL)) {
    printf("%s() error, line: %d, RSA_generate_key_ex failed\n",
           __func__, __LINE__);
    ret = false;
    goto done;
  }

done:
  BN_free(bne);
  return ret;
}

bool key_to_RSA(const key_message &k, RSA *r) {
  bool private_key = true;
  int  key_size_bits = 0;
  if (k.key_type() == Enc_method_rsa_1024_public) {
    key_size_bits = 1024;
    private_key = false;
  } else if (k.key_type() == Enc_method_rsa_1024_private) {
    key_size_bits = 1024;
    private_key = true;
  } else if (k.key_type() == Enc_method_rsa_2048_public) {
    key_size_bits = 2048;
    private_key = false;
  } else if (k.key_type() == Enc_method_rsa_2048_private) {
    key_size_bits = 2048;
    private_key = true;
  } else if (k.key_type() == Enc_method_rsa_4096_private) {
    key_size_bits = 4096;
    private_key = true;
  } else if (k.key_type() == Enc_method_rsa_4096_public) {
    key_size_bits = 4096;
    private_key = false;
  } else if (k.key_type() == Enc_method_rsa_3072_private) {
    key_size_bits = 3072;
    private_key = true;
  } else if (k.key_type() == Enc_method_rsa_3072_public) {
    key_size_bits = 3072;
    private_key = false;
  } else {
    // Shut compiler warning about key_size_bits set-but-not-used
    return (key_size_bits != 0);
  }

  if (!k.has_rsa_key()) {
    printf("%s() error, line: %d, no rsa key\n", __func__, __LINE__);
    return false;
  }
  const rsa_message &rsa_key_data = k.rsa_key();
  if (!rsa_key_data.has_public_modulus()
      || !rsa_key_data.has_public_exponent()) {
    printf("%s() error, line: %d, modulus or exponent missing\n",
           __func__, __LINE__);
    print_key_message(k);
    return false;
  }
  BIGNUM* n = BN_bin2bn((byte *)(rsa_key_data.public_modulus().data()),
                        (int)(rsa_key_data.public_modulus().size()),
                        NULL);
  if (n == nullptr) {
    printf("%s() error, line: %d, Can't get bignum\n", __func__, __LINE__);
    return false;
  }
  BIGNUM* e = BN_bin2bn((const byte *)rsa_key_data.public_exponent().data(),
                        (int)rsa_key_data.public_exponent().size(),
                        NULL);
  if (e == nullptr) {
    printf("%s() error, line: %d, Can't get bignum\n", __func__, __LINE__);
    return false;
  }
  BIGNUM* d = nullptr;
  if (private_key && rsa_key_data.has_private_exponent()) {
    d = BN_bin2bn((const byte *)rsa_key_data.private_exponent().data(),
                  (int)rsa_key_data.private_exponent().size(),
                  NULL);
    if (d == nullptr) {
      printf("%s() error, line: %d, Can't get bignum\n", __func__, __LINE__);
      return false;
    }
  }
  if (1 != RSA_set0_key(r, n, e, d)) {
    printf("%s() error, line: %d, RSA_set0_key failed\n", __func__, __LINE__);
    return false;
  }
  if (private_key) {
    BIGNUM* p = nullptr;
    BIGNUM* q = nullptr;
    BIGNUM* dmp1 = nullptr;
    BIGNUM* dmq1 = nullptr;
    BIGNUM* iqmp = nullptr;
    if (rsa_key_data.has_private_p()) {
      p = BN_bin2bn((const byte *)rsa_key_data.private_p().data(),
                    (int)rsa_key_data.private_p().size(),
                    NULL);
      if (p == nullptr) {
        printf("%s() error, line: %d, Can't get bignum\n", __func__, __LINE__);
        return false;
      }
    }
    if (rsa_key_data.has_private_q()) {
      q = BN_bin2bn((const byte *)rsa_key_data.private_q().data(),
                    (int)rsa_key_data.private_q().size(),
                    NULL);
      if (q == nullptr) {
        printf("%s() error, line: %d, Can't get bignum\n", __func__, __LINE__);
        return false;
      }
    }
    if (rsa_key_data.has_private_dp()) {
      dmp1 = BN_bin2bn((const byte *)rsa_key_data.private_dp().data(),
                       (int)rsa_key_data.private_dp().size(),
                       NULL);
      if (dmp1 == nullptr) {
        printf("%s() error, line: %d, Can't get bignum\n", __func__, __LINE__);
        return false;
      }
    }
    if (rsa_key_data.has_private_dq()) {
      dmq1 = BN_bin2bn((const byte *)rsa_key_data.private_dq().data(),
                       (int)rsa_key_data.private_dq().size(),
                       NULL);
      if (dmq1 == nullptr) {
        printf("%s() error, line: %d, Can't get bignum\n", __func__, __LINE__);
        return false;
      }
    }
    if (rsa_key_data.has_private_iqmp()) {
      iqmp = BN_bin2bn((const byte *)rsa_key_data.private_iqmp().data(),
                       (int)rsa_key_data.private_iqmp().size(),
                       NULL);
      if (iqmp == nullptr) {
        printf("%s() error, line: %d, Can't get bignum\n", __func__, __LINE__);
        return false;
      }
    }
    if (1 != RSA_set0_factors(r, p, q)) {
      printf("%s() error, line: %d, RSA_set0_factors failed\n",
             __func__, __LINE__);
      return false;
    }
    if (1 != RSA_set0_crt_params(r, dmp1, dmq1, iqmp)) {
      printf("%s() error, line: %d, RSA_set0_crt_params failed\n",
             __func__, __LINE__);
      return false;
    }
  }
  return true;
}

bool RSA_to_key(const RSA *r, key_message *k) {
  const BIGNUM* m = nullptr;
  const BIGNUM* e = nullptr;
  const BIGNUM* d = nullptr;
  const BIGNUM* p = nullptr;
  const BIGNUM* q = nullptr;
  const BIGNUM* dmp1 = nullptr;
  const BIGNUM* dmq1 = nullptr;
  const BIGNUM* iqmp = nullptr;

  RSA_get0_key(r, &m, &e, &d);
  RSA_get0_factors(r, &p, &q);
  RSA_get0_crt_params(r, &dmp1, &dmq1, &iqmp);

  int rsa_size = RSA_bits(r);
  if (rsa_size == 1024) {
    if (d == nullptr)
      k->set_key_type(Enc_method_rsa_1024_public);
    else
      k->set_key_type(Enc_method_rsa_1024_private);
  } else if (rsa_size == 2048) {
    if (d == nullptr)
      k->set_key_type(Enc_method_rsa_2048_public);
    else
      k->set_key_type(Enc_method_rsa_2048_private);
  } else if (rsa_size == 4096) {
    if (d == nullptr)
      k->set_key_type(Enc_method_rsa_4096_public);
    else
      k->set_key_type(Enc_method_rsa_4096_private);
  } else if (rsa_size == 3072) {
    if (d == nullptr)
      k->set_key_type(Enc_method_rsa_3072_public);
    else
      k->set_key_type(Enc_method_rsa_3072_private);
  } else {
    return false;
  }
  rsa_message *rsa = new (rsa_message);
  k->set_allocated_rsa_key(rsa);

  int i;
  int size;
  if (m != nullptr) {
    size = BN_num_bytes(m);
    byte m_b[size];
    memset(m_b, 0, size);
    i = BN_bn2bin(m, m_b);
    rsa->set_public_modulus((void *)m_b, i);
  }
  if (e != nullptr) {
    size = BN_num_bytes(e);
    byte e_b[size];
    memset(e_b, 0, size);
    i = BN_bn2bin(e, e_b);
    rsa->set_public_exponent((void *)e_b, i);
  }
  if (d != nullptr) {
    size = BN_num_bytes(d);
    byte d_b[size];
    memset(d_b, 0, size);
    i = BN_bn2bin(d, d_b);
    rsa->set_private_exponent((void *)d_b, i);

    size = BN_num_bytes(p);
    byte p_b[size];
    memset(p_b, 0, size);
    i = BN_bn2bin(p, p_b);
    rsa->set_private_p((void *)p_b, i);

    size = BN_num_bytes(q);
    byte q_b[size];
    memset(q_b, 0, size);
    i = BN_bn2bin(q, q_b);
    rsa->set_private_q((void *)q_b, i);

    size = BN_num_bytes(dmp1);
    byte dmp1_b[size];
    memset(dmp1_b, 0, size);
    i = BN_bn2bin(dmp1, dmp1_b);
    rsa->set_private_dp((void *)dmp1_b, i);

    size = BN_num_bytes(dmq1);
    byte dmq1_b[size];
    memset(dmq1_b, 0, size);
    i = BN_bn2bin(dmq1, dmq1_b);
    rsa->set_private_dq((void *)dmq1_b, i);

    size = BN_num_bytes(iqmp);
    byte iqmp_b[size];
    memset(iqmp_b, 0, size);
    i = BN_bn2bin(iqmp, iqmp_b);
    rsa->set_private_iqmp((void *)iqmp_b, i);
  }
  return true;
}

void print_point(const point_message &pt) {
  if (!pt.has_x() || !pt.has_y())
    return;

  BIGNUM* x = BN_new();
  BIGNUM* y = BN_new();

  BN_bin2bn((byte *)pt.x().data(), pt.x().size(), x);
  BN_bin2bn((byte *)pt.y().data(), pt.y().size(), y);
  printf("(");
  BN_print_fp(stdout, x);
  printf(", ");
  BN_print_fp(stdout, y);
  printf(")");

  BN_free(x);
  BN_free(y);
}

void print_ecc_key(const ecc_message &em) {

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
    BIGNUM *order = BN_new();
    BN_bin2bn((byte *)em.order_of_base_point().data(),
              em.order_of_base_point().size(),
              order);
    printf("order: ");
    BN_print_fp(stdout, order);
    printf("\n");
    BN_free(order);
  }

  if (em.has_private_multiplier()) {
    BIGNUM* private_mult = BN_new();

    BN_bin2bn((byte *)em.private_multiplier().data(),
              em.private_multiplier().size(),
              private_mult);
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

    BN_bin2bn((byte *)em.curve_p().data(), em.curve_p().size(), p);
    BN_bin2bn((byte *)em.curve_a().data(), em.curve_a().size(), a);
    BN_bin2bn((byte *)em.curve_b().data(), em.curve_b().size(), b);

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
//      compute Q=xkG = kP.  Subtract Q from kP + P_m = P_m.  Extract message
//      from P_m.
bool ecc_sign(const char *alg, EC_KEY* key, int size, byte* msg,
              int* size_out, byte* out) {
  unsigned int len = (unsigned int)digest_output_byte_size(alg);
  byte         digest[len];

  int blk_len = ECDSA_size(key);
  if (*size_out < 2 * blk_len) {
    printf("%s() error, line: %d, ecc_sign: size_out too small %d %d\n",
           __func__, __LINE__, *size_out, blk_len);
    return false;
  }

  if (!digest_message(alg, msg, size, digest, len)) {
    printf("%s() error, line: %d, ecc_sign: digest fails\n",
           __func__, __LINE__);
    return false;
  }
  unsigned int sz = (unsigned int)*size_out;
  if (ECDSA_sign(0, digest, len, out, &sz, key) != 1) {
    printf("%s() error, line: %d, ecc_sign: ECDSA_sign fails\n",
           __func__, __LINE__);
    return false;
  }
  *size_out = (int)sz;
  return true;
}

bool ecc_verify(const char *alg, EC_KEY* key, int size,
                byte* msg, int size_sig, byte* sig) {
  int ilen = (unsigned int)digest_output_byte_size(alg);
  if (ilen <= 0) {
    printf("%s() error, line: %d, Bad digest size\n", __func__, __LINE__);
    return false;
  }
  unsigned int len = (unsigned int)ilen;
  byte         digest[len];

  if (!digest_message(alg, msg, size, digest, len)) {
    printf("%s() error, line: %d, ecc_verify: %s digest failed %d\n",
           __func__, __LINE__, alg, len);
    return false;
  }
  int res = ECDSA_verify(0, digest, len, sig, size_sig, key);
  if (res != 1) {
    printf("%s() error, line: %d, ecc_verify: ECDSA_failed %d %d\n",
           __func__, __LINE__, len, size_sig);
    return false;
  }
  return true;
}

EC_KEY* generate_new_ecc_key(int num_bits) {

  EC_KEY *ecc_key = nullptr;
  if (num_bits == 384) {
    ecc_key = EC_KEY_new_by_curve_name(NID_secp384r1);
  } else if (num_bits == 256) {
    ecc_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  } else {
    printf("%s() error, line: %d, generate_new_ecc_key: Only P-256 and P-384 "
           "supported\n",
           __func__, __LINE__);
    return nullptr;
  }
  if (ecc_key == nullptr) {
    printf("%s() error, line: %d,  generate_new_ecc_key: Can't get curve by "
           "name\n", __func__, __LINE__);
    return nullptr;
  }

  if (1 != EC_KEY_generate_key(ecc_key)) {
    printf("%s() error, line: %d, generate_new_ecc_key: Can't generate key\n",
           __func__, __LINE__); return nullptr;
  }

  BN_CTX* ctx = BN_CTX_new();
  const EC_GROUP *group = EC_KEY_get0_group(ecc_key);
  if (group == nullptr) {
    printf("%s() error, line: %d, generate_new_ecc_key: Can't get group (1)\n",
           __func__, __LINE__);
    return nullptr;
  }
  BIGNUM* pt_x = BN_new();
  BIGNUM* pt_y = BN_new();
  const EC_POINT *pt = EC_KEY_get0_public_key(ecc_key);
  EC_POINT_get_affine_coordinates_GFp(group, pt, pt_x, pt_y, ctx);
  BN_CTX_free(ctx);

  return ecc_key;
}

// Todo: free k on error
EC_KEY *key_to_ECC(const key_message &k) {

  EC_KEY *ecc_key = nullptr;
  if (k.key_type() == Enc_method_ecc_384_private
      || k.key_type() == Enc_method_ecc_384_public) {
    ecc_key = EC_KEY_new_by_curve_name(NID_secp384r1);
  } else if (k.key_type() == Enc_method_ecc_256_private
             || k.key_type() == Enc_method_ecc_256_public) {
    ecc_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  } else {
    printf("%s() error, line: %d, key_to_ECC: wrong type %s\n",
           __func__, __LINE__, k.key_type().c_str());
    return nullptr;
  }
  if (ecc_key == nullptr) {
    printf("%s() error, line: %d, key_to_ECC: Can't get curve by name\n",
           __func__, __LINE__);
    return nullptr;
  }

  // set private multiplier
  const BIGNUM *priv_mult =
      BN_bin2bn((byte *)(k.ecc_key().private_multiplier().data()),
                (int)(k.ecc_key().private_multiplier().size()),
                NULL);
  if (priv_mult == nullptr) {
    printf("%s() error, line: %d, key_to_ECC: no private mult\n",
           __func__, __LINE__);
    return nullptr;
  }
  if (EC_KEY_set_private_key(ecc_key, priv_mult) != 1) {
    printf("%s() error, line: %d, key_to_ECC: not can't set\n",
           __func__, __LINE__);
    return nullptr;
  }

  // set public point
  const EC_GROUP *group = EC_KEY_get0_group(ecc_key);
  if (group == nullptr) {
    printf("%s() error, line: %d, key_to_ECC: Can't get group (1)\n",
           __func__, __LINE__);
    return nullptr;
  }
  const BIGNUM* p_pt_x =
      BN_bin2bn((byte *)(k.ecc_key().public_point().x().data()),
                (int)(k.ecc_key().public_point().x().size()),
                NULL);
  const BIGNUM* p_pt_y =
      BN_bin2bn((byte *)(k.ecc_key().public_point().y().data()),
                (int)(k.ecc_key().public_point().y().size()),
                NULL);
  if (p_pt_x == nullptr || p_pt_y == nullptr) {
    printf("%s() error, line: %d, key_to_ECC: pts are null\n",
           __func__, __LINE__);
    return nullptr;
  }

  EC_POINT* pt = EC_POINT_new(group);
  if (pt == nullptr) {
    printf("%s() error, line: %d, key_to_ECC: no pt in group\n",
           __func__, __LINE__);
    return nullptr;
  }
  BN_CTX* ctx = BN_CTX_new();
  if (ctx == nullptr) {
    printf("%s() error, line: %d, BN_CTX_new failed\n", __func__, __LINE__);
    return nullptr;
  }
  if (EC_POINT_set_affine_coordinates_GFp(group, pt, p_pt_x, p_pt_y, ctx)
      != 1) {
    printf("%s() error, line: %d, key_to_ECC: can't set affine\n",
           __func__, __LINE__);
    return nullptr;
  }
  if (EC_KEY_set_public_key(ecc_key, pt) != 1) {
    printf("%s() error, line: %d, key_to_ECC: can't set public\n",
           __func__, __LINE__);
    return nullptr;
  }
  BN_CTX_free(ctx);

  return ecc_key;
}

bool ECC_to_key(const EC_KEY *ecc_key, key_message *k) {
  if (ecc_key == nullptr) {
    printf("%s() error, line: %d, ECC_to_key\n", __func__, __LINE__);
    return false;
  }
  ecc_message* ek = new ecc_message;
  if (ek == nullptr) {
    printf("%s() error, line: %d, Can't allocate ecc_message\n",
           __func__, __LINE__);
    return false;
  }


  BN_CTX* ctx = BN_CTX_new();
  if (ctx == nullptr) {
    printf("%s() error, line: %d, BN_CTX_new failed\n", __func__, __LINE__);
    return false;
  }

  const EC_GROUP *group = EC_KEY_get0_group(ecc_key);
  if (group == nullptr) {
    printf("%s() error, line: %d, ECC_to_key: Can't get group\n",
           __func__, __LINE__);
    return false;
  }

  BIGNUM* p = BN_new();
  BIGNUM* a = BN_new();
  BIGNUM* b = BN_new();
  if (EC_GROUP_get_curve_GFp(group, p, a, b, ctx) <= 0) {
    printf("%s() error, line: %d, EC_GROUP_get_curve_GFp failed\n",
           __func__, __LINE__);
    BN_CTX_free(ctx);
    return false;
  }

  int modulus_size = BN_num_bytes(p);

  if (modulus_size == 48) {
    k->set_key_type(Enc_method_ecc_384_public);
    ek->set_curve_name("P-384");
  } else if (modulus_size == 32) {
    k->set_key_type(Enc_method_ecc_256_public);
    ek->set_curve_name("P-256");
  } else {
    printf("%s() error, line: %d, ECC_to_key: Modulus size not supported: %d\n",
           __func__, __LINE__,
           modulus_size);
    return false;
  }

  // set p, a, b
  int  sz = BN_num_bytes(p);
  byte p_buf[sz];
  sz = BN_bn2bin(p, p_buf);
  ek->mutable_curve_p()->assign((char *)p_buf, sz);

  sz = BN_num_bytes(a);
  byte a_buf[sz];
  sz = BN_bn2bin(a, a_buf);
  ek->mutable_curve_a()->assign((char *)a_buf, sz);

  sz = BN_num_bytes(b);
  byte b_buf[sz];
  sz = BN_bn2bin(b, b_buf);
  ek->mutable_curve_b()->assign((char *)b_buf, sz);

  BN_free(p);
  BN_free(a);
  BN_free(b);

  // set base_point
  const EC_POINT *generator = EC_GROUP_get0_generator(group);
  if (generator == nullptr) {
    printf("%s() error, line: %d, ECC_to_key: Can't get base point\n",
           __func__, __LINE__);
    BN_CTX_free(ctx);
    return false;
  }
  BIGNUM *x = BN_new();
  BIGNUM *y = BN_new();
  if (EC_POINT_get_affine_coordinates_GFp(group, generator, x, y, ctx) != 1) {
    printf("%s() error, line: %d, ECC_to_key: Can't get affine coordinates\n",
           __func__, __LINE__);
    BN_CTX_free(ctx);
    return false;
  }

  sz = BN_num_bytes(x);
  byte x_buf[sz];
  sz = BN_bn2bin(x, x_buf);
  point_message *b_pt = new point_message;
  ek->set_allocated_base_point(b_pt);
  b_pt->set_x((void *)x_buf, sz);

  sz = BN_num_bytes(y);
  byte y_buf[sz];
  sz = BN_bn2bin(y, y_buf);
  b_pt->set_y((void *)y_buf, sz);
  BN_free(x);
  BN_free(y);

  // set public_point
  const EC_POINT *pub_pt = EC_KEY_get0_public_key(ecc_key);
  if (pub_pt == nullptr) {
    printf("%s() error, line: %d, ECC_to_key: Can't get public point\n",
           __func__, __LINE__);
    BN_CTX_free(ctx);
    return false;
  }

  BIGNUM *xx = BN_new();
  BIGNUM *yy = BN_new();
  if (EC_POINT_get_affine_coordinates_GFp(group, pub_pt, xx, yy, ctx) != 1) {
    printf("%s() error, line: %d, ECC_to_key: Can't get affine coordinates\n",
           __func__, __LINE__);
    BN_CTX_free(ctx);
    return false;
  }
  sz = BN_num_bytes(xx);
  byte xx_buf[sz];
  sz = BN_bn2bin(xx, xx_buf);
  point_message *p_pt = new point_message;
  ek->set_allocated_public_point(p_pt);
  p_pt->set_x((void *)xx_buf, sz);
  sz = BN_num_bytes(yy);
  byte yy_buf[sz];
  sz = BN_bn2bin(yy, yy_buf);
  p_pt->set_y((void *)yy_buf, sz);
  BN_free(xx);
  BN_free(yy);

  // set order_of_base_point
  BIGNUM *order = BN_new();
  if (EC_GROUP_get_order(group, order, ctx) != 1) {
    printf("%s() error, line: %d, ECC_to_key: Can't get order\n",
           __func__, __LINE__);
    BN_free(order);
    BN_CTX_free(ctx);
    return false;
  }
  sz = BN_num_bytes(order);
  byte order_buf[sz];
  sz = BN_bn2bin(order, order_buf);
  ek->set_order_of_base_point((void *)order_buf, sz);
  BN_free(order);

  // set private_multiplier
  const BIGNUM *pk = EC_KEY_get0_private_key(ecc_key);
  if (pk != nullptr) {
    if (modulus_size == 48) {
      k->set_key_type(Enc_method_ecc_384_private);
    } else if (modulus_size == 32) {
      k->set_key_type(Enc_method_ecc_256_private);
    } else {
      printf("%s() error, line: %d, EC_KEY_get0_private_key failed\n",
             __func__, __LINE__);
      return false;
    }
    sz = BN_num_bytes(pk);
    byte pm_buf[sz];
    sz = BN_bn2bin(pk, pm_buf);
    ek->set_private_multiplier((void *)pm_buf, sz);
  }

  k->set_allocated_ecc_key(ek);
  if (ctx != nullptr)
    BN_CTX_free(ctx);
  return true;
}

bool make_certifier_ecc_key(int n, key_message *k) {
  if (k == nullptr)
    return false;
  if (n == 384) {
    k->set_key_type(Enc_method_ecc_384_private);
  } else if (n == 256) {
    k->set_key_type(Enc_method_ecc_256_private);
  } else {
    printf(
        "%s() error, line: %d, make_certifier_ecc_key: unsupported key size\n",
        __func__, __LINE__);
    return false;
  }

  EC_KEY *ek = generate_new_ecc_key(n);
  if (ek == nullptr) {
    printf("%s() error, line: %d, generate_new_ecc_key failed\n",
           __func__, __LINE__);
    return false;
  }

  k->set_key_name("test-key-2");
  if (!ECC_to_key(ek, k)) {
    printf("%s() error, line: %d, ECC_to_key failed\n", __func__, __LINE__);
    return false;
  }
  EC_KEY_free(ek);
  return true;
}


void print_rsa_key(const rsa_message &rsa) {
  if (rsa.has_public_modulus()) {
    printf("Modulus: ");
    print_bytes(rsa.public_modulus().size(),
                (byte *)rsa.public_modulus().data());
    printf("\n");
  }
  if (rsa.has_public_exponent()) {
    printf("Public exponent: ");
    print_bytes(rsa.public_exponent().size(),
                (byte *)rsa.public_exponent().data());
    printf("\n");
  }
  if (rsa.has_private_exponent()) {
    printf("Private exponent: ");
    print_bytes(rsa.private_exponent().size(),
                (byte *)rsa.private_exponent().data());
    printf("\n");
  }
  if (rsa.has_private_p()) {
    printf("P              : ");
    print_bytes(rsa.private_p().size(), (byte *)rsa.private_p().data());
    printf("\n");
  }
  if (rsa.has_private_q()) {
    printf("Q              : ");
    print_bytes(rsa.private_q().size(), (byte *)rsa.private_q().data());
    printf("\n");
  }
  if (rsa.has_private_dp()) {
    printf("DP             : ");
    print_bytes(rsa.private_dp().size(), (byte *)rsa.private_dp().data());
    printf("\n");
  }
  if (rsa.has_private_dq()) {
    printf("DQ             : ");
    print_bytes(rsa.private_dq().size(), (byte *)rsa.private_dq().data());
    printf("\n");
  }
}

void print_key_message(const key_message &k) {
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
    print_bytes(k.secret_key_bits().size(), (byte *)k.secret_key_bits().data());
    printf("\n");
  }
  if (k.has_certificate() && k.certificate().size() > 0) {
    X509 *cert = X509_new();
    if (cert == nullptr)
      return;
    string in;
    in.assign((char *)k.certificate().data(), k.certificate().size());
    if (!asn1_to_x509(in, cert)) {
      X509_free(cert);
      return;
    }
    X509_print_fp(stdout, cert);
    X509_free(cert);
  }
}

void print_key_descriptor(const key_message &k) {

  if (!k.has_key_type())
    return;

  if (k.key_type() == Enc_method_rsa_2048_private
      || k.key_type() == Enc_method_rsa_2048_public
      || k.key_type() == Enc_method_rsa_3072_private
      || k.key_type() == Enc_method_rsa_3072_public
      || k.key_type() == Enc_method_rsa_1024_private
      || k.key_type() == Enc_method_rsa_1024_public
      || k.key_type() == Enc_method_rsa_4096_private
      || k.key_type() == Enc_method_rsa_4096_public) {
    printf("Key[rsa, ");
    if (k.has_key_name()) {
      printf("%s, ", k.key_name().c_str());
    }
    if (k.has_rsa_key()) {
      int l = (int)k.rsa_key().public_modulus().size();
      if (l > 20)
        l = 20;
      if (k.rsa_key().has_public_modulus()) {
        print_bytes(l, (byte *)k.rsa_key().public_modulus().data());
      }
      printf("]");
    }
  } else if (k.key_type() == Enc_method_ecc_384_private
             || k.key_type() == Enc_method_ecc_384_public
             || k.key_type() == Enc_method_ecc_256_private
             || k.key_type() == Enc_method_ecc_256_public) {
    printf("Key[ecc, ");
    if (k.has_key_name()) {
      printf("%s, ", k.key_name().c_str());
    }
    if (k.has_ecc_key()) {
      printf("%s-", k.ecc_key().curve_name().c_str());
      print_bytes(k.ecc_key().base_point().x().size(),
                  (byte *)k.ecc_key().base_point().x().data());
      printf("_");
      print_bytes(k.ecc_key().base_point().y().size(),
                  (byte *)k.ecc_key().base_point().y().data());
      printf("]");
    }
  } else {
    printf("%s() error, line: %d, unsupported type %s ",
           __func__, __LINE__, k.key_type().c_str());
  }
}

int add_ext(X509* cert, int nid, const char *value) {
  X509_EXTENSION* ex;
  X509V3_CTX ctx;

  // This sets the 'context' of the extensions.
  X509V3_set_ctx_nodb(&ctx);

  X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
  ex = X509V3_EXT_nconf_nid(NULL, &ctx, nid, value);
  if (!ex)
    return 0;

  X509_add_ext(cert, ex, -1);
  X509_EXTENSION_free(ex);
  return 1;
}

// Caller should have allocated X509
// name is some printable version of the measurement
bool produce_artifact(key_message &signing_key, string& issuer_name_str,
                      string& issuer_organization_str,
                      key_message& subject_key, string& subject_name_str,
                      string& subject_organization_str, uint64_t sn,
                      double secs_duration, X509* x509, bool is_root) {

  ASN1_INTEGER *a = ASN1_INTEGER_new();
  ASN1_INTEGER_set_uint64(a, sn);
  X509_set_serialNumber(x509, a);
  X509_set_version(x509, 2L);

  X509_NAME *subject_name = X509_NAME_new();
  X509_NAME_add_entry_by_txt(subject_name, "CN", MBSTRING_ASC,
                             (unsigned char *)subject_name_str.c_str(),
                             -1, -1, 0);
  X509_NAME_add_entry_by_txt(subject_name, "O", MBSTRING_ASC,
                             (const byte *)subject_organization_str.c_str(),
                             -1, -1, 0);
  X509_set_subject_name(x509, subject_name);

  X509_NAME *issuer_name = X509_NAME_new();
  X509_NAME_add_entry_by_txt(issuer_name, "CN", MBSTRING_ASC, (unsigned char *)issuer_name_str.c_str(),
                             -1, -1, 0);
  X509_NAME_add_entry_by_txt(issuer_name, "O", MBSTRING_ASC,
                             (const byte *)issuer_organization_str.c_str(),
                             -1, -1, 0);
  X509_set_issuer_name(x509, issuer_name);

  time_t     t_start = time(NULL);
  ASN1_TIME *tm_start = ASN1_TIME_new();
  ASN1_TIME_set(tm_start, t_start);
  int        offset_day = (int)(secs_duration / 86400.0);
  long       offset_sec = ((long)secs_duration) - ((long)offset_day * 86400);
  ASN1_TIME *tm_end = ASN1_TIME_adj(NULL, t_start, offset_day, offset_sec);
  X509_set1_notBefore(x509, tm_start);
  X509_set1_notAfter(x509, tm_end);

    add_ext(x509, NID_key_usage, "critical,keyCertSign,digitalSignature,cRLSign");
    add_ext(x509, NID_ext_key_usage, "clientAuth,serverAuth");
    // add_ext(x509, NID_subject_key_identifier, "hash");
    if (is_root) {
      add_ext(x509, NID_basic_constraints, "critical,CA:TRUE");
    }

  EVP_PKEY *signing_pkey = EVP_PKEY_new();
  if (signing_key.key_type() == Enc_method_rsa_1024_private
      || signing_key.key_type() == Enc_method_rsa_2048_private
      || signing_key.key_type() == Enc_method_rsa_3072_private
      || signing_key.key_type() == Enc_method_rsa_4096_private) {
    RSA *signing_rsa_key = RSA_new();
    if (!key_to_RSA(signing_key, signing_rsa_key)) {
      printf("produce_artifact: can't get rsa signing key\n");
      return false;
    }
    EVP_PKEY_set1_RSA(signing_pkey, signing_rsa_key);
    X509_set_pubkey(x509, signing_pkey);

    EVP_PKEY *subject_pkey = EVP_PKEY_new();
    if (subject_key.key_type() == Enc_method_rsa_1024_public
        || subject_key.key_type() == Enc_method_rsa_2048_public
        || subject_key.key_type() == Enc_method_rsa_4096_public
        || subject_key.key_type() == Enc_method_rsa_3072_public
        || subject_key.key_type() == Enc_method_rsa_1024_private
        || subject_key.key_type() == Enc_method_rsa_2048_private
        || subject_key.key_type() == Enc_method_rsa_3072_private
        || subject_key.key_type() == Enc_method_rsa_4096_private) {
      RSA *subject_rsa_key = RSA_new();
      if (!key_to_RSA(subject_key, subject_rsa_key)) {
        printf("%s() error, line: %d, produce_artifact: can't get rsa subject "
               "key\n", __func__, __LINE__);
        return false;
      }
      EVP_PKEY_set1_RSA(subject_pkey, subject_rsa_key);
      X509_set_pubkey(x509, subject_pkey);
      RSA_free(subject_rsa_key);
    } else if (subject_key.key_type() == Enc_method_ecc_384_public
               || subject_key.key_type() == Enc_method_ecc_384_private
               || subject_key.key_type() == Enc_method_ecc_256_public
               || subject_key.key_type() == Enc_method_ecc_256_private) {
      EC_KEY *subject_ecc_key = key_to_ECC(subject_key);
      if (subject_ecc_key == nullptr) {
        printf(
            "%s() error, line: %d, produce_artifact: can't get subject key\n",
            __func__, __LINE__);
        return false;
      }
      EVP_PKEY_set1_EC_KEY(subject_pkey, subject_ecc_key);
      X509_set_pubkey(x509, subject_pkey);
      EC_KEY_free(subject_ecc_key);
    } else {
      printf("%s() error, line: %d, produce_artifact: unknown public key type "
             "%s\n", __func__, __LINE__,
             subject_key.key_type().c_str());
      return false;
    }
    if (signing_key.key_type() == Enc_method_rsa_4096_private
        || signing_key.key_type() == Enc_method_ecc_384_private) {
      X509_sign(x509, signing_pkey, EVP_sha384());
    } else {
      X509_sign(x509, signing_pkey, EVP_sha256());
    }
    EVP_PKEY_free(signing_pkey);
    EVP_PKEY_free(subject_pkey);
    RSA_free(signing_rsa_key);
  } else if (signing_key.key_type() == Enc_method_ecc_384_private
             || signing_key.key_type() == Enc_method_ecc_256_private) {
    EC_KEY *signing_ecc_key = key_to_ECC(signing_key);
    if (signing_ecc_key == nullptr) {
      printf("%s() error, line: %d, produce_artifact: can't get signing key\n",
             __func__, __LINE__);
      return false;
    }
    EVP_PKEY *signing_pkey = EVP_PKEY_new();
    EVP_PKEY_set1_EC_KEY(signing_pkey, signing_ecc_key);
    X509_set_pubkey(x509, signing_pkey);

    EVP_PKEY *subject_pkey = EVP_PKEY_new();
    if (subject_key.key_type() == Enc_method_rsa_1024_public
        || subject_key.key_type() == Enc_method_rsa_2048_public
        || subject_key.key_type() == Enc_method_rsa_3072_public
        || subject_key.key_type() == Enc_method_rsa_4096_public
        || subject_key.key_type() == Enc_method_rsa_1024_private
        || subject_key.key_type() == Enc_method_rsa_2048_private
        || subject_key.key_type() == Enc_method_rsa_3072_private
        || subject_key.key_type() == Enc_method_rsa_4096_private) {
      RSA *subject_rsa_key = RSA_new();
      if (!key_to_RSA(subject_key, subject_rsa_key)) {
        printf("%s() error, line: %d, produce_artifact: can't get rsa subject "
               "key\n", __func__, __LINE__);
        return false;
      }
      EVP_PKEY_set1_RSA(subject_pkey, subject_rsa_key);
      X509_set_pubkey(x509, subject_pkey);
      RSA_free(subject_rsa_key);
    } else if (subject_key.key_type() == Enc_method_ecc_384_public
               || subject_key.key_type() == Enc_method_ecc_384_private
               || subject_key.key_type() == Enc_method_ecc_256_public
               || subject_key.key_type() == Enc_method_ecc_256_private) {
      EC_KEY *subject_ecc_key = key_to_ECC(subject_key);
      if (subject_ecc_key == nullptr) {
        printf(
            "%s() error, line: %d, produce_artifact: can't get subject key\n",
            __func__, __LINE__);
        return false;
      }
      EVP_PKEY_set1_EC_KEY(subject_pkey, subject_ecc_key);
      X509_set_pubkey(x509, subject_pkey);
      EC_KEY_free(subject_ecc_key);
    } else {
      printf("%s() error, line: %d, produce_artifact: unknown public key type "
             "%s\n", __func__, __LINE__,
             subject_key.key_type().c_str());
      return false;
    }
    X509_sign(x509, signing_pkey, EVP_sha384());
    EVP_PKEY_free(signing_pkey);
    EVP_PKEY_free(subject_pkey);
  } else {
    printf("%s() error, line: %d, produce_artifact: Unsupported algorithm\n",
           __func__, __LINE__);
    return false;
  }

  ASN1_INTEGER_free(a);
  ASN1_TIME_free(tm_start);
  ASN1_TIME_free(tm_end);
  X509_NAME_free(subject_name);
  X509_NAME_free(issuer_name);
  return true;
}

bool same_cert(X509* c1, X509* c2) {
  bool ret = true;

  key_message k1;
  key_message k2;

  string issuer_name_1_str;
  string issuer_name_2_str;
  string issuer_organization_1_str;
  string issuer_organization_2_str;
  X509_NAME *issuer_name_1 = nullptr;
  X509_NAME *issuer_name_2 = nullptr;

  string subject_name_1_str;
  string subject_name_2_str;
  string subject_organization_1_str;
  string subject_organization_2_str;
  X509_NAME *subject_name_1 = nullptr;
  X509_NAME *subject_name_2 = nullptr;

  int max_buf = 512;
  char name_buf[max_buf];

  memset(name_buf, 0, max_buf);
  issuer_name_1 = X509_get_issuer_name(c1);
  if (issuer_name_1 == nullptr) {
    ret = false;
    goto done;
  }
  if (X509_NAME_get_text_by_NID(issuer_name_1, NID_commonName, name_buf, max_buf) < 0) {
    ret = false;
    goto done;
  }
  issuer_name_1_str.assign(name_buf);
  if (X509_NAME_get_text_by_NID(issuer_name_1, NID_organizationName, name_buf, max_buf) < 0) {
    ret = false;
    goto done;
  }
  issuer_organization_1_str.assign(name_buf);

  issuer_name_2 = X509_get_issuer_name(c2);
  if (issuer_name_2 == nullptr) {
    ret = false;
    goto done;
  }
  if (X509_NAME_get_text_by_NID(issuer_name_2, NID_commonName, name_buf, max_buf) < 0) {
    ret = false;
    goto done;
  }

  issuer_name_2_str.assign(name_buf);
  if (X509_NAME_get_text_by_NID(issuer_name_2, NID_organizationName, name_buf, max_buf) < 0) {
    ret = false;
    goto done;
  }
  issuer_organization_2_str.assign(name_buf);

  if (issuer_name_1_str != issuer_name_2_str) {
    ret = false;
    goto done;
  }

  subject_name_1 = X509_get_subject_name(c1);
  if (subject_name_1 == nullptr) {
    ret = false;
    goto done;
  }
  if (X509_NAME_get_text_by_NID(subject_name_1, NID_commonName, name_buf, max_buf) < 0) {
    ret = false;
    goto done;
  }
  subject_name_1_str.assign(name_buf);
  if (X509_NAME_get_text_by_NID(subject_name_1, NID_organizationName, name_buf, max_buf) < 0) {
    ret = false;
    goto done;
  }
  subject_organization_1_str.assign(name_buf);

  subject_name_2 = X509_get_subject_name(c2);
  if (subject_name_2 == nullptr) {
    ret = false;
    goto done;
  }
  if (X509_NAME_get_text_by_NID(subject_name_2, NID_commonName, name_buf, max_buf) < 0) {
    ret = false;
    goto done;
  }
  subject_name_2_str.assign(name_buf);
  if (X509_NAME_get_text_by_NID(subject_name_2, NID_organizationName, name_buf, max_buf) < 0) {
    ret = false;
    goto done;
  }
  subject_organization_2_str.assign(name_buf);

  if (subject_name_1_str != subject_name_2_str) {
    ret = false;
    goto done;
  }
  if (subject_organization_1_str != subject_organization_2_str) {
    ret = false;
    goto done;
  }

  // same_keys?
  if (!x509_to_public_key(c1, &k1)) {
    ret = false;
    goto done;
  }
  if (!x509_to_public_key(c2, &k2)) {
    ret = false;
    goto done;
  }
  if (!same_key(k1, k2)) {
    ret = false;
    goto done;
  }

done:
  // issuer_name_1, issuer_name_2, subject_name_1, subject_name_2
  //   should not be freed.
  return ret;
}

// note: no revocation check
bool verify_cert_chain(X509* root_cert, buffer_list& certs) {

  bool ret = true;
  string asn_cert;

  string issuer_name_str;
  string subject_name_str;
  string issuer_description_str;
  string subject_organization_str;
  key_message sk;
  key_message root_verify_key;

  X509* last_cert= nullptr;
  key_message* last_key = nullptr;
  X509* current_cert = nullptr;
  key_message* current_key = nullptr;

  string last_issuer_name;
  string current_issuer_name_str;
  string current_issuer_organization_str;
  string current_subject_name_str;
  string current_subject_organization_str;
  uint64_t current_sn;
  uint64_t sn;

  if (certs.blobs_size() < 1) {
    printf("%s() error, line %d: there are no cert blobs\n", __func__, __LINE__);
    ret = false;
    goto done;
  }

  if (!x509_to_public_key(root_cert, &root_verify_key)) {
    printf("%s() error, line %d: x509_to_public_key failed\n", __func__, __LINE__);
    ret = false;
    goto done;
  }

  last_key = new(key_message);
  if (!verify_artifact(*root_cert, root_verify_key, &issuer_name_str, 
                     &issuer_description_str, last_key,
                     &subject_name_str, &subject_organization_str, &sn)) {
    printf("%s() error, line %d: verify_artifact failed\n", __func__, __LINE__);
    ret = false;
    goto done;
  }

  // first cert should be root cert
  asn_cert.assign((char*)certs.blobs(0).data(), certs.blobs(0).size());
  current_cert = X509_new();
  if (current_cert == nullptr) {
    printf("%s() error, line %d: can't allocate current cert\n", __func__, __LINE__);
    ret = false;
    goto done;
  }
  if (!asn1_to_x509(asn_cert, current_cert)) {
    printf("%s() error, line %d: asn1_to_x509 failed\n", __func__, __LINE__);
    ret = false;
    goto done;
  }
  if (!same_cert(root_cert, current_cert)) {
    ret = false;
    goto done;
  }

  last_cert = current_cert;  // now points to root cert
  current_cert = nullptr;

  for (int i = 1; i < certs.blobs_size(); i++) {
    current_cert = X509_new();
    if (current_cert == nullptr) {
      ret = false;
      goto done;
    }
    asn_cert.assign((char*)certs.blobs(i).data(), certs.blobs(i).size());
    if (!asn1_to_x509(asn_cert, current_cert)) {
      printf("%s() error, line %d: asn1_to_cert failed\n", __func__, __LINE__);
      ret = false;
      goto done;
    }
    current_key = new(key_message);
    bool res = verify_artifact(*current_cert, *last_key, &current_issuer_name_str,
                      &current_issuer_organization_str, current_key,
                      &current_subject_name_str, &current_subject_organization_str,
                      &current_sn);
    if (!res) {
      printf("%s() error, line %d: %d cert verify failed\n", __func__, __LINE__, i);
      ret = false;
      goto done;
    }
    current_key = nullptr;

    if (last_cert != nullptr) {
      X509_free(last_cert);
      last_cert= nullptr;
    }
    if (last_key != nullptr) {
      delete last_key;
      last_key = nullptr;
    }

    last_cert= current_cert;
    last_key = current_key;
    current_cert = nullptr;
    current_key = nullptr;
  }

done:
  if (last_cert != nullptr) {
    X509_free(last_cert);
    last_cert = nullptr;
  }
  if(current_cert != nullptr) {
    X509_free(current_cert);
    current_cert = nullptr;
  }
  if (last_key != nullptr) {
    delete last_key;
    last_key = nullptr;
  }
  if(current_key != nullptr) {
    delete current_key;
    current_key = nullptr;
  }
  return ret;
}

bool verify_artifact(X509& cert, key_message &verify_key, string* issuer_name_str,
                     string* issuer_description_str, key_message* subject_key,
                     string* subject_name_str, string* subject_organization_str,
                     uint64_t *sn) {

  bool success = false;
  if (verify_key.key_type() == Enc_method_rsa_1024_public
      || verify_key.key_type() == Enc_method_rsa_1024_private
      || verify_key.key_type() == Enc_method_rsa_2048_public
      || verify_key.key_type() == Enc_method_rsa_2048_private
      || verify_key.key_type() == Enc_method_rsa_3072_public
      || verify_key.key_type() == Enc_method_rsa_3072_private
      || verify_key.key_type() == Enc_method_rsa_4096_public
      || verify_key.key_type() == Enc_method_rsa_4096_private) {
    EVP_PKEY *verify_pkey = EVP_PKEY_new();
    RSA *     verify_rsa_key = RSA_new();
    if (!key_to_RSA(verify_key, verify_rsa_key))
      return false;
    EVP_PKEY_set1_RSA(verify_pkey, verify_rsa_key);

    EVP_PKEY *subject_pkey = X509_get_pubkey(&cert);
    RSA* subject_rsa_key = EVP_PKEY_get1_RSA(subject_pkey);
    if (!RSA_to_key(subject_rsa_key, subject_key)) {
      return false;
    }
    success = (X509_verify(&cert, verify_pkey) == 1);
    RSA_free(verify_rsa_key);
    RSA_free(subject_rsa_key);
    EVP_PKEY_free(verify_pkey);
    EVP_PKEY_free(subject_pkey);
    // Todo: Make this work
  } else if (verify_key.key_type() == Enc_method_ecc_384_public
             || verify_key.key_type() == Enc_method_ecc_384_private
             || verify_key.key_type() == Enc_method_ecc_256_public
             || verify_key.key_type() == Enc_method_ecc_256_private) {
    EVP_PKEY* verify_pkey = EVP_PKEY_new();
    EC_KEY*  verify_ecc_key = key_to_ECC(verify_key);
    if (verify_ecc_key == nullptr) {
      return false;
    }
    EVP_PKEY_set1_EC_KEY(verify_pkey, verify_ecc_key);

    EVP_PKEY* subject_pkey = X509_get_pubkey(&cert);
    EC_KEY* subject_ecc_key = EVP_PKEY_get1_EC_KEY(subject_pkey);
    if (!ECC_to_key(subject_ecc_key, subject_key)) {
      return false;
    }
    success = (X509_verify(&cert, verify_pkey) == 1);
    EC_KEY_free(verify_ecc_key);
    EC_KEY_free(subject_ecc_key);
    EVP_PKEY_free(verify_pkey);
    EVP_PKEY_free(subject_pkey);
  } else {
    printf("%s() error, line: %d, Unsupported key type\n", __func__, __LINE__);
    return false;
  }

  // Todo: report other cert values
  X509_NAME* subject_name = X509_get_subject_name(&cert);
  const int  max_buf = 2048;
  char name_buf[max_buf];
  if (X509_NAME_get_text_by_NID(subject_name, NID_commonName, name_buf, max_buf)
      < 0)
    success = false;
  else {
    subject_name_str->assign((const char *)name_buf);
  }

  return success;
}

bool asn1_to_x509(const string& in, X509* x) {
  int len = in.size();

  byte* p = (byte *)in.data();
  d2i_X509(&x, (const byte **)&p, len);
  if (x == nullptr) {
    printf("%s() error, line: %d, no x509 pointer\n", __func__, __LINE__);
    return false;
  }
  return true;
}

bool x509_to_asn1(X509* x, string *out) {
  int len = i2d_X509(x, nullptr);
  byte buf[len];
  byte* p = buf;

  i2d_X509(x, (byte **)&p);
  out->assign((char *)buf, len);
  return true;
}

// -----------------------------------------------------------------------

//  Blocking read of pipe, socket, SSL connection with
//  size prefix

// little endian only
const int max_pipe_size = 65536;
int  sized_pipe_write(int fd, int size, byte *buf) {
  if (size > max_pipe_size)
    return -1;
  if (write(fd, (byte *)&size, sizeof(int)) < (int)sizeof(int))
    return -1;
  if (write(fd, buf, size) < size)
    return -1;
  return size;
}

// little endian only
int sized_pipe_read(int fd, string *out) {
  int size = 0;
  if (read(fd, (byte *)&size, sizeof(int)) < (int)sizeof(int)) {
    printf("sized_pipe_read: bad read size \n");
    return -1;
  }
  if (size > max_pipe_size) {
    printf("%s() error, line: %d, sized_pipe_read: larger than pipe buffer\n",
           __func__, __LINE__);
    return -1;
  }

  byte buf[size];
  int  cur_size = 0;
  int  n = 0;
  while (cur_size < size) {
    n = read(fd, &buf[cur_size], size - cur_size);
    if (n < 0) {
      printf("%s() error, line: %d, sized_pipe_read: read failed\n",
             __func__, __LINE__);
      return -1;
    }
    cur_size += n;
  }

  out->clear();
  out->assign((char *)buf, size);
  return n;
}

// little endian only
int sized_ssl_write(SSL *ssl, int size, byte *buf) {
  if (SSL_write(ssl, (byte *)&size, sizeof(int)) < (int)sizeof(int))
    return -1;
  if (SSL_write(ssl, buf, size) < size)
    return -1;
  return size;
}

// little endian only
int sized_ssl_read(SSL *ssl, string *out) {
  out->clear();
  int size = 0;
  int n = SSL_read(ssl, (byte *)&size, sizeof(int));
  if (n < 0)
    return n;

  int total = 0;
  const int read_stride = 8192;
  byte buf[read_stride];

  while (total < size) {
    if ((size - total) > read_stride)
      n = SSL_read(ssl, buf, read_stride);
    else
      n = SSL_read(ssl, buf, size - total);
    if (n < 0) {
      return n;
    } else {
      out->append((char *)buf, n);
      total += n;
    }
  }
  return total;
}

// little endian only
int sized_socket_read(int fd, string *out) {
  out->clear();
  int n = 0;
  int size = 0;
  int total = 0;
  const int read_stride = 8192;
  byte buf[read_stride];

  if (read(fd, (byte *)&size, sizeof(int)) < (int)sizeof(int))
    return -1;

  while (total < size) {
    if ((size - total) > read_stride)
      n = read(fd, buf, read_stride);
    else
      n = read(fd, buf, size - total);
    if (n <= 0) {
      return -1;
    } else {
      out->append((char *)buf, n);
      total += n;
    }
  }
  return total;
}

// little endian only
int sized_socket_write(int fd, int size, byte *buf) {
  if (write(fd, (byte *)&size, sizeof(int)) < (int)sizeof(int))
    return -1;
  if (write(fd, buf, size) < size)
    return -1;
  return size;
}

// -----------------------------------------------------------------------

bool key_from_pkey(EVP_PKEY *pkey, const string &name, key_message *k) {

  if (pkey == nullptr)
    return false;
  if (EVP_PKEY_base_id(pkey) == EVP_PKEY_RSA) {
    int  size = EVP_PKEY_bits(pkey);
    RSA *rsa_key = EVP_PKEY_get1_RSA(pkey);
    if (!RSA_to_key(rsa_key, k)) {
      printf("%s() error, line: %d, key_from_pkey: RSA_to_key failed\n",
             __func__, __LINE__);
      return false;
    }
    switch (size) {
      case 1024:
        k->set_key_type(Enc_method_rsa_1024_public);
        break;
      case 2048:
        k->set_key_type(Enc_method_rsa_2048_public);
        break;
      case 3072:
        k->set_key_type(Enc_method_rsa_3072_public);
        break;
      case 4096:
        k->set_key_type(Enc_method_rsa_4096_public);
        break;
      default:
        return false;
    }
  } else if (EVP_PKEY_base_id(pkey) == EVP_PKEY_EC) {
    int size = EVP_PKEY_bits(pkey);
    EC_KEY* ecc_key = EVP_PKEY_get1_EC_KEY(pkey);
    if (!ECC_to_key(ecc_key, k)) {
      printf("%s() error, line: %d, key_from_pkey: ECC_to_key failed\n",
             __func__, __LINE__);
      return false;
    }
    if (size == 384) {
      k->set_key_type(Enc_method_ecc_384_public);
    } else if (size == 256) {
      k->set_key_type(Enc_method_ecc_256_public);
    } else {
      return false;
    }
  } else {
    printf("%s() error, line: %d, key_from_pkey: unsupported key type\n",
           __func__, __LINE__);
    return false;
  }

  k->set_key_name(name);
  return true;
}

cert_keys_seen_list::cert_keys_seen_list(int max_size) {
  max_size_ = max_size;
  entries_ = new cert_keys_seen *[max_size];
  size_ = 0;
}

cert_keys_seen_list::~cert_keys_seen_list() {
  for (int i = 0; i < size_; i++) {
    delete entries_[i];
  }
  delete[] entries_;
}

key_message *cert_keys_seen_list::find_key_seen(const string &name) {
  for (int i = 0; i < size_; i++) {
    if (entries_[i]->issuer_name_ == name)
      return entries_[i]->k_;
  }
  return nullptr;
}

bool cert_keys_seen_list::add_key_seen(key_message *k) {
  if (size_ >= (max_size_ - 1))
    return false;
  entries_[size_] = new cert_keys_seen;
  entries_[size_]->issuer_name_.assign(k->key_name());
  entries_[size_]->k_ = k;
  size_++;
  return true;
}

key_message *get_issuer_key(X509 *x, cert_keys_seen_list &list) {
  string str_issuer_name;

  const int  max_buf = 2048;
  char       name_buf[max_buf];
  X509_NAME *issuer_name = X509_get_issuer_name(x);
  if (X509_NAME_get_text_by_NID(issuer_name, NID_commonName, name_buf, max_buf)
      < 0) {
    printf("%s() error, line: %d, get_issuer_key: Can't get name from NID\n",
           __func__, __LINE__);
    return nullptr;
  }
  str_issuer_name.assign((const char *)name_buf);
  // X509_NAME_free(issuer_name);
  return list.find_key_seen(str_issuer_name);
}

EVP_PKEY* pkey_from_key(const key_message& k) {
  EVP_PKEY* pkey = EVP_PKEY_new();

  if (k.key_type() == Enc_method_rsa_1024_public
      || k.key_type() == Enc_method_rsa_1024_private
      || k.key_type() == Enc_method_rsa_3072_public
      || k.key_type() == Enc_method_rsa_3072_private
      || k.key_type() == Enc_method_rsa_2048_public
      || k.key_type() == Enc_method_rsa_2048_private
      || k.key_type() == Enc_method_rsa_4096_public
      || k.key_type() == Enc_method_rsa_4096_private) {
    RSA *rsa_key = RSA_new();
    if (!key_to_RSA(k, rsa_key)) {
      printf("%s() error, line: %d, pkey_from_key: Can't translate key to RSA "
             "key\n", __func__, __LINE__);
      EVP_PKEY_free(pkey);
      return nullptr;
    }
    if (1 != EVP_PKEY_assign_RSA(pkey, rsa_key)) {
      printf("%s() error, line: %d, pkey_from_key: Can't set RSA key\n",
             __func__, __LINE__);
      EVP_PKEY_free(pkey);
      return nullptr;
    }
    return pkey;
  } else if (k.key_type() == Enc_method_ecc_384_public
             || k.key_type() == Enc_method_ecc_384_private
             || k.key_type() == Enc_method_ecc_256_public
             || k.key_type() == Enc_method_ecc_256_private) {
    EC_KEY *ecc_key = key_to_ECC(k);
    if (ecc_key == nullptr) {
      EVP_PKEY_free(pkey);
      return nullptr;
    }
    EVP_PKEY_assign_EC_KEY(pkey, ecc_key);
    return pkey;
  } else {
    printf("%s() error, line: %d, pkey_from_key: Unsupported key type\n",
           __func__, __LINE__);
    EVP_PKEY_free(pkey);
    return nullptr;
  }
}

// make a public key from the X509 cert's subject key
bool x509_to_public_key(X509* x, key_message* k) {
  EVP_PKEY *subject_pkey = X509_get_pubkey(x);
  if (subject_pkey == nullptr) {
    printf("x509_to_public_key: subject_pkey is null\n");
    return false;
  }

  if (EVP_PKEY_base_id(subject_pkey) == EVP_PKEY_RSA) {
    int  size = EVP_PKEY_bits(subject_pkey);
    RSA *subject_rsa_key = EVP_PKEY_get1_RSA(subject_pkey);
    if (!RSA_to_key(subject_rsa_key, k)) {
      printf("%s() error, line: %d, x509_to_public_key: RSA_to_key failed\n",
             __func__, __LINE__);
      return false;
    }
    switch (size) {
      case 1024:
        k->set_key_type(Enc_method_rsa_1024_public);
        break;
      case 2048:
        k->set_key_type(Enc_method_rsa_2048_public);
        break;
      case 3072:
        k->set_key_type(Enc_method_rsa_3072_public);
        break;
      case 4096:
        k->set_key_type(Enc_method_rsa_4096_public);
        break;
      default:
        printf("%s() error, line: %d, x509_to_public_key: bad key type\n",
               __func__, __LINE__);
        return false;
    }
    // free subject_rsa_key?
  } else if (EVP_PKEY_base_id(subject_pkey) == EVP_PKEY_EC) {
    int     size = EVP_PKEY_bits(subject_pkey);
    EC_KEY *subject_ecc_key = EVP_PKEY_get1_EC_KEY(subject_pkey);
    if (!ECC_to_key(subject_ecc_key, k)) {
      return false;
    }
    if (size == 384) {
      k->set_key_type(Enc_method_ecc_384_public);
    } else if (size == 256) {
      k->set_key_type(Enc_method_ecc_256_public);
    } else {
      return false;
    }
    // Todo: free subject_ecc_key?
  } else {
    printf("%s() error, line: %d, x509_to_public_key: bad pkey type\n",
           __func__, __LINE__);
    return false;
  }

  X509_NAME *subject_name = X509_get_subject_name(x);
  const int  max_buf = 2048;
  char name_buf[max_buf];
   memset(name_buf, 0, max_buf);
  if (X509_NAME_get_text_by_NID(subject_name, NID_commonName, name_buf, max_buf)
      < 0) {
    printf("%s() error, line: %d, x509_to_public_key: can't get subject_name\n",
           __func__, __LINE__);
    return false;
  }
  k->set_key_name((const char *)name_buf);
  EVP_PKEY_free(subject_pkey);
  return true;
}

bool make_root_key_with_cert(string& type, string& name, string& issuer_name,
                                           key_message *k) {
  string root_name("root");

  if (type == Enc_method_rsa_4096_private || type == Enc_method_rsa_2048_private
      || type == Enc_method_rsa_3072_private
      || type == Enc_method_rsa_1024_private) {
    int n = 2048;
    if (type == Enc_method_rsa_2048_private)
      n = 2048;
    else if (type == Enc_method_rsa_1024_private)
      n = 1024;
    else if (type == Enc_method_rsa_3072_private)
      n = 3072;
    else if (type == Enc_method_rsa_4096_private)
      n = 4096;

    if (!make_certifier_rsa_key(n, k))
      return false;
    k->set_key_type(type);
    k->set_key_name(name);
    double duration = 5.0 * 86400.0 * 365.0;
    X509 * cert = X509_new();
    if (cert == nullptr)
      return false;
    if (!produce_artifact(*k, issuer_name, root_name, *k, issuer_name,
                          root_name, 01L, duration, cert, true)) {
      return false;
    }
    string cert_asn;
    if (!x509_to_asn1(cert, &cert_asn))
      return false;
    k->set_certificate((byte *)cert_asn.data(), cert_asn.size());
    X509_free(cert);
  } else if (type == Enc_method_ecc_384_private) {
    if (!make_certifier_ecc_key(384, k))
      return false;
    k->set_key_type(type);
    k->set_key_name(name);
    double duration = 5.0 * 86400.0 * 365.0;
    X509 * cert = X509_new();
    if (cert == nullptr)
      return false;
    if (!produce_artifact(*k, issuer_name, root_name, *k, issuer_name,
                          root_name, 01L, duration, cert, true)) {
      return false;
    }
    string cert_asn;
    if (!x509_to_asn1(cert, &cert_asn))
      return false;
    k->set_certificate((byte *)cert_asn.data(), cert_asn.size());
    X509_free(cert);
  } else if (type == Enc_method_ecc_256_private) {
    if (!make_certifier_ecc_key(256, k))
      return false;
    k->set_key_type(type);
    k->set_key_name(name);
    double duration = 5.0 * 86400.0 * 365.0;
    X509 * cert = X509_new();
    if (cert == nullptr)
      return false;
    if (!produce_artifact(*k, issuer_name, root_name, *k, issuer_name,
                          root_name, 01L, duration, cert, true)) {
      return false;
    }
    string cert_asn;
    if (!x509_to_asn1(cert, &cert_asn))
      return false;
    k->set_certificate((byte *)cert_asn.data(), cert_asn.size());
    X509_free(cert);
  } else {
    return false;
  }
  return true;
}

// may want to check leading 0's
bool same_point(const point_message &pt1, const point_message &pt2) {
  if (pt1.x().size() != pt2.x().size()) {
    return false;
  } 
  if (pt1.y().size() != pt2.y().size()) {
    return false;
  } 
  if (memcmp(pt1.x().data(), pt1.x().data(), pt1.x().size()) != 0) {
    return false;
  }     
  if (memcmp(pt1.y().data(), pt1.y().data(), pt1.y().size()) != 0) {
    return false; 
  }            
  return true;
}   

bool same_key(const key_message &k1, const key_message &k2) {
  if (k1.key_type() != k2.key_type()) {
    return false;
  }

  if (k1.key_type() == Enc_method_rsa_2048_private || k1.key_type() == Enc_method_rsa_2048_public
      || k1.key_type() == Enc_method_rsa_1024_private || k1.key_type() == Enc_method_rsa_1024_public
      || k1.key_type() == Enc_method_rsa_3072_private || k1.key_type() == Enc_method_rsa_3072_public
      || k1.key_type() == Enc_method_rsa_4096_private || k1.key_type() == Enc_method_rsa_4096_public) {
    string b1, b2;
    if (!k1.has_rsa_key() || !k2.has_rsa_key()) {
      return false;
    }
    if (k1.rsa_key().public_modulus() != k2.rsa_key().public_modulus()) {
      return false;
    } 
    if (k1.rsa_key().public_exponent() != k2.rsa_key().public_exponent()) {
      return false;
    }         
    return true;
  } else if (k1.key_type() == Enc_method_aes_256_cbc_hmac_sha256
             || k1.key_type() == Enc_method_aes_256_cbc
             || k1.key_type() == Enc_method_aes_256) {
    if (!k1.has_secret_key_bits()) {
      printf("%s() error, line: %d, no secret key bits\n", __func__, __LINE__);
      return false;
    }
    if (k1.secret_key_bits().size() != k2.secret_key_bits().size()) {
      printf("%s() error, line: %d, number of key bits don't match\n",
             __func__,
             __LINE__);
      return false;
    }
    return (memcmp(k1.secret_key_bits().data(),
                   k2.secret_key_bits().data(),
                   k1.secret_key_bits().size())
            == 0);
  } else if (k1.key_type() == Enc_method_ecc_384_public
             || k1.key_type() == Enc_method_ecc_384_private) {
    const ecc_message &em1 = k1.ecc_key();
    const ecc_message &em2 = k2.ecc_key();
    if (em1.curve_p().size() != em2.curve_p().size()
        || memcmp(em1.curve_p().data(),
                  em2.curve_p().data(),
                  em1.curve_p().size())
               != 0) {
      return false;

    }
    if (em1.curve_a().size() != em2.curve_a().size()
        || memcmp(em1.curve_a().data(),
                  em1.curve_a().data(),
                  em2.curve_a().size())
               != 0) {
      return false;
    }
    if (em1.curve_b().size() != em2.curve_b().size()
        || memcmp(em1.curve_b().data(),
                  em1.curve_b().data(),
                  em2.curve_b().size())
               != 0) {
      return false;
    }
    if (!same_point(em1.base_point(), em2.base_point())) {
      return false;
    }
    if (!same_point(em1.public_point(), em2.public_point())) {
      return false;
    }
    return true;
  } else if (k1.key_type() == Enc_method_ecc_256_public
             || k1.key_type() == Enc_method_ecc_256_private) {
    const ecc_message &em1 = k1.ecc_key();
    const ecc_message &em2 = k2.ecc_key();
    if (em1.curve_p().size() != em2.curve_p().size()
        || memcmp(em1.curve_p().data(),
                  em2.curve_p().data(),
                  em1.curve_p().size())
               != 0) {
      return false;
    }
    if (em1.curve_a().size() != em2.curve_a().size()
        || memcmp(em1.curve_a().data(),
                  em1.curve_a().data(),
                  em2.curve_a().size())
               != 0) {
      return false;
    }
    if (em1.curve_b().size() != em2.curve_b().size()
        || memcmp(em1.curve_b().data(),
                  em1.curve_b().data(),
                  em2.curve_b().size())
               != 0) {
      return false;
    }
    if (!same_point(em1.base_point(), em2.base_point())) {
      return false;
    }
    if (!same_point(em1.base_point(), em2.base_point())) {
      return false;
    }
    if (!same_point(em1.public_point(), em2.public_point())) {
      return false;
    }
    return true;
  } else {
    printf("%s() error, line: %d, baad ecc type\n", __func__, __LINE__);
    return false;
  }
  return true;
}

// -----------------------------------------------------------------------
