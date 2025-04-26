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

#include "certifier.h"
#include "support.h"
#include "acl_support.h"
#include "certifier.pb.h"
#include "acl.pb.h"

using namespace certifier::framework;
using namespace certifier::utilities;

namespace certifier {
namespace acl_lib {

void init_time_point(time_point *tp) {
  tp->set_year(0);
  tp->set_month(0);
  tp->set_day(0);
  tp->set_hour(0);
  tp->set_minute(0);
  tp->set_seconds(0.0);
}

bool time_now(time_point *tp) {
  time_t    now;
  struct tm current_time;

  time(&now);
  gmtime_r(&now, &current_time);
  if (!unix_tm_to_time_point(&current_time, tp))
    return false;
  return true;
}

bool add_interval_to_time(time_point &from,
                          double      seconds_later,
                          time_point *to) {

  // This doesn't do leap years, seconds, month or other stuff... correctly
  to->set_year(from.year());
  to->set_month(from.month());
  to->set_day(from.day());
  to->set_hour(from.hour());
  to->set_minute(from.minute());
  to->set_seconds(from.seconds());

  int days = seconds_later / (double)seconds_in_day;
  seconds_later -= (double)(days * seconds_in_day);
  int yrs = days / 365;
  days -= yrs * 365;
  to->set_year(yrs + to->year());
  int months = days / 30;  // not right;
  days -= months * 30;
  to->set_month(months + to->month());
  to->set_day(days + to->day());
  int mins = (int)seconds_later / 60.0;
  seconds_later -= (double)(mins * 60);
  int hrs = (int)mins / 60.0;
  mins -= hrs * 60;
  to->set_hour(hrs + to->hour());
  to->set_minute(mins + to->minute());
  to->set_seconds(seconds_later + to->seconds());
  // now fix overflows
  if (to->seconds() >= 60.0) {
    to->set_seconds(to->seconds() - 60.0);
    to->set_minute(1 + to->minute());
  }
  if (to->minute() >= 60) {
    to->set_minute(to->minute() - 60);
    to->set_hour(1 + to->hour());
  }
  if (to->hour() >= 24) {
    to->set_day(1 + to->day());
    to->set_hour(to->hour() - 24);
  }
  if (to->day() > 30) {
    to->set_month(1 + to->month());
    to->set_day(to->day() - 30);
  }
  if (to->month() > 12) {
    to->set_year(1 + to->year());
    to->set_month(to->month() - 12);
  }
  return true;
}

const char *s_months[] = {"January",
                          "February",
                          "March",
                          "April",
                          "May",
                          "June",
                          "July",
                          "August",
                          "September",
                          "October",
                          "November",
                          "December"};

void print_time(time_point &tp) {
  int m = tp.month() - 1;
  if (m < 0 || m > 11)
    return;
  printf("%d %s %d, %02d:%02d:%lfZ",
         tp.day(),
         s_months[m],
         tp.year(),
         tp.hour(),
         tp.minute(),
         tp.seconds());
}

bool encode_time(time_point &tp, string *the_time) {
  int m = tp.month() - 1;
  if (m < 0 || m > 11)
    return false;
  char time_str[256];
  *time_str = '\0';
  snprintf(time_str,
           255,
           "%d %s %d, %02d:%02d:%lfZ",
           tp.day(),
           s_months[m],
           tp.year(),
           tp.hour(),
           tp.minute(),
           tp.seconds());
  m = strlen(time_str);
  *the_time = time_str;
  return true;
}

const char *m_months[12] = {"January",
                            "February",
                            "March",
                            "April",
                            "May",
                            "June",
                            "July",
                            "August",
                            "September",
                            "October",
                            "November",
                            "December"};
int         month_from_name(char *mn) {
  for (int i = 0; i < 12; i++) {
    if (strcmp(mn, m_months[i]) == 0)
      return i;
  }
  return -1;
}

bool decode_time(string &encoded_time, time_point *tp) {
  int    dm, yr, hr, min;
  double sec;
  char   s[64];

  memset((certifier::acl_lib::byte *)s, 0, 64);
  sscanf(encoded_time.c_str(),
         "%d %s %d, %02d:%02d:%lfZ",
         &dm,
         s,
         &yr,
         &hr,
         &min,
         &sec);
  int mm = month_from_name(s);
  if (mm < 0) {
    printf("decode time failure: %s, %s, %d\n", encoded_time.c_str(), s, mm);
    return false;
  }
  mm++;
  tp->set_year(yr);
  tp->set_month(mm);
  tp->set_day(dm);
  tp->set_hour(hr);
  tp->set_minute(min);
  tp->set_seconds(sec);
  return true;
}

bool time_point_to_unix_tm(time_point *tp, struct tm *time_now) {
  return false;
}

bool unix_tm_to_time_point(struct tm *the_time, time_point *tp) {
  tp->set_year(the_time->tm_year + 1900);
  tp->set_month(the_time->tm_mon + 1);
  tp->set_day(the_time->tm_mday);
  tp->set_hour(the_time->tm_hour);
  tp->set_minute(the_time->tm_min);
  tp->set_seconds(the_time->tm_sec);
  return true;
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

static byte s_hex_values1[10] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
static byte s_hex_values2[6] = {10, 11, 12, 13, 14, 15};
byte        hex_value(char a) {
  if (a >= '0' && a <= '9')
    return s_hex_values1[a - '0'];
  if (a >= 'A' && a <= 'F')
    return s_hex_values2[a - 'A'];
  if (a >= 'a' && a <= 'f')
    return s_hex_values2[a - 'a'];
  return 0;
}

bool valid_hex(char *s) {
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

bool hex_to_bytes(string &h, string *b) {
  b->clear();
  if (!valid_hex((char *)h.c_str()))
    return false;
  int h_size = strlen(h.c_str());

  // if odd first 4 bits is 0
  byte b1, b2;
  int  k;
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

static char s_hex_chars[16] = {'0',
                               '1',
                               '2',
                               '3',
                               '4',
                               '5',
                               '6',
                               '7',
                               '8',
                               '9',
                               'a',
                               'b',
                               'c',
                               'd',
                               'e',
                               'f'};
char        hex_char(byte b) {
  if (b > 16)
    return '0';
  return s_hex_chars[b];
}

bool bytes_to_hex(string &b, string *h) {
  // always returns even number of hex characters
  h->clear();
  int  b_size = b.size();
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

static const char *web_safe_base64_characters =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
bool valid_base64(char *s) {
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

bool base64_to_bytes(string &b64, string *b) {
  if (!valid_base64((char *)b64.c_str()))
    return false;
  b->clear();
  int b64_size = strlen(b64.c_str());
  if (((int)b->capacity()) < ((b64_size / 4) * 3 + 1))
    return false;
  int  i;
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

bool bytes_to_base64(string &b, string *b64) {
  b64->clear();
  int  b_size = b.size();
  byte x1, x2, x3, z;
  char c;
  int  i;
  for (i = 0; i < (b_size - 3); i += 3) {
    x1 = b[i];
    z = x1 >> 2;
    c = base64_char(z);
    b64->append(1, c);
    x2 = b[i + 1];
    z = (x1 & 0x03) << 4 | x2 >> 4;
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
    z = x2 & 0x0f;
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
    z = (x2 & 0x0f) << 2 | x3 >> 6;
    c = base64_char(z);
    b64->append(1, c);
    z = x3 & 0x03f;
    c = base64_char(z);
    b64->append(1, c);
  }
  b64->append(1, '\0');
  return true;
}

void reverse_bytes(int size, byte *in, byte *out) {
  for (int i = 0; i < size; i++)
    out[size - 1 - i] = in[i];
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
#  define HAVE_RD_RAND
#endif
int random_source::get_random_bytes(int n, byte *b) {
  if (!initialized_)
    return -1;
#ifdef HAVE_RD_RAND
  int m = n;
  if (have_rd_rand_) {
    uint32_t out;

    while (m > 0) {
      asm volatile("\trdrand %%edx\n"
                   "\tmovl   %%edx, %[out]\n"
                   : [out] "=m"(out)::"%edx");
      memcpy(b, (byte *)&out, sizeof(uint32_t));
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

bool          global_crypto_initialized = false;
random_source global_crypto_random_source;

int crypto_get_random_bytes(int num_bytes, byte *buf) {
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

key_message *make_symmetric_key(string       &alg,
                                string       &name,
                                const string &not_before,
                                const string &not_after,
                                const string &key_bits) {
  key_message *km = new (key_message);

  km->set_key_name(name);
  km->set_key_type(alg);
  km->set_key_format("vse");
  km->set_secret_key_bits(key_bits);
  km->set_not_before(not_before);
  km->set_not_after(not_after);

  return km;
}

void print_binary_blob(const binary_blob_message &m) {
  printf("Binary blob: ");
  print_bytes((int)m.blob().size(), (byte *)m.blob().data());
}

void print_encrypted_message(const encrypted_message &m) {
  printf("Encrypted message:\n");
  if (m.has_encryption_identifier())
    printf("  Scheme id   : %s\n", m.encryption_identifier().c_str());
  if (m.has_message_identifier())
    printf("  Message id  : %s\n", m.message_identifier().c_str());
  if (m.has_source() && m.has_destination())
    printf("  Source      : %s, destination: %s\n",
           m.source().c_str(),
           m.destination().c_str());
  if (m.has_date())
    printf("  Date        : %s\n", m.date().c_str());
  if (m.has_buffer()) {
    printf("  Buffer      : ");
    print_bytes((int)m.buffer().size(), (byte *)m.buffer().data());
  }
}

void print_signature_message(const signature_message &m) {
  printf("Signature message\n");
  printf("    algorithm : %s\n", m.encryption_algorithm_name().c_str());
  printf("    key name  : %s\n", m.key_name().c_str());
  printf("    signature : ");
  print_bytes((int)m.signature().size(), (byte *)m.signature().data());
  printf("    signer    : %s\n", m.signer_name().c_str());
}

// -----------------------------------------------------------------------------

bool same_cert(X509 *c1, X509 *c2) {
  bool ret = true;

  key_message k1;
  key_message k2;

  string     issuer_name_1_str;
  string     issuer_name_2_str;
  string     issuer_organization_1_str;
  string     issuer_organization_2_str;
  X509_NAME *issuer_name_1 = nullptr;
  X509_NAME *issuer_name_2 = nullptr;

  string     subject_name_1_str;
  string     subject_name_2_str;
  string     subject_organization_1_str;
  string     subject_organization_2_str;
  X509_NAME *subject_name_1 = nullptr;
  X509_NAME *subject_name_2 = nullptr;

  int  max_buf = 512;
  char name_buf[max_buf];

  memset(name_buf, 0, max_buf);
  issuer_name_1 = X509_get_issuer_name(c1);
  if (issuer_name_1 == nullptr) {
    ret = false;
    goto done;
  }
  if (X509_NAME_get_text_by_NID(issuer_name_1,
                                NID_commonName,
                                name_buf,
                                max_buf)
      < 0) {
    ret = false;
    goto done;
  }
  issuer_name_1_str.assign(name_buf);
  if (X509_NAME_get_text_by_NID(issuer_name_1,
                                NID_organizationName,
                                name_buf,
                                max_buf)
      < 0) {
    ret = false;
    goto done;
  }
  issuer_organization_1_str.assign(name_buf);

  issuer_name_2 = X509_get_issuer_name(c2);
  if (issuer_name_2 == nullptr) {
    ret = false;
    goto done;
  }
  if (X509_NAME_get_text_by_NID(issuer_name_2,
                                NID_commonName,
                                name_buf,
                                max_buf)
      < 0) {
    ret = false;
    goto done;
  }

  issuer_name_2_str.assign(name_buf);
  if (X509_NAME_get_text_by_NID(issuer_name_2,
                                NID_organizationName,
                                name_buf,
                                max_buf)
      < 0) {
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
  if (X509_NAME_get_text_by_NID(subject_name_1,
                                NID_commonName,
                                name_buf,
                                max_buf)
      < 0) {
    ret = false;
    goto done;
  }
  subject_name_1_str.assign(name_buf);
  if (X509_NAME_get_text_by_NID(subject_name_1,
                                NID_organizationName,
                                name_buf,
                                max_buf)
      < 0) {
    ret = false;
    goto done;
  }
  subject_organization_1_str.assign(name_buf);

  subject_name_2 = X509_get_subject_name(c2);
  if (subject_name_2 == nullptr) {
    ret = false;
    goto done;
  }
  if (X509_NAME_get_text_by_NID(subject_name_2,
                                NID_commonName,
                                name_buf,
                                max_buf)
      < 0) {
    ret = false;
    goto done;
  }
  subject_name_2_str.assign(name_buf);
  if (X509_NAME_get_text_by_NID(subject_name_2,
                                NID_organizationName,
                                name_buf,
                                max_buf)
      < 0) {
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
bool verify_cert_chain(X509 *root_cert, buffer_list &certs) {

  bool   ret = true;
  string asn_cert;

  string      issuer_name_str;
  string      subject_name_str;
  string      issuer_description_str;
  string      subject_organization_str;
  key_message sk;
  key_message root_verify_key;

  X509        *last_cert = nullptr;
  key_message *last_key = nullptr;
  X509        *current_cert = nullptr;
  key_message *current_key = nullptr;

  string   last_issuer_name;
  string   current_issuer_name_str;
  string   current_issuer_organization_str;
  string   current_subject_name_str;
  string   current_subject_organization_str;
  uint64_t current_sn;
  uint64_t sn;

  if (certs.blobs_size() < 1) {
    printf("%s() error, line %d: there are no cert blobs\n",
           __func__,
           __LINE__);
    ret = false;
    goto done;
  }

  if (!x509_to_public_key(root_cert, &root_verify_key)) {
    printf("%s() error, line %d: x509_to_public_key failed\n",
           __func__,
           __LINE__);
    ret = false;
    goto done;
  }

  last_key = new (key_message);
  if (!verify_artifact(*root_cert,
                       root_verify_key,
                       &issuer_name_str,
                       &issuer_description_str,
                       last_key,
                       &subject_name_str,
                       &subject_organization_str,
                       &sn)) {
    printf("%s() error, line %d: verify_artifact failed\n", __func__, __LINE__);
    ret = false;
    goto done;
  }

  // first cert should be root cert
  asn_cert.assign((char *)certs.blobs(0).data(), certs.blobs(0).size());
  current_cert = X509_new();
  if (current_cert == nullptr) {
    printf("%s() error, line %d: can't allocate current cert\n",
           __func__,
           __LINE__);
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
    asn_cert.assign((char *)certs.blobs(i).data(), certs.blobs(i).size());
    if (!asn1_to_x509(asn_cert, current_cert)) {
      printf("%s() error, line %d: asn1_to_cert failed\n", __func__, __LINE__);
      ret = false;
      goto done;
    }
    current_key = new (key_message);
    bool res = verify_artifact(*current_cert,
                               *last_key,
                               &current_issuer_name_str,
                               &current_issuer_organization_str,
                               current_key,
                               &current_subject_name_str,
                               &current_subject_organization_str,
                               &current_sn);
    if (!res) {
      printf("%s() error, line %d: %d cert verify failed\n",
             __func__,
             __LINE__,
             i);
      ret = false;
      goto done;
    }
    current_key = nullptr;

    if (last_cert != nullptr) {
      X509_free(last_cert);
      last_cert = nullptr;
    }
    if (last_key != nullptr) {
      delete last_key;
      last_key = nullptr;
    }

    last_cert = current_cert;
    last_key = current_key;
    current_cert = nullptr;
    current_key = nullptr;
  }

done:
  if (last_cert != nullptr) {
    X509_free(last_cert);
    last_cert = nullptr;
  }
  if (current_cert != nullptr) {
    X509_free(current_cert);
    current_cert = nullptr;
  }
  if (last_key != nullptr) {
    delete last_key;
    last_key = nullptr;
  }
  if (current_key != nullptr) {
    delete current_key;
    current_key = nullptr;
  }
  return ret;
}

}  // namespace acl_lib
}  // namespace certifier

// -----------------------------------------------------------------------
