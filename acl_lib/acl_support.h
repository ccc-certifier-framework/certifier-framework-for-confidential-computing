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
// File: acl_support.h

#ifndef _ACL_SUPPORT_H__
#define _ACL_SUPPORT_H__

#include "acl.pb.h"

#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/ec.h>

#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "stdio.h"
#include <unistd.h>
#include "sys/fcntl.h"
#include "sys/stat.h"

#include "certifier.pb.h"
#include "support.h"
#include "certifier.h"
#include "support.h"
#include "acl.pb.h"
#include "acl_support.h"
#include "acl.h"

using namespace certifier::framework;
using namespace certifier::utilities;

// ----------------------------------------------------------------------

namespace certifier {
namespace acl_lib {


#ifndef int32_t
typedef int int32_t;
#endif

#ifndef int64_t
#  ifdef __linux__
typedef long int int64_t;
#  else
typedef long long int int64_t;
#  endif
#endif

#ifndef uint32_t
typedef unsigned uint32_t;
#endif

#ifndef uint64_t
#  ifdef __linux__
typedef long unsigned uint64_t;
#  else
typedef long long unsigned uint64_t;
#  endif
#endif

#ifndef NBITSINBYTE
#  define NBITSINBYTE 8
#endif
#ifndef NBITSINUINT64
#  define NBITSINUINT64 64
#endif

#ifndef byte
typedef unsigned char byte;
#endif

using std::string;

const int    seconds_in_day = 86400;
const int    seconds_in_minute = 60;
const int    seconds_in_hour = 3600;
const double seconds_in_common_year = 365.0 * 86400;
const double seconds_in_leap_year = 366.0 * 86400;
const double seconds_in_gaussian_year = 365.2568983 * 86400;

// --------------------------------------------------

bool add_interval_to_time(time_point &from,
                          double      seconds_later,
                          time_point *to);
bool encode_time(time_point &tp, string *the_time);
bool decode_time(string &encoded_time, time_point *tp);
bool unix_tm_to_time_point(struct tm *the_time, time_point *tp);

class random_source {
 public:
  bool initialized_;
  bool have_rd_rand_;
  int  fd_;

  random_source();
  bool have_intel_rd_rand();
  bool start_random_source();
  int  get_random_bytes(int n, byte *b);
  bool close_random_source();
};

void reverse_bytes(int size, byte *in, byte *out);
void reverse_bytes_in_place(int size, byte *b);
int  bits_to_bytes(int n);
int  bytes_to_bits(int n);
int  bits_to_uint64(int n);
int  uint64_to_bits(int n);
bool hex_to_bytes(string &h, string *b);
bool bytes_to_hex(string &b, string *h);
bool base64_to_bytes(string &b64, string *b);
bool bytes_to_base64(string &b, string *b64);
void print_encrypted_message(encrypted_message &m);
void print_signature_message(signature_message &m);

key_message *make_symmetric_key(string       &alg,
                                string       &name,
                                const string &not_before,
                                const string &not_after,
                                const string &key_bits);

class name_size {
 public:
  const char *name_;
  int         size_;
};

int  crypto_get_random_bytes(int num_bytes, byte *buf);
bool init_crypto();
void close_crypto();

bool verify_cert_chain(X509 *root_cert, buffer_list &certs);

}  // namespace acl_lib
}  // namespace certifier
#endif
