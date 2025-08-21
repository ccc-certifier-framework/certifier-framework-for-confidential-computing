//  Copyright (c) 2021-23, VMware Inc, and the Certifier Authors.  All rights
//  reserved.  Copyright (c), 2025, John Manferdelli, Paul England and
//  Datica Researdh.
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

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/err.h>

#include "certifier_framework.h"
#include "certifier_utilities.h"
#include "certifier_algorithms.h"

#include "cryptstore.pb.h"

using namespace certifier::framework;
using namespace certifier::utilities;

// cf_support.cc

//  -------------------------------------------------------------------

void print_cryptstore_entry(const cryptstore_entry& ent) {
  if (ent.has_tag()) {
    printf("tag: %s\n", ent.tag().c_str());
  }
  if (ent.has_type()) {
    printf("type: %s\n", ent.type().c_str());
  }
  if (ent.has_version()) {
    printf("version: %d\n", (int)ent.version());
  }
  if (ent.has_time_entered()) {
    printf("time entered: %s\n", ent.time_entered().c_str());
  }
  if (ent.has_blob()) {
    if (ent.type() == "key_message_serialized-protobuf") {
      key_message km;
      if (km.ParseFromString(ent.blob())) {
        print_key(km);
        printf("\n");
      } else {
        printf("Can't deserialize key message\n");
      }
    } else if (ent.type() == "X509-der-cert") {
      X509* cert= X509_new();
      if (cert != nullptr) {
        if (asn1_to_x509(ent.blob(), cert)) {
          X509_print_fp(stdout, cert);
        } else {
          printf("Can't decode der encoded cert\n");
        }
      }
      X509_free(cert);
    } else {
      printf("Value:\n");
      print_bytes(ent.blob().size(), (byte*)ent.blob().data());
      printf("\n");
    }
  }
}

cryptstore_entry* find_in_cryptstore(cryptstore& cs, string& tag, int version) {
  for (int i= 0; i < cs.entries_size(); i++) {
    const cryptstore_entry& ce = cs.entries(i);
    if (ce.tag() == tag) {
      return cs.mutable_entries(i);
    }
  }
  return nullptr;
}

bool version_range_in_cryptstore(cryptstore& cs, string& tag,
                                 int* low, int* high) {
  bool ret= false;

  *low= 0;
  *high= 0;
  for (int i= 0; i < cs.entries_size(); i++) {
    const cryptstore_entry& ce = cs.entries(i);
    if (ce.tag() == tag) {
      ret= true;
      if (ce.version() > 0 && ce.version() < *low) {
        *low= ce.version();
      }
      if (ce.version() > 0 && ce.version() > *high) {
        *high= ce.version();
      }
    }
  }

  return ret;
}

bool cf_generate_symmetric_key(
   key_message* key,
   string key_name,
   string key_type,
   string key_format,
   double duration_in_hours) {

  int num_key_bytes;
  if (key_type == Enc_method_aes_256_cbc_hmac_sha256
      || key_type == Enc_method_aes_256_cbc_hmac_sha384
      || key_type == Enc_method_aes_256_gcm) {
    num_key_bytes = cipher_key_byte_size(key_type.c_str());
    if (num_key_bytes <= 0) {
      printf("%s() error, line %d, Can't recover symmetric alg key size\n",
             __func__,
             __LINE__);
      return false;
    }
  } else {
    printf("%s() error, line %d, unsupported encryption algorithm: '%s'\n",
           __func__,
           __LINE__,
           key_type.c_str());
    return false;
  }
  printf("num_bytes: %d\n", num_key_bytes);
  byte key_bytes[num_key_bytes];
  memset(key_bytes, 0, num_key_bytes);
  if (!get_random(8 * num_key_bytes, key_bytes)) {
    printf("%s() error, line %d, Can't get random bytes for app key\n",
           __func__,
           __LINE__);
    return false;
  }
  key->set_key_name(key_name);
  key->set_key_type(key_type);
  key->set_key_format(key_format);
  key->set_secret_key_bits((byte*)key_bytes, num_key_bytes);
  time_point tp_not_before;
  time_point tp_not_after;
  if (!time_now(&tp_not_before)) {
    printf("%s() error, line %d, Can't get current time\n",
           __func__,
           __LINE__);
    return false;
  }
  if (!add_interval_to_time_point(tp_not_before,
                                duration_in_hours,
                                &tp_not_after)) {
    printf("%s() error, line %d, Can't add time points\n",
           __func__,
           __LINE__);
    return false;
  }
  string nb_str;
  string na_str;
  if (!time_to_string(tp_not_before, &nb_str)) {
    printf("%s() error, line %d, Can't convert time to string\n",
           __func__,
           __LINE__);
    return false;
  }
  if (!time_to_string(tp_not_after, &na_str)) {
    printf("%s() error, line %d, Can't convert time to string\n",
           __func__,
           __LINE__);
    return false;
  }
  key->set_not_before(nb_str);
  key->set_not_after(na_str);

  return true;
}

bool cf_generate_public_key(
   key_message* key,
   string key_name,
   string key_type,
   string key_format,
   double duration_in_hours) {

  if (key_type == Enc_method_rsa_2048) {
    if (!make_certifier_rsa_key(2048, key)) {
      printf("%s() error, line %d, Can't generate private key\n",
             __func__,
             __LINE__);
      return false;
    }
  } else if (key_type == Enc_method_rsa_3072) {
    if (!make_certifier_rsa_key(3072, key)) {
      printf("%s() error, line %d, Can't generate App private key\n",
             __func__,
             __LINE__);
      return false;
    }
  } else if (key_type == Enc_method_rsa_4096) {
    if (!make_certifier_rsa_key(4096, key)) {
      printf("%s() error, line %d, Can't generate App private key\n",
             __func__,
             __LINE__);
      return false;
    }
  } else if (key_type == Enc_method_ecc_384) {
    if (!make_certifier_ecc_key(384, key)) {
      printf("%s() error, line %d, Can't generate App private key\n",
             __func__,
            __LINE__);
      return false;
    }
  } else {
    printf("%s() error, line %d, Unsupported public key algorithm: '%s'\n",
           __func__,
           __LINE__,
           key_type.c_str());
    return false;
  }

  key->set_key_name(key_name);
  key->set_key_type(key_type);
  key->set_key_format("vse-key");

  time_point tp_not_before;
  time_point tp_not_after;
  if (!time_now(&tp_not_before)) {
    printf("%s() error, line %d, Can't get current time\n",
           __func__,
           __LINE__);
    return false;
  }
  if (!add_interval_to_time_point(tp_not_before,
                                duration_in_hours,
                                &tp_not_after)) {
    printf("%s() error, line %d, Can't add time points\n",
           __func__,
           __LINE__);
    return false;
  }
  string nb_str;
  string na_str;
  if (!time_to_string(tp_not_before, &nb_str)) {
    printf("%s() error, line %d, Can't convert time to string\n",
           __func__,
           __LINE__);
    return false;
  }
  if (!time_to_string(tp_not_after, &na_str)) {
    printf("%s() error, line %d, Can't convert time to string\n",
           __func__,
           __LINE__);
    return false;
  }
  key->set_not_before(nb_str);
  key->set_not_after(na_str);

  return true;
}

bool get_item(cryptstore& cs, string& tag, string* type, int* version,
              string* tp, string* value) {
  cryptstore_entry* ce= nullptr;
  int l= 0;
  int h= 0;

  if (*version == 0) {
    if (!version_range_in_cryptstore(cs, tag, &l, &h)) {
      ce= find_in_cryptstore(cs, tag, h);
      *version= h;
    }
  } else {
    ce= find_in_cryptstore(cs, tag, *version);
  }
  if (ce == nullptr)
    return false;
  *tp= ce->time_entered(); 
  value->assign((const char*)ce->blob().data(), ce->blob().size());
  return true;
}

bool put_item(cryptstore& cs, string& tag, string& type, int& version,
               string& value) {
  cryptstore_entry* ce= nullptr;
  int l= 0;
  int h= 0;
  int ver= version;

  if (version == 0) {
    if (!version_range_in_cryptstore(cs, tag, &l, &h)) {
      ce= find_in_cryptstore(cs, tag, h);
      ver= h + 1;
    }
  }

  ce= cs.add_entries();
  if (ce == nullptr)
    return false;

  time_point tp;
  if (!time_now(&tp)) {
    printf("%s() error, line %d, Can't get current time\n",
           __func__,
           __LINE__);
    return false;
  }
  string tp_str;
  if (!time_to_string(tp, &tp_str)) {
    printf("%s() error, line %d, Can't convert time to string\n",
           __func__,
           __LINE__);
    return false;
  }
  ce->set_tag(tag);
  ce->set_type(type);
  ce->set_time_entered(tp_str);
  ce->set_version(ver);

  ce->set_blob((byte*)value.data(), value.size());
  return true;
  // return save_cryptstore(cs);
}

void print_cryptstore(cryptstore& cs) {
  printf("\nCryptstore:\n\n");
  for (int i = 0; i < cs.entries_size(); i++) {
    print_cryptstore_entry(cs.entries(i));
    printf("\n");
  }
}

// -------------------------------------------------------------------------------

