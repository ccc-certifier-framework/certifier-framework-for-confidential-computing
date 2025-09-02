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

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <sys/socket.h>

#include "certifier_algorithms.h"
#include "certifier_framework.h"
#include "certifier_utilities.h"
#include "cryptstore.pb.h"

using namespace certifier::framework;
using namespace certifier::utilities;

// cf_support.cc

//  -------------------------------------------------------------------

void print_cryptstore_entry(const cryptstore_entry &ent) {
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
    if (ent.type() == "key-message-serialized-protobuf") {
      key_message km;
      if (km.ParseFromString(ent.blob())) {
        print_key(km);
        printf("\n");
      } else {
        printf("Can't deserialize key message\n");
      }
    } else if (ent.type() == "X509-der-cert") {
      X509 *cert = X509_new();
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
      print_bytes(ent.blob().size(), (byte *)ent.blob().data());
      printf("\n");
    }
  }
}

cryptstore_entry *find_in_cryptstore(cryptstore &cs, string &tag, int version) {
  for (int i = 0; i < cs.entries_size(); i++) {
    const cryptstore_entry &ce = cs.entries(i);
    if (ce.tag() == tag) {
      return cs.mutable_entries(i);
    }
  }
  return nullptr;
}

bool version_range_in_cryptstore(cryptstore &cs,
                                 string     &tag,
                                 int        *low,
                                 int        *high) {
  bool ret = false;

  *low = 0;
  *high = 0;
  for (int i = 0; i < cs.entries_size(); i++) {
    const cryptstore_entry &ce = cs.entries(i);
    if (ce.tag() == tag) {
      ret = true;
      if (ce.version() > 0 && (ce.version() < *low || *low == 0)) {
        *low = ce.version();
      }
      if (ce.version() > 0 && ce.version() > *high) {
        *high = ce.version();
      }
    }
  }

  return ret;
}

bool cf_generate_symmetric_key(key_message *key,
                               string       key_name,
                               string       key_type,
                               string       key_format,
                               double       duration_in_hours) {
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
  key->set_secret_key_bits((byte *)key_bytes, num_key_bytes);
  time_point tp_not_before;
  time_point tp_not_after;
  if (!time_now(&tp_not_before)) {
    printf("%s() error, line %d, Can't get current time\n", __func__, __LINE__);
    return false;
  }
  if (!add_interval_to_time_point(tp_not_before,
                                  duration_in_hours,
                                  &tp_not_after)) {
    printf("%s() error, line %d, Can't add time points\n", __func__, __LINE__);
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

bool cf_generate_public_key(key_message *key,
                            string       key_name,
                            string       key_type,
                            string       key_format,
                            double       duration_in_hours) {
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
    printf("%s() error, line %d, Can't get current time\n", __func__, __LINE__);
    return false;
  }
  if (!add_interval_to_time_point(tp_not_before,
                                  duration_in_hours,
                                  &tp_not_after)) {
    printf("%s() error, line %d, Can't add time points\n", __func__, __LINE__);
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

bool get_item(cryptstore &cs,
              string     &tag,
              string     *type,
              int        *version,
              string     *tp,
              string     *value) {
  cryptstore_entry *ce = nullptr;
  int               l = 0;
  int               h = 0;

  if (*version == 0) {
    if (version_range_in_cryptstore(cs, tag, &l, &h)) {
      ce = find_in_cryptstore(cs, tag, h);
      *version = h;
    }
  } else {
    ce = find_in_cryptstore(cs, tag, *version);
  }
  if (ce == nullptr) {
    return false;
  }
  *tp = ce->time_entered();
  value->assign((const char *)ce->blob().data(), ce->blob().size());
  return true;
}

bool put_item(cryptstore &cs,
              string     &tag,
              string     &type,
              int        &version,
              string     &value) {
  cryptstore_entry *ce = nullptr;
  int               l = 0;
  int               h = 0;
  int               ver = version;

  if (version == 0) {
    if (!version_range_in_cryptstore(cs, tag, &l, &h)) {
      ce = find_in_cryptstore(cs, tag, h);
      ver = h + 1;
    }
  }

  ce = cs.add_entries();
  if (ce == nullptr) {
    printf("error pointer\n");
    return false;
  }

  time_point tp;
  if (!time_now(&tp)) {
    printf("%s() error, line %d, Can't get current time\n", __func__, __LINE__);
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
  ce->set_blob((byte *)value.data(), value.size());
  return true;
}

void print_cryptstore(cryptstore &cs) {
  printf("\nCryptstore:\n\n");
  for (int i = 0; i < cs.entries_size(); i++) {
    print_cryptstore_entry(cs.entries(i));
    printf("\n");
  }
}

// -------------------------------------------------------------------------------

// generates cryptstore encryption key and saves protected blob
bool create_cryptstore(cryptstore &cs,
                       string     &data_dir,
                       string     &encrypted_cryptstore_filename,
                       double      duration,
                       string     &enclave_type,
                       string     &sym_alg) {
  string cryptstore_file_name(data_dir);
  cryptstore_file_name.append(encrypted_cryptstore_filename);

  // generate the key
  key_message cryptstore_key;
  string      cryptstore_key_name("cryptstore-sealing-key");
  string      cryptstore_key_type(sym_alg);
  string      cryptstore_key_format("vse-key");
  double      cryptstore_duration_in_hours = duration;

  if (!cf_generate_symmetric_key(&cryptstore_key,
                                 cryptstore_key_name,
                                 cryptstore_key_type,
                                 cryptstore_key_format,
                                 cryptstore_duration_in_hours)) {
    printf("%s() error, line %d, Can't generate symmetric key\n",
           __func__,
           __LINE__);
    return false;
  }

  string serialized_encryption_key;
  if (!cryptstore_key.SerializeToString(&serialized_encryption_key)) {
    printf("%s() error, line %d, Can't serialize key\n", __func__, __LINE__);
    return false;
  }

  string enclave_id("test-enclave");
  int    size_sealed_key = serialized_encryption_key.size() + 128;
  byte   sealed_key[size_sealed_key];

  memset((byte *)sealed_key, 0, size_sealed_key);
  if (!Seal(enclave_type,
            enclave_id,
            serialized_encryption_key.size(),
            (byte *)serialized_encryption_key.data(),
            &size_sealed_key,
            sealed_key)) {
    printf("%s() error, line %d, Can't seal cryptstore key\n",
           __func__,
           __LINE__);
    return false;
  }

  protected_blob_message encrypted_blob;
  string                 serialized_encrypted_blob;

  encrypted_blob.set_encrypted_key((byte *)sealed_key, size_sealed_key);
  encrypted_blob.set_encrypted_data((byte *)sealed_key, 0);

  if (!encrypted_blob.SerializeToString(&serialized_encrypted_blob)) {
    printf("%s() error, line %d, Can't serialize encrypted blob\n",
           __func__,
           __LINE__);
    return false;
  }
  if (!write_file_from_string(cryptstore_file_name,
                              serialized_encrypted_blob)) {
    printf("%s() error, line %d, Can't write protected blob\n",
           __func__,
           __LINE__);
    return false;
  }
  return true;
}

bool save_cryptstore(cryptstore &cs,
                     string     &data_dir,
                     string     &encrypted_cryptstore_filename,
                     double      duration,
                     string     &enclave_type,
                     string     &sym_alg) {
  string cryptstore_file_name(data_dir);
  cryptstore_file_name.append(encrypted_cryptstore_filename);

  protected_blob_message encrypted_blob;
  string                 serialized_encrypted_blob;

  if (!read_file_into_string(encrypted_cryptstore_filename,
                             &serialized_encrypted_blob)) {
    printf("%s() error, line %d, couldn't read encrypted cryptstore %s\n",
           __func__,
           __LINE__,
           encrypted_cryptstore_filename.c_str());
    return false;
  }

  if (!encrypted_blob.ParseFromString(serialized_encrypted_blob)) {
    printf("%s() error, line %d, Can't serialize encrypted blob\n",
           __func__,
           __LINE__);
    return false;
  }

  string enclave_id("test-enclave");
  int size_unsealed_serialized_key = encrypted_blob.encrypted_key().size() + 64;
  byte unsealed_serialized_key[size_unsealed_serialized_key];

  if (!Unseal(enclave_type,
              enclave_id,
              encrypted_blob.encrypted_key().size(),
              (byte *)encrypted_blob.encrypted_key().data(),
              &size_unsealed_serialized_key,
              unsealed_serialized_key)) {
    printf("%s() error, line %d, Can't unseal cryptstore key\n",
           __func__,
           __LINE__);
    return false;
  }

  string      serialized_encryption_key;
  key_message crypt_key;
  serialized_encryption_key.assign((const char *)unsealed_serialized_key,
                                   size_unsealed_serialized_key);

  if (!crypt_key.ParseFromString(serialized_encryption_key)) {
    printf("%s() error, line %d, Can't parse unsealed key\n",
           __func__,
           __LINE__);
    return false;
  }

  string serialized_store;
  if (!cs.SerializeToString(&serialized_store)) {
    printf("%s() error, line %d, Can't parse unsealed key\n",
           __func__,
           __LINE__);
    return false;
  }

  if (serialized_store.size() <= 0) {
    return true;
  }

  int  out_size = serialized_store.size() + 128;
  byte out[out_size];
  memset(out, 0, out_size);

  int  iv_len = 16;
  byte iv[iv_len];
  memset(iv, 0, iv_len);

  if (!get_random(8 * iv_len, iv)) {
    printf("%s() error, line %d, Can't get iv\n", __func__, __LINE__);
    return false;
  }

  if (!authenticated_encrypt(crypt_key.key_type().c_str(),
                             (byte *)serialized_store.data(),
                             (int)serialized_store.size(),
                             (byte *)crypt_key.secret_key_bits().data(),
                             crypt_key.secret_key_bits().size(),
                             (byte *)iv,
                             iv_len,
                             (byte *)out,
                             &out_size)) {
    printf("%s() error, line %d, Can't encrypt sealing key\n",
           __func__,
           __LINE__);
    return false;
  }

  encrypted_blob.set_encrypted_data((byte *)out, out_size);
  serialized_encrypted_blob.clear();
  if (!encrypted_blob.SerializeToString(&serialized_encrypted_blob)) {
    printf("%s() error, line %d, Can't serialize encrypted blob\n",
           __func__,
           __LINE__);
    return false;
  }

#ifdef DEBUG
  printf("\nsave_cryptstore: Symmetric key for unsealing cryptstore\n");
  print_key(crypt_key);
  printf("\n");
  printf("encrypted store save\n");
  print_bytes(serialized_encrypted_blob.size(),
              (byte *)serialized_encrypted_blob.data());
  printf("\n");
  printf("serialized store:\n");
  print_bytes(serialized_store.size(), (byte *)serialized_store.data());
  printf("\n");
#endif

  // write file
  if (!write_file_from_string(cryptstore_file_name,
                              serialized_encrypted_blob)) {
    printf("%s() error, line %d, Can't write protected blob to %s\n",
           __func__,
           __LINE__,
	   cryptstore_file_name.c_str());
    return false;
  }

  return true;
}

bool open_cryptstore(cryptstore *cs,
                     string     &data_dir,
                     string     &encrypted_cryptstore_filename,
                     double      duration,
                     string     &enclave_type,
                     string     &sym_alg) {
  string cryptstore_file_name(data_dir);
  cryptstore_file_name.append(encrypted_cryptstore_filename);

  protected_blob_message encrypted_blob;
  string                 serialized_encrypted_blob;

  if (!read_file_into_string(encrypted_cryptstore_filename,
                             &serialized_encrypted_blob)) {
    printf("%s() error, line %d, couldn't read encrypted cryptstore %s\n",
           __func__,
           __LINE__,
           encrypted_cryptstore_filename.c_str());
    return false;
  }

  if (!encrypted_blob.ParseFromString(serialized_encrypted_blob)) {
    printf("%s() error, line %d, Can't serialize encrypted blob\n",
           __func__,
           __LINE__);
    return false;
  }

  string enclave_id("test-enclave");
  int size_unsealed_serialized_key = encrypted_blob.encrypted_key().size() + 64;
  byte unsealed_serialized_key[size_unsealed_serialized_key];

  if (!Unseal(enclave_type,
              enclave_id,
              encrypted_blob.encrypted_key().size(),
              (byte *)encrypted_blob.encrypted_key().data(),
              &size_unsealed_serialized_key,
              unsealed_serialized_key)) {
    printf("%s() error, line %d, Can't unseal cryptstore key\n",
           __func__,
           __LINE__);
    return false;
  }

  string      serialized_encryption_key;
  key_message crypt_key;
  serialized_encryption_key.assign((const char *)unsealed_serialized_key,
                                   size_unsealed_serialized_key);

  if (!crypt_key.ParseFromString(serialized_encryption_key)) {
    printf("%s() error, line %d, Can't parse unsealed key\n",
           __func__,
           __LINE__);
    return false;
  }

  int  out_size = encrypted_blob.encrypted_data().size() + 128;
  byte out[out_size];
  memset((byte *)out, 0, out_size);

#ifdef DEBUG
  printf("\nopen_cryptstore: Symmetric key for unsealing cryptstore\n");
  print_key(crypt_key);
  printf("\n");
  printf("encrypted store in open %d\n",
         (int)encrypted_blob.encrypted_data().size());
  print_bytes(encrypted_blob.encrypted_data().size(),
              (byte *)encrypted_blob.encrypted_data().data());
  printf("\n");
#endif

  // Nothing to do?
  if ((int)encrypted_blob.encrypted_data().size() <= 0)
    return true;

  if (!authenticated_decrypt(crypt_key.key_type().c_str(),
                             (byte *)encrypted_blob.encrypted_data().data(),
                             encrypted_blob.encrypted_data().size(),
                             (byte *)crypt_key.secret_key_bits().data(),
                             crypt_key.secret_key_bits().size(),
                             (byte *)out,
                             &out_size)) {
    printf("%s() error, line %d, Can't decrypt cryptstore\n",
           __func__,
           __LINE__);
    return false;
  }

  string serialized_cryptstore;
  serialized_cryptstore.assign((const char *)out, out_size);
  if (!cs->ParseFromString(serialized_cryptstore)) {
    printf("%s() error, line %d, Can't parse cryptstore\n", __func__, __LINE__);
    return false;
  }

#ifdef DEBUG
  printf("\nserialized cryptstore\n");
  print_bytes(serialized_cryptstore.size(),
              (byte *)serialized_cryptstore.data());
  printf("\n");
#endif

  return true;
}

// -------------------------------------------------------------------------------
