//  Copyright (c) 2025, the Certifier Authors.  All rights
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


#include <gflags/gflags.h>
#include <gtest/gtest.h>

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
#include "cf_support.h"

using namespace certifier::framework;
using namespace certifier::utilities;

DEFINE_bool(print_all, false, "verbose");

DEFINE_string(enclave_type, "simulated-enclave", "enclave type");
DEFINE_string(data_dir, "./", "data directory");
DEFINE_string(encrypted_cryptstore_filename,
              "encrypted_filestore.datica",
              "cryptstore");
DEFINE_double(duration, 24.0 * 365.0, "duration of key");
DEFINE_string(public_key_algorithm,
              Enc_method_rsa_2048,
              "public key algorithm");
DEFINE_string(symmetric_key_algorithm,
              Enc_method_aes_256_cbc_hmac_sha256,
              "symmetric algorithm");


// --------------------------------------------------------------------

bool test_get_put_item(bool print) {
  cryptstore cs;

  key_message km1;
  string      key_name1("test-key-1");
  string      key_type1(Enc_method_aes_256_cbc_hmac_sha256);
  string      key_format("vse-key");
  double      duration_in_hours = 24.0 * 365.0;

  if (!cf_generate_symmetric_key(&km1,
                                 key_name1,
                                 key_type1,
                                 key_format,
                                 duration_in_hours)) {
    printf("Can't generate symmetric key\n");
    return false;
  }

  if (print) {
    printf("Generated key\n");
    print_key(km1);
    printf("\n");
  }

  key_message km2;
  string      key_name2("test-key-2");
  string      key_type2(Enc_method_rsa_2048);
  if (!cf_generate_public_key(&km2,
                              key_name2,
                              key_type2,
                              key_format,
                              duration_in_hours)) {
    printf("Can't generate public key\n");
    return false;
  }

  if (print) {
    printf("Generated key\n");
    print_key(km2);
    printf("\n");
  }

  string tag1("test-key1-tag");
  string tag2("test-key2-tag");
  int    version1 = 0;
  int    version2 = 0;
  string cs_type("key-message-serialized-protobuf");
  string tp_str;
  string serialized_key_1;
  string serialized_key_2;
  if (!km1.SerializeToString(&serialized_key_1)) {
    printf("Can't serialize symmetric key\n");
    return false;
  }
  if (!km2.SerializeToString(&serialized_key_2)) {
    printf("Can't serialize public key\n");
    return false;
  }
  if (!put_item(cs, tag1, cs_type, version1, serialized_key_1)) {
    printf("Can't put_item key 1\n");
    return false;
  }
  if (!put_item(cs, tag2, cs_type, version2, serialized_key_2)) {
    printf("Can't put_item key 1\n");
    return false;
  }

  int               l = 0;
  int               h = 0;
  cryptstore_entry *ce = find_in_cryptstore(cs, tag1, 1);
  if (ce == nullptr) {
    printf("find_in_cryptstore failed\n");
    return false;
  }

  if (print) {
    printf("find_in_cryptstore succeeded\n");
    print_cryptstore_entry(*ce);
    printf("\n");
  }

  if (!version_range_in_cryptstore(cs, tag1, &l, &h)) {
    printf("version_in_range failed\n");
    return false;
  }

  if (print) {
    printf("version_in_range succeeded, low: %d, high: %d\n", l, h);
  }

  string recovered_value_1;
  string recovered_value_2;
  string tp_str2;
  if (!get_item(cs, tag1, &cs_type, &version2, &tp_str2, &recovered_value_1)) {
    printf("Can't get_item key 1\n");
    return false;
  }

  if (print) {
    printf("get_item succeeded, %s, %s, %d, %s\n",
           tag1.c_str(),
           cs_type.c_str(),
           version2,
           tp_str2.c_str());
  }

  print_cryptstore(cs);
  return true;
}

bool test_store(bool print) {
  extern bool simulator_init();
  if (!simulator_init()) {
    printf("Can't init simulator\n");
    return false;
  }

  cryptstore cs;
  if (!create_cryptstore(cs,
                         FLAGS_data_dir,
                         FLAGS_encrypted_cryptstore_filename,
                         FLAGS_duration,
                         FLAGS_enclave_type,
                         FLAGS_symmetric_key_algorithm)) {
    printf("Can't create cryptstore\n");
    return false;
  }

  cryptstore_entry *ce = cs.add_entries();
  ce->set_tag("test-entry");
  ce->set_type("blob");
  ce->set_version(1);
  const char *a = "12345";
  ce->set_blob((byte *)a, strlen(a) + 1);

  if (print) {
    printf("\noriginal keystore\n");
    print_cryptstore(cs);
    printf("\n");
  }

  if (!save_cryptstore(cs,
                       FLAGS_data_dir,
                       FLAGS_encrypted_cryptstore_filename,
                       FLAGS_duration,
                       FLAGS_enclave_type,
                       FLAGS_symmetric_key_algorithm)) {
    printf("Can't save cryptstore\n");
    return false;
  }

  cryptstore recovered_cs;
  if (!open_cryptstore(&recovered_cs,
                       FLAGS_data_dir,
                       FLAGS_encrypted_cryptstore_filename,
                       FLAGS_duration,
                       FLAGS_enclave_type,
                       FLAGS_symmetric_key_algorithm)) {
    printf("Can't reopen cryptstore\n");
    return false;
  }

  if (print) {
    printf("\nrecovered keystore\n");
    print_cryptstore(recovered_cs);
    printf("\n");
  }

  return true;
}

TEST(test_get_put, test_get_put_item) {
  EXPECT_TRUE(test_get_put_item(FLAGS_print_all));
}

TEST(test_store, test_store) {
  EXPECT_TRUE(test_store(FLAGS_print_all));
}

// --------------------------------------------------------------------


int main(int an, char **av) {
  gflags::ParseCommandLineFlags(&an, &av, true);
  an = 1;
  ::testing::InitGoogleTest(&an, av);

  int result = RUN_ALL_TESTS();

  printf("\n");
  return result;
}

// --------------------------------------------------------------------------------
