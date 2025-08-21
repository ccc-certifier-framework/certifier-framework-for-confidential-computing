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

// --------------------------------------------------------------------

bool test_get_put_item(bool print) {
  return true;
}

TEST(test_get_put, test_get_put_item) {
  EXPECT_TRUE(test_get_put_item(FLAGS_print_all));
}


int main(int an, char **av) {
  gflags::ParseCommandLineFlags(&an, &av, true);
  an = 1;
  ::testing::InitGoogleTest(&an, av);

#if 1
  extern bool simulator_init();
  if (!simulator_init()) {
    return 1;
  }
#else
  if (!simulated_Init(serialized_policy_cert_,
                      attest_key_file_name,
                      measurement_file_name,
                      attest_endorsement_file_name)) {
    printf("simulated_init failed\n");
    return false;
  }
#endif

  int result = RUN_ALL_TESTS();

  printf("\n");
  return result;
}

// --------------------------------------------------------------------------------
