//  Copyright (c) 2021-22, VMware Inc, and the Certifier Authors.  All rights
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

#include <gtest/gtest.h>
#include <gflags/gflags.h>

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

using namespace certifier::framework;
using namespace certifier::utilities;

// Ops are: cold-init, get-certified, run-app-as-client, run-app-as-server
DEFINE_bool(print_all, false, "verbose");
DEFINE_string(operation, "", "operation");

DEFINE_string(policy_host, "localhost", "address for policy server");
DEFINE_int32(policy_port, 8123, "port for policy server");
DEFINE_string(data_dir, "./app1_data/", "directory for application data");

DEFINE_string(policy_store_file, "store.bin", "policy store file name");
DEFINE_string(platform_file_name, "platform_file.bin", "platform certificate");
DEFINE_string(platform_attest_endorsement,
              "platform_attest_endorsement.bin",
              "platform endorsement of attest key");
DEFINE_string(attest_key_file, "attest_key_file.bin", "attest key");
DEFINE_string(measurement_file, "example_app.measurement", "measurement");


// The test demonstrates key rotation of the public key
// For an example of rotating keys for protect_blob, see the certifier_tests.

#include "policy_key.cc"
cc_trust_manager *trust_mgr = nullptr;


// -----------------------------------------------------------------------------------------

// Parameters for simulated enclave
bool get_simulated_enclave_parameters(string **s, int *n) {

  // serialized attest key, measurement, serialized endorsement, in that order
  string *args = new string[3];
  if (args == nullptr) {
    return false;
  }
  *s = args;

  if (!read_file_into_string(FLAGS_data_dir + FLAGS_attest_key_file,
                             &args[0])) {
    printf("%s() error, line %d, Can't read attest file\n", __func__, __LINE__);
    return false;
  }

  if (!read_file_into_string(FLAGS_data_dir + FLAGS_measurement_file,
                             &args[1])) {
    printf("%s() error, line %d, Can't read measurement file\n",
           __func__,
           __LINE__);
    return false;
  }

  if (!read_file_into_string(FLAGS_data_dir + FLAGS_platform_attest_endorsement,
                             &args[2])) {
    printf("%s() error, line %d, Can't read endorsement file\n",
           __func__,
           __LINE__);
    return false;
  }

  *n = 3;
  return true;
}

int main(int an, char **av) {
  gflags::ParseCommandLineFlags(&an, &av, true);
  an = 1;
  ::testing::InitGoogleTest(&an, av);

  if (FLAGS_operation == "") {
    printf(
        "example_key_rotation.exe --print_all=true|false --operation=op "
        "--policy_host=policy-host-address --policy_port=policy-host-port\n");
    printf("\t --data_dir=-directory-for-app-data\n");
    printf("\t --policy_cert_file=self-signed-policy-cert-file-name "
           "--policy_store_file=policy-store-file-name\n");
    return 0;
  }

  SSL_library_init();
  string enclave_type("simulated-enclave");

  string store_file(FLAGS_data_dir);
  store_file.append(FLAGS_policy_store_file);
  string purpose("authentication");

  trust_mgr = new cc_trust_manager(enclave_type, purpose, store_file);
  if (trust_mgr == nullptr) {
    printf("%s() error, line %d, couldn't initialize trust object\n",
           __func__,
           __LINE__);
    return 1;
  }

  // Init policy key info
  if (!trust_mgr->init_policy_key(initialized_cert, initialized_cert_size)) {
    printf("%s() error, line %d, Can't init policy key\n", __func__, __LINE__);
    return 1;
  }

  // Get parameters
  string *params = nullptr;
  int     n = 0;
  if (!get_simulated_enclave_parameters(&params, &n) || params == nullptr) {
    printf("%s() error, line %d, get simulated enclave parameters\n",
           __func__,
           __LINE__);
    return 1;
  }

  // Init simulated enclave
  if (!trust_mgr->initialize_enclave(n, params)) {
    printf("%s() error, line %d, Can't init simulated enclave\n",
           __func__,
           __LINE__);
    return 1;
  }
  if (params != nullptr) {
    delete[] params;
    params = nullptr;
  }

  int ret = 0;

  // Get certificate
  string der_cert;
  X509 * x509_cert = X509_new();
  if (purpose == "authentication") {
    if (!trust_mgr->cc_auth_key_initialized_) {
      printf("%s() error, line %d, Auth key uninitialized", __func__, __LINE__);
      return 1;
    }
    der_cert = trust_mgr->public_auth_key_.certificate();
    if (!asn1_to_x509(der_cert, x509_cert)) {
      printf("%s() error, line %d, Can't convert der to x509",
             __func__,
             __LINE__);
      return 1;
    }
  } else if (purpose == "attestation") {
    if (!trust_mgr->cc_service_key_initialized_) {
      printf("%s() error, line %d, Service key uninitialized",
             __func__,
             __LINE__);
      return 1;
    }
    der_cert = trust_mgr->public_service_key_.certificate();
    if (!asn1_to_x509(der_cert, x509_cert)) {
      printf("%s() error, line %d, Can't convert der to x509",
             __func__,
             __LINE__);
      return 1;
    }
  } else {
    printf("%s() error, line %d, Unknown purpose\n", __func__, __LINE__);
    return 1;
  }

  // time left?
  time_point now;
  time_point expires;
  time_point two_days_from_now;

  if (!get_not_after_from_cert(x509_cert, &expires)) {
    printf("%s() error, line %d, Can't get expitation time",
           __func__,
           __LINE__);
    return 1;
  }

  if (!time_now(&now)) {
    printf("%s() error, line %d, Can't get time now\n", __func__, __LINE__);
    return 1;
  }
  if (!add_interval_to_time_point(now, 48.0, &two_days_from_now)) {
    printf("%s() error, line %d, Can't add time interval\n",
           __func__,
           __LINE__);
    return 1;
  }

  if (compare_time(two_days_from_now, expires) <= 0) {
    printf("%s() error, line %d, More than two days left\n",
           __func__,
           __LINE__);
    return 1;
  }

  if (!trust_mgr->generate_symmetric_key(true)) {
    printf("%s() error, line %d, can't generate key\n", __func__, __LINE__);
    return 1;
  }
  if (!trust_mgr->generate_sealing_key(true)) {
    printf("%s() error, line %d, can't generate key\n", __func__, __LINE__);
    return 1;
  }
  if (!trust_mgr->generate_auth_key(true)) {
    printf("%s() error, line %d, can't generate key\n", __func__, __LINE__);
    return 1;
  }
  if (!trust_mgr->generate_service_key(true)) {
    printf("%s() error, line %d, can't generate key\n", __func__, __LINE__);
    return 1;
  }

  trust_mgr->cc_is_certified_ = false;

  // Now recertify
  if (!trust_mgr->certify_me()) {
    printf("%s() error, line %d, can't recertify\n", __func__, __LINE__);
    return 1;
  }

  if (!trust_mgr->put_trust_data_in_store()) {
    printf("%s() error, line %d, Can't put_trust_in_store\n",
           __func__,
           __LINE__);
    return 1;
  }
  if (!trust_mgr->save_store()) {
    printf("%s() error, line %d, Can't save store\n", __func__, __LINE__);
    return 1;
  }
  printf("Key rotation succeeded\n");

  if (x509_cert != nullptr) {
    X509_free(x509_cert);
    x509_cert = nullptr;
  }

  trust_mgr->clear_sensitive_data();
  if (trust_mgr != nullptr) {
    delete trust_mgr;
  }
  return ret;
}
