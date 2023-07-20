//  Copyright (c) 2021-23, VMware Inc, and the Certifier Authors.  All rights
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

using namespace certifier::framework;

// operations are: cold-init, warm-restart, get-certifier, run-app-as-client,
// run-app-as-server
DEFINE_bool(print_all, false, "verbose");
DEFINE_string(operation, "", "operation");

DEFINE_string(policy_host, "localhost", "address for policy server");
DEFINE_int32(policy_port, 8123, "port for policy server");
DEFINE_string(data_dir, "./app1_data/", "directory for application data");

DEFINE_string(server_app_host, "localhost", "address for app server");
DEFINE_int32(server_app_port, 8124, "port for server app server");

DEFINE_string(policy_store_file, "store.bin", "policy store file name");
DEFINE_string(platform_file_name, "platform_file.bin", "platform certificate");
DEFINE_string(platform_attest_endorsement,
              "platform_attest_endorsement.bin",
              "platform endorsement of attest key");
DEFINE_string(attest_key_file, "attest_key_file.bin", "attest key");
DEFINE_string(measurement_file, "example_app.measurement", "measurement");


// The test app performs five possible roles
//    cold-init: This creates application keys and initializes the policy store.
//    warm-restart:  This retrieves the policy store data.
//    get-certifier: This obtains the app admission cert from the service,
//    naming the public app key. run-app-as-client: This runs the app as a
//    server. run-app-as-server: This runs the app as a client

#include "policy_key.cc"  // generated file

cc_trust_data *app_trust_data = nullptr;

// -----------------------------------------------------------------------------------------

void client_application(secure_authenticated_channel &channel) {

  printf("Client peer id is %s\n", channel.peer_id_.c_str());
  if (channel.peer_cert_ != nullptr) {
    printf("Client peer cert is:\n");
#ifdef DEBUG
    X509_print_fp(stdout, channel.peer_cert_);
#endif
  }

  // client sends a message over authenticated, encrypted channel
  const char *msg = "Hi from your secret client\n";
  channel.write(strlen(msg), (byte *)msg);

  // Get server response over authenticated, encrypted channel and print it
  string out;
  int    n = channel.read(&out);
  printf("SSL client read: %s\n", out.data());
}


void server_application(secure_authenticated_channel &channel) {

  printf("Server peer id is %s\n", channel.peer_id_.c_str());
  if (channel.peer_cert_ != nullptr) {
    printf("Server peer cert is:\n");
#ifdef DEBUG
    X509_print_fp(stdout, channel.peer_cert_);
#endif
  }

  // Read message from client over authenticated, encrypted channel
  string out;
  int    n = channel.read(&out);
  printf("SSL server read: %s\n", (const char *)out.data());

  // Reply over authenticated, encrypted channel
  const char *msg = "Hi from your secret server\n";
  channel.write(strlen(msg), (byte *)msg);
}

int main(int an, char **av) {
  string usage("ARM CCA-based simple app");
  gflags::SetUsageMessage(usage);
  gflags::ParseCommandLineFlags(&an, &av, true);
  an = 1;
  ::testing::InitGoogleTest(&an, av);

  if (FLAGS_operation == "") {
    printf("%s: %s\n\n", av[0], usage.c_str());
    printf("\
%s --print_all=true|false \n\
                      --operation=op \n\
                      --policy_host=policy-host-address \n\
                      --policy_port=policy-host-port\n\
                      --data_dir=-directory-for-app-data \n\
                      --server_app_host=my-server-host-address \n\
                      --server_app_port=server-host-port\n\
                      --policy_cert_file=self-signed-policy-cert-file-name \n\
                      --policy_store_file=policy-store-file-name\n\n",
           av[0]);
    printf("Operations are: cold-init, warm-restart, get-certifier, "
           "run-app-as-client, run-app-as-server\n");
    return 0;
  }

  SSL_library_init();
  string enclave_type("islet-enclave");
  string purpose("authentication");

  string store_file(FLAGS_data_dir);
  store_file.append(FLAGS_policy_store_file);
  app_trust_data = new cc_trust_data(enclave_type, purpose, store_file);
  if (app_trust_data == nullptr) {
    printf("couldn't initialize trust object\n");
    return 1;
  }

  // Init policy key info
  if (!app_trust_data->init_policy_key(initialized_cert,
                                       initialized_cert_size)) {
    printf("Can't init policy key\n");
    return 1;
  }

  string platform_attest_file_name(FLAGS_data_dir);
  string measurement_file_name(FLAGS_data_dir);
  measurement_file_name.append(FLAGS_measurement_file);
  string attest_key_file_name(FLAGS_data_dir);
  attest_key_file_name.append(FLAGS_attest_key_file);

  string endorsement_cert;

  if (!app_trust_data->initialize_islet_enclave_data(
          attest_key_file_name,
          measurement_file_name,
          platform_attest_file_name)) {
    printf("%s() error, line %d, Can't init Islet enclave\n",
           __func__,
           __LINE__);
    return 1;
  }

  // Standard algorithms for the enclave
  string public_key_alg("rsa-2048");
  string symmetric_key_alg("aes-256-cbc-hmac-sha256");

  // Carry out operation
  int ret = 0;
  if (FLAGS_operation == "cold-init") {
    if (!app_trust_data->cold_init(public_key_alg,
                                   symmetric_key_alg,
                                   initialized_cert,
                                   initialized_cert_size,
                                   "simple-app-home_domain",
                                   FLAGS_policy_host,
                                   FLAGS_policy_port,
                                   FLAGS_server_app_host,
                                   FLAGS_server_app_port)) {
      printf("%s() error, line %d, cold-init failed\n", __func__, __LINE__);
      ret = 1;
      goto done;
    }
  } else if (FLAGS_operation == "warm-restart") {
    if (!app_trust_data->warm_restart()) {
      printf("%s() error, line %d, warm-restart failed\n", __func__, __LINE__);
      ret = 1;
      goto done;
    }

  } else if (FLAGS_operation == "get-certifier") {
    if (!app_trust_data->warm_restart()) {
      printf("%s() error, line %d, warm-restart failed\n", __func__, __LINE__);
      ret = 1;
      goto done;
    }

    if (!app_trust_data->certify_me()) {
      printf("%s() error, line %d, certification failed\n", __func__, __LINE__);
      ret = 1;
      goto done;
    }
  } else if (FLAGS_operation == "run-app-as-client") {
    string                       my_role("client");
    secure_authenticated_channel channel(my_role);

    if (!app_trust_data->warm_restart()) {
      printf("%s() error, line %d, warm-restart failed\n", __func__, __LINE__);
      ret = 1;
      goto done;
    }

    printf("Running App as client\n");
    if (!app_trust_data->cc_auth_key_initialized_
        || !app_trust_data->cc_policy_info_initialized_) {
      printf("%s() error, line %d, trust data not initialized\n",
             __func__,
             __LINE__);
      ret = 1;
      goto done;
    }
    if (!app_trust_data->primary_admissions_cert_valid_) {
      printf("%s() error, line %d, primary admissions cert not valid\n",
             __func__,
             __LINE__);
      ret = 1;
      goto done;
    }

    if (!channel.init_client_ssl(
            FLAGS_server_app_host,
            FLAGS_server_app_port,
            app_trust_data->serialized_policy_cert_,
            app_trust_data->private_auth_key_,
            app_trust_data->serialized_primary_admissions_cert_)) {
      printf("%s() error, line %d, Can't init client app\n",
             __func__,
             __LINE__);
      ret = 1;
      goto done;
    }

    // This is the actual application code.
    client_application(channel);
  } else if (FLAGS_operation == "run-app-as-server") {
    if (!app_trust_data->warm_restart()) {
      printf("%s() error, line %d, warm-restart failed\n", __func__, __LINE__);
      ret = 1;
      goto done;
    }
    if (!app_trust_data->primary_admissions_cert_valid_) {
      printf("%s() error, line %d, primary admissions cert not valid\n",
             __func__,
             __LINE__);
      ret = 1;
      goto done;
    }
    printf("Running App as server\n");
    if (!server_dispatch(FLAGS_server_app_host,
                         FLAGS_server_app_port,
                         app_trust_data->serialized_policy_cert_,
                         app_trust_data->private_auth_key_,
                         app_trust_data->serialized_primary_admissions_cert_,
                         server_application)) {
      ret = 1;
      goto done;
    }
  } else {
    printf("%s() error, line %d, Unknown operation\n", __func__, __LINE__);
  }

done:
  // app_trust_data->print_trust_data();
  app_trust_data->clear_sensitive_data();
  if (app_trust_data != nullptr) {
    delete app_trust_data;
  }
  return ret;
}
