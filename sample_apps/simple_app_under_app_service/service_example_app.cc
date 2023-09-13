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
DEFINE_string(parent_enclave, "simulated-enclave", "parent enclave");

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
//    get-certified: This obtains the app admission cert naming the public app
//    key from the service. run-app-as-client: This runs the app as a server.
//    run-app-as-server: This runs the app as a client
//    warm-restart:  This retrieves the policy store data. Operation is subsumed
//      under other ops.

#include "policy_key.cc"
cc_trust_manager *trust_mgr = nullptr;

// -----------------------------------------------------------------------------------------

// This is the secure channel between the CC protected client and protected
// server.
//    Most of the work of setting up SSL is done with the helpers.

// Consider changing return value to bool and returning false if
// we don't get the expected response.

bool client_application(secure_authenticated_channel &channel) {

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
  channel.close();

  if (n < 0 || strcmp(out.c_str(), "Hi from your secret server\n") != 0) {
    printf("%s() error, line %d, did not receive expected server response\n",
           __func__,
           __LINE__);
    return false;
  }
  return true;
}


void server_application(secure_authenticated_channel &channel) {

  printf("Server peer id is %s\n", channel.peer_id_.c_str());

  // Read message from client over authenticated, encrypted channel
  string out;
  int    n = channel.read(&out);
  printf("SSL server read: %s\n", (const char *)out.data());

  // Reply over authenticated, encrypted channel
  const char *msg = "Hi from your secret server\n";
  channel.write(strlen(msg), (byte *)msg);
  channel.close();
}

bool run_me_as_server(const string &host_name,
                      int           port,
                      string &      asn1_policy_cert,
                      key_message & private_key,
                      string &      private_key_cert) {

  printf("running as server\n");
  server_dispatch(host_name,
                  port,
                  asn1_policy_cert,
                  private_key,
                  private_key_cert,
                  server_application);
  return true;
}

// Standard algorithms for the enclave
string public_key_alg(Enc_method_rsa_2048);
string symmetric_key_alg(Enc_method_aes_256_cbc_hmac_sha256);

// -------------------------------------------------------------

int main(int an, char **av) {

  // remove pipe descriptors before processing other arguments
  if (an < 2) {
    printf("%s() error, line %d, Too few input arguments\n",
           __func__,
           __LINE__);
    return 1;
  }

  // Debug
  printf("num args: %d\n", an);
  for (int i = 0; i < an; i++) {
    printf("argv[%d]: %s\n", i, av[i]);
  }
  printf("\n");

  string input_fd = av[an - 2];
  string output_fd = av[an - 1];
  an -= 2;

  gflags::ParseCommandLineFlags(&an, &av, true);
  ::testing::InitGoogleTest(&an, av);

  if (FLAGS_operation == "") {
    printf(
        "service_example_app.exe --print_all=true|false --operation=op "
        "--policy_host=policy-host-address --policy_port=policy-host-port\n");
    printf("\t --data_dir=-directory-for-app-data "
           "--server_app_host=my-server-host-address "
           "--server_app_port=server-host-port\n");
    printf("\t --policy_cert_file=self-signed-policy-cert-file-name "
           "--policy_store_file=policy-store-file-name\n");
    printf("Operations are: cold-init, get-certified, "
           "run-app-as-client, run-app-as-server\n");
    return 0;
  }

  SSL_library_init();
  // Parent will usually be an SEV-SNP or TDX encrypted vitual
  // machine.
  string parent_enclave_type(FLAGS_parent_enclave);
  string enclave_type("application-enclave");
  string purpose("authentication");

  string store_file(FLAGS_data_dir);
  store_file.append(FLAGS_policy_store_file);
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
    return false;
  }

  // Application enclave parameters
  int    n = 3;
  string params[3];
  params[0] = parent_enclave_type;
  params[1] = input_fd;
  params[2] = output_fd;

  // Init application enclave
  if (!trust_mgr->initialize_enclave(n, params)) {
    printf("%s() error, line %d, Can't init application-enclave\n",
           __func__,
           __LINE__);
    return 1;
  }

  // Carry out operations as before
  int ret = 0;
  if (FLAGS_operation == "cold-init") {
    if (!trust_mgr->cold_init(public_key_alg,
                              symmetric_key_alg,
                              "simple-app-home_domain",
                              FLAGS_policy_host,
                              FLAGS_policy_port,
                              FLAGS_server_app_host,
                              FLAGS_server_app_port)) {
      printf("%s() error, line %d, cold-init failed\n", __func__, __LINE__);
      ret = 1;
      goto done;
    }
  } else if (FLAGS_operation == "get-certified") {
    if (!trust_mgr->warm_restart()) {
      printf("%s() error, line %d, warm-restart failed\n", __func__, __LINE__);
      ret = 1;
      goto done;
    }
    if (!trust_mgr->certify_me()) {
      printf("%s() error, line %d, certification failed\n", __func__, __LINE__);
      ret = 1;
    }
  } else if (FLAGS_operation == "run-app-as-client") {
    string                       my_role("client");
    secure_authenticated_channel channel(my_role);

    if (!trust_mgr->warm_restart()) {
      printf("%s() error, line %d, warm-restart failed\n", __func__, __LINE__);
      ret = 1;
      goto done;
    }
    if (!trust_mgr->primary_admissions_cert_valid_) {
      printf("%s() error, line %d, primary admissions cert not valid\n",
             __func__,
             __LINE__);
      ret = 1;
      goto done;
    }

    printf("running as client\n");
    if (!trust_mgr->cc_auth_key_initialized_
        || !trust_mgr->cc_policy_info_initialized_) {
      printf("%s() error, line %d, trust data not initialized\n",
             __func__,
             __LINE__);
      ret = 1;
      goto done;
    }

#ifdef DEBUG
    printf("client_init\n");
    printf("App host: %s\n", FLAGS_server_app_host.c_str());
    printf("App port: %d\n", FLAGS_server_app_port);
    printf("Policy cert: ");
    print_bytes(trust_mgr->serialized_policy_cert_.size(),
                (byte *)trust_mgr->serialized_policy_cert_.data());
    printf("\n");
    printf("Auth key: ");
    print_key(trust_mgr->private_auth_key_);
    printf("\n");
    printf("Admissions cert: ");
    print_bytes(trust_mgr->serialized_primary_admissions_cert_.size(),
                (byte *)trust_mgr->serialized_primary_admissions_cert_.data());
    printf("\n");
#endif

    if (!channel.init_client_ssl(
            FLAGS_server_app_host,
            FLAGS_server_app_port,
            trust_mgr->serialized_policy_cert_,
            trust_mgr->private_auth_key_,
            trust_mgr->serialized_primary_admissions_cert_)) {
      printf("%s() error, line %d, Can't init client app\n",
             __func__,
             __LINE__);
      ret = 1;
      goto done;
    }

    // This is the actual application code.
    if (!client_application(channel)) {
      printf("%s() error, line %d, client_application failed\n",
             __func__,
             __LINE__);
      ret = 1;
      goto done;
    }

  } else if (FLAGS_operation == "run-app-as-server") {
    if (!trust_mgr->warm_restart()) {
      printf("%s() error, line %d, warm-restart failed\n", __func__, __LINE__);
      ret = 1;
      goto done;
    }
    if (!trust_mgr->primary_admissions_cert_valid_) {
      printf("%s() error, line %d, primary admissions cert not valid\n",
             __func__,
             __LINE__);
      ret = 1;
      goto done;
    }

    printf("running as server\n");
    server_dispatch(FLAGS_server_app_host,
                    FLAGS_server_app_port,
                    trust_mgr->serialized_policy_cert_,
                    trust_mgr->private_auth_key_,
                    trust_mgr->serialized_primary_admissions_cert_,
                    server_application);
  } else {
    printf("%s() error, line %d, Unknown operation\n", __func__, __LINE__);
    ret = 1;
  }

done:
  printf("enclave: %s, parent enclave: %s, purpose: %s\n",
         trust_mgr->enclave_type_.c_str(),
         parent_enclave_type.c_str(),
         trust_mgr->purpose_.c_str());
  printf("\n");
  // trust_mgr->print_trust_data();
  trust_mgr->clear_sensitive_data();
  if (trust_mgr != nullptr) {
    delete trust_mgr;
  }
  return ret;
}
