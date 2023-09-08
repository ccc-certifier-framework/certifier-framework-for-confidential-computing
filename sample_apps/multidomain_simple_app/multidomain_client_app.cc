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

DEFINE_string(primary_policy_host, "localhost", "address for policy server");
DEFINE_int32(primary_policy_port, 8123, "port for policy server");

DEFINE_string(secondary_policy_host, "localhost", "address for policy server");
DEFINE_int32(secondary_policy_port, 8123, "port for policy server");

DEFINE_string(data_dir, "./app1_data/", "directory for application data");

DEFINE_string(secondary_cert_file,
              "server_policy_cert_file.bin",
              "directory for application data");

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
//    key from the service. run-app-as-client: This runs the app as a client
//    warm-restart:  This retrieves the policy store data. Operation is subsumed
//      under other ops.

#include "client_policy_key.cc"
cc_trust_manager *trust_mgr = nullptr;

// -----------------------------------------------------------------------------------------


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

// --------------------------------------------------------------------------

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
    string err = FLAGS_data_dir + FLAGS_attest_key_file;
    printf("%s() error, line %d, Can't read attest file %s\n",
           __func__,
           __LINE__,
           err.c_str());
    return false;
  }

  if (!read_file_into_string(FLAGS_data_dir + FLAGS_measurement_file,
                             &args[1])) {
    string err = FLAGS_data_dir + FLAGS_measurement_file;
    printf("%s() error, line %d, Can't read measurement file %s\n",
           __func__,
           __LINE__,
           err.c_str());
    return false;
  }

  if (!read_file_into_string(FLAGS_data_dir + FLAGS_platform_attest_endorsement,
                             &args[2])) {
    string err = FLAGS_data_dir + FLAGS_platform_attest_endorsement;
    printf("%s() error, line %d, Can't read endorsement file %s\n",
           __func__,
           __LINE__,
           err.c_str());
    return false;
  }

  *n = 3;
  return true;
}

#if 0
// General initialization for sev enclave
bool get_sev_enclave_parameters(string** s, int* n) {

  // ark cert file, ask cert file, vcek cert file
  string *args = new string[3];
  if (args == nullptr) {
    return false;
  }
  *s = args;

  if (!read_file_into_string(FLAGS_data_dir + FLAGS_ark_cert_file, &args[0])) {
        printf("%s() error, line %d, Can't read attest file\n",
           __func__,
           __LINE__);
    return false;
  }

  if (!read_file_into_string(FLAGS_data_dir + FLAGS_ask_cert_file, &args[1])) {
        printf("%s() error, line %d, Can't read measurement file\n",
           __func__,
           __LINE__);
    return false;
  }

  if (!read_file_into_string(FLAGS_data_dir + FLAGS_vcek_cert_file, &args[2])) {
        printf("%s() error, line %d, Can't read endorsement file\n",
           __func__,
           __LINE__);
    return false;
  }

  *n = 3;
  return true;
}
#endif

int main(int an, char **av) {
  gflags::ParseCommandLineFlags(&an, &av, true);
  an = 1;
  ::testing::InitGoogleTest(&an, av);

  if (FLAGS_operation == "") {
    printf(
        "multidomain_client_app.exe --print_all=true|false --operation=op\n");
    printf("\t--primary_policy_host=policy-host-address "
           "--primary_policy_port=policy-host-port\n");
    printf("\t--secondary_policy_host=policy-host-address "
           "--secondary_policy_port=policy-host-port\n");
    printf("\t--data_dir=-directory-for-app-data\n");
    printf("\t--server_app_host=my-server-host-address "
           "--server_app_port=server-host-port\n");
    printf("\t--policy_cert_file=self-signed-policy-cert-file-name "
           "--policy_store_file=policy-store-file-name\n");
    printf("Operations are: cold-init, get-certified, run-app-as-client\n");
    return 0;
  }

  SSL_library_init();
  string enclave_type("simulated-enclave");
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
    return 1;
  }

  // Get parameters
  int     n = 0;
  string *params = nullptr;
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

  // Standard algorithms for the enclave
  string public_key_alg(Enc_method_rsa_2048);
  string symmetric_key_alg(Enc_method_aes_256_cbc_hmac_sha256);

  // Carry out operation
  int ret = 0;
  if (FLAGS_operation == "cold-init") {
    if (!trust_mgr->cold_init(public_key_alg,
                              symmetric_key_alg,
                              "simple-app-client-home-domain",
                              FLAGS_primary_policy_host,
                              FLAGS_primary_policy_port,
                              FLAGS_server_app_host,
                              FLAGS_server_app_port)) {
      printf("%s() error, line %d, cold-init failed\n", __func__, __LINE__);
      ret = 1;
      goto done;
    }
    // Debug
    trust_mgr->print_trust_data();
  } else if (FLAGS_operation == "get-certified") {

    // Certifier in home domain and server domain

    if (!trust_mgr->warm_restart()) {
      printf("%s() error, line %d, warm-restart failed\n", __func__, __LINE__);
      ret = 1;
      goto done;
    }

    printf("Certifying primary domain\n");
    certifiers *cd = trust_mgr->certified_domains_[0];
    cd->print_certifiers_entry();

    if (!trust_mgr->certify_me()) {
      printf("%s() error, line %d, certification failed\n", __func__, __LINE__);
      ret = 1;
      goto done;
    }
    // Debug
    // trust_mgr->print_trust_data();

    // now server domain
    string server_domain_name = "simple-app-server-home-domain";
    string server_cert_file_name(FLAGS_data_dir);
    server_cert_file_name.append(FLAGS_secondary_cert_file);
    string server_domain_cert;
    if (!read_file_into_string(server_cert_file_name, &server_domain_cert)) {
      printf("%s() error, line %d, Can't read secondary cert file %s\n",
             __func__,
             __LINE__,
             FLAGS_secondary_cert_file.c_str());
      ret = 1;
      goto done;
    }
    int    server_port = FLAGS_secondary_policy_port;
    string server_host = FLAGS_secondary_policy_host;
    string server_service_host = FLAGS_server_app_host;
    int    server_service_port = FLAGS_server_app_port;

    if (!trust_mgr->add_or_update_new_domain(server_domain_name,
                                             server_domain_cert,
                                             server_host,
                                             server_port,
                                             server_service_host,
                                             server_service_port)) {
      printf("%s() error, line %d, Can't add_or_update_new_domain\n",
             __func__,
             __LINE__);
      ret = 1;
      goto done;
    }

    printf("Certifying secondary domain\n");
    cd = trust_mgr->certified_domains_[1];
    cd->print_certifiers_entry();


    if (!trust_mgr->certify_secondary_domain(server_domain_name)) {
      printf("%s() error, line %d, secondary certification failed\n",
             __func__,
             __LINE__);
      ret = 1;
      goto done;
    }
  } else if (FLAGS_operation == "run-app-as-client") {

    printf("Running App as client\n");

    string                       my_role("client");
    secure_authenticated_channel channel(my_role);

    if (!trust_mgr->warm_restart()) {
      printf("%s() error, line %d, warm-restart failed\n", __func__, __LINE__);
      ret = 1;
      goto done;
    }

    if (!trust_mgr->cc_auth_key_initialized_
        || !trust_mgr->cc_policy_info_initialized_) {
      printf("%s() error, line %d, trust data not initialized\n",
             __func__,
             __LINE__);
      ret = 1;
      goto done;
    }
    printf("warm restart completed\n");

    // Use certified_domain[1] here
    certifiers *cd = trust_mgr->certified_domains_[1];
    if (!cd->is_certified_) {
      printf("%s() error, line %d, secondary admissions cert not valid\n",
             __func__,
             __LINE__);
      ret = 1;
      goto done;
    }

    printf("Certifiers data for secondary domain:\n");
    cd->print_certifiers_entry();
    printf("\n");

    if (!channel.init_client_ssl(cd->service_host_,
                                 cd->service_port_,
                                 cd->domain_policy_cert_,
                                 trust_mgr->private_auth_key_,
                                 cd->admissions_cert_)) {
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
    printf("%s() error, line %d, client only app\n", __func__, __LINE__);
    ret = 1;
    goto done;
  } else {
    printf("%s() error, line %d, Unknown operation\n", __func__, __LINE__);
  }

done:
  // trust_mgr->print_trust_data();
  trust_mgr->clear_sensitive_data();
  if (trust_mgr != nullptr) {
    delete trust_mgr;
  }
  return ret;
}
