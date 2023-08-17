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

#include "support.h"
#include "certifier.h"
#include "simulated_enclave.h"
#include "cc_helpers.h"

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

using namespace certifier::framework;
using namespace certifier::utilities;

// operations are: client, server
DEFINE_bool(print_all, false, "verbose");
DEFINE_string(operation, "server", "operation");

DEFINE_string(app_host, "localhost", "address for server");
DEFINE_int32(app_port, 8124, "port for server");

DEFINE_string(data_dir, "./test_data/", "directory for files");
DEFINE_string(policy_cert_file, "policy_cert_file.bin", "policy cert file");
DEFINE_string(policy_key_file, "policy_key_file.bin", "policy key file");
DEFINE_string(auth_key_file, "auth_key_file.bin", "auth key file");


// ----------------------------------------------------------------------------------

#define DEBUG

void server_application(secure_authenticated_channel &channel) {

  printf("Server peer id is %s\n", channel.peer_id_.c_str());

  // Read message from client over authenticated, encrypted channel
  string out;
  int    n = channel.read(&out);
  printf("SSL server read: %s\n", (const char *)out.data());

  // Reply over authenticated, encrypted channel
  const char *msg = "Hi from your secret server\n";
  channel.write(strlen(msg), (byte *)msg);
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

void client_application(secure_authenticated_channel &channel) {

  printf("Client peer id is %s\n", channel.peer_id_.c_str());

  // client sends a message over authenticated, encrypted channel
  const char *msg = "Hi from your secret client\n";
  channel.write(strlen(msg), (byte *)msg);

  // Get server response over authenticated, encrypted channel and print it
  string out;
  int    n = channel.read(&out);
  printf("SSL client read: %s\n", out.data());
}

bool run_me_as_client(const string &host_name,
                      int           port,
                      string &      asn1_policy_cert,
                      key_message & private_key,
                      string &      private_key_cert) {

  printf("running as client\n");
  string                       my_role("client");
  secure_authenticated_channel channel(my_role);
  if (!channel.init_client_ssl(host_name,
                               port,
                               asn1_policy_cert,
                               private_key,
                               private_key_cert)) {
    printf("Can't init client app\n");
    return false;
  }

  // This is the actual application code.
  client_application(channel);
  return true;
}

bool make_admissions_cert(const string &role,
                          key_message & policy_key,
                          key_message & auth_key,
                          string *      out) {
  string issuer_name("policyAuthority");
  string issuer_organization("root");
  string subject_name(role);
  string subject_organization("1234567890");

  X509 *x509_cert = X509_new();
  if (!produce_artifact(policy_key,
                        issuer_name,
                        issuer_organization,
                        auth_key,
                        subject_name,
                        subject_organization,
                        23,
                        365.26 * 86400.0,
                        x509_cert,
                        false)) {
    return false;
  }
  if (!x509_to_asn1(x509_cert, out)) {
    return false;
  }
  return true;
}

// ------------------------------------------------------------------------------------------

int main(int an, char **av) {
  gflags::ParseCommandLineFlags(&an, &av, true);
  an = 1;
  ::testing::InitGoogleTest(&an, av);

  if (FLAGS_operation == "") {
    printf("test_channel.exe --print_all=true|false --operation=op "
           "--app_host=policy-host-address --app_port=policy-host-port\n");
    printf("\t --policy_cert_file=self-signed-policy-cert-file-name "
           "--policy_store_file=policy-store-file-name\n");
    printf("Operations are: client, server\n");
    return 0;
  }

  SSL_library_init();

  // read in policy key and my key
  key_message policy_key;
  key_message auth_key;
  X509 *      policy_cert = nullptr;

  string policy_cert_file(FLAGS_data_dir);
  policy_cert_file.append(FLAGS_policy_cert_file);
  int sz = file_size(policy_cert_file);
  if (sz < 0) {
    printf("Can't find policy cert\n");
    return 1;
  }
  byte policy_cert_buf[sz];
  if (!read_file(policy_cert_file, &sz, policy_cert_buf)) {
    printf("Can't read policy cert\n");
    return 1;
  }
  string str_policy_cert;
  str_policy_cert.assign((char *)policy_cert_buf, sz);

  // policy_key_file
  string policy_key_file(FLAGS_data_dir);
  policy_key_file.append(FLAGS_policy_key_file);
  sz = file_size(policy_key_file);
  if (sz < 0) {
    printf("Can't find policy key %s\n", policy_key_file.c_str());
    return 1;
  }
  byte policy_key_buf[sz];
  if (!read_file(policy_key_file, &sz, policy_key_buf)) {
    printf("Can't read policy key %s\n", policy_key_file.c_str());
    return 1;
  }
  string str_policy_key;
  str_policy_key.assign((char *)policy_key_buf, sz);

  // auth_key_file
  string auth_key_file(FLAGS_data_dir);
  auth_key_file.append(FLAGS_auth_key_file);
  sz = file_size(auth_key_file);
  if (sz < 0) {
    printf("Can't find auth key\n");
    return 1;
  }
  byte auth_key_buf[sz];
  if (!read_file(auth_key_file, &sz, auth_key_buf)) {
    printf("Can't read auth key\n");
    return 1;
  }
  string str_auth_key;
  str_auth_key.assign((char *)auth_key_buf, sz);

  policy_cert = X509_new();
  if (!asn1_to_x509(str_policy_cert, policy_cert)) {
    printf("Can't translate cert\n");
    return 1;
  }
  if (!policy_key.ParseFromString(str_policy_key)) {
    printf("Can't parse policy key\n");
    return 1;
  }
  policy_key.set_certificate((byte *)str_policy_cert.data(),
                             str_policy_cert.size());
  if (!auth_key.ParseFromString(str_auth_key)) {
    printf("Can't parse auth key\n");
    return 1;
  }

  // make admissions cert
  string auth_cert;
  if (!make_admissions_cert(FLAGS_operation,
                            policy_key,
                            auth_key,
                            &auth_cert)) {
    printf("Can't make admissions cert\n");
    return 1;
  }
  auth_key.set_certificate(auth_cert);

#ifdef DEBUG
  X509 *x509_auth_cert = X509_new();
  asn1_to_x509(auth_cert, x509_auth_cert);
  printf("\npolicy cert:\n");
  X509_print_fp(stdout, policy_cert);
  printf("\nAdmissions cert:\n");
  X509_print_fp(stdout, x509_auth_cert);
  printf("\nPolicy key::\n");
  print_key(policy_key);
#endif

  if (FLAGS_operation == "client") {
    if (!run_me_as_client(FLAGS_app_host.c_str(),
                          FLAGS_app_port,
                          str_policy_cert,
                          auth_key,
                          auth_cert)) {
      printf("run-me-as-client failed\n");
      return 1;
    }
  } else if (FLAGS_operation == "server") {
    if (!run_me_as_server(FLAGS_app_host.c_str(),
                          FLAGS_app_port,
                          str_policy_cert,
                          auth_key,
                          auth_cert)) {
      printf("server failed\n");
      return 1;
    }
  } else {
    printf("Unknown operation\n");
  }

  return 0;
}
