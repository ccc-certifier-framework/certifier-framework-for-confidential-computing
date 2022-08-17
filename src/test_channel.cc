#include <gtest/gtest.h>
#include <gflags/gflags.h>

#include "support.h"
#include "certifier.h"
#include "simulated_enclave.h"
#include "cc_helpers.h"

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include  <netdb.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/err.h>

//  Copyright (c) 2021-22, VMware Inc, and the Certifier Authors.  All rights reserved.
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


// operations are: cold-init, warm-restart, get-certifier, run-app-as-client, run-app-as-server
DEFINE_bool(print_all, false,  "verbose");
DEFINE_string(operation, "server", "operation");

DEFINE_string(policy_host, "localhost", "address for server");
DEFINE_int32(port, 8124, "port for server");

DEFINE_string(policy_cert_file, "policy_cert.bin", "policy cert file");
DEFINE_string(policy_key_file, "policy_key.bin", "policy key file");
DEFINE_string(auth_key_file, "auth_key.bin", "auth key file");


// ----------------------------------------------------------------------------------

#define DEBUG


void server_application(secure_authenticated_channel& channel) {

  // Read message from client over authenticated, encrypted channel
  string out;
  int n = channel.read(&out);
  printf("SSL server read: %s\n", (const char*) out.data());

  // Reply over authenticated, encrypted channel
  const char* msg = "Hi from your secret server\n";
  channel.write(strlen(msg), (byte*)msg);
}

bool run_me_as_server(const string& host_name, int port,
      string& asn1_policy_cert, key_message& private_key) {

  X509* x509_policy_cert = X509_new();
  if (!asn1_to_x509(asn1_policy_cert, x509_policy_cert)) {
    printf("Can't parse policy cert\n");
    return false;
  }

  server_dispatch(host_name, port, asn1_policy_cert, private_key,
      server_application);
  return true;
}

void client_application(secure_authenticated_channel& channel) {

  // client sends a message over authenticated, encrypted channel
  const char* msg = "Hi from your secret client\n";
  channel.write(strlen(msg), (byte*)msg);

  // Get server response over authenticated, encrypted channel and print it
  string out;
  int n = channel.read(&out);
  printf("SSL client read: %s\n", out.data());
}

bool run_me_as_client( const string& host_name, int port,
      string& asn1_policy_cert, key_message& private_key) {

  string my_role("client");
  secure_authenticated_channel channel(my_role);
  if (!channel.init_client_ssl(host_name, port, asn1_policy_cert, private_key)) {
    printf("Can't init client app\n");
    return false;
  }

  // This is the actual application code.
  client_application(channel);
  return true;
}

// ------------------------------------------------------------------------------------------

int main(int an, char** av) {
  gflags::ParseCommandLineFlags(&an, &av, true);
  an = 1;
  ::testing::InitGoogleTest(&an, av);

  if (FLAGS_operation == "") {
    printf("example_app.exe --print_all=true|false --operation=op --policy_host=policy-host-address --policy_port=policy-host-port\n");
    printf("\t --data_dir=-directory-for-app-data --server_app_host=my-server-host-address --server_app_port=server-host-port\n");
    printf("\t --policy_cert_file=self-signed-policy-cert-file-name --policy_store_file=policy-store-file-name\n");
    printf("Operations are: cold-init, warm-restart, get-certifier, run-app-as-client, run-app-as-server\n");
    return 0;
  }

  SSL_library_init();

  // read in policy key and my key
  key_message policy_key;
  key_message auth_key;
  X509* policy_cert = nullptr;

  int sz = file_size(FLAGS_policy_cert_file);
  byte policy_cert_buf[sz];
  if (!read_file(FLAGS_policy_cert_file, &sz, policy_cert_buf)) {
    printf("Can't read policy cert\n");
    return 1;
  }
  string str_policy_cert;
  str_policy_cert.assign((char*)policy_cert_buf, sz);

  // policy_key_file
  sz = file_size(FLAGS_policy_key_file);
  byte policy_key_buf[sz];
  if (!read_file(FLAGS_policy_key_file, &sz, policy_key_buf)) {
    printf("Can't read policy key\n");
    return 1;
  }
  string str_policy_key;
  str_policy_key.assign((char*)policy_key_buf, sz);

  // auth_key_file
  sz = file_size(FLAGS_auth_key_file);
  byte auth_key_buf[sz];
  if (!read_file(FLAGS_auth_key_file, &sz, auth_key_buf)) {
    printf("Can't read auth key\n");
    return 1;
  }
  string str_auth_key;
  str_auth_key.assign((char*)auth_key_buf, sz);

  policy_cert = X509_new();
  if (!asn1_to_x509(str_policy_cert, policy_cert)) {
    printf("Can't translate cert\n");
    return 1;
  }
  if (!policy_key.ParseFromString(str_policy_key)) {
    printf("Can't parse policy key\n");
    return 1;
  }
  if (!auth_key.ParseFromString(str_auth_key)) {
    printf("Can't parse auth key\n");
    return 1;
  }

  if (FLAGS_operation == "client") {
    if (!run_me_as_client(FLAGS_policy_host.c_str(), FLAGS_port,
          str_policy_cert, auth_key)) {
      printf("run-me-as-client failed\n");
      return 1;
    }
  } else if (FLAGS_operation == "server") {
    if (!run_me_as_server( FLAGS_policy_host.c_str(), FLAGS_port,
          str_policy_cert, auth_key)) {
      printf("server failed\n");
      return 1;
    }
  } else {
    printf("Unknown operation\n");
  }

  return 0;
}
