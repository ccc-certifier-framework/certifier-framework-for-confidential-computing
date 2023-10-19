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

DEFINE_string(test_case, "test1", "test1");
DEFINE_string(cert_chain1, "cert_chain1.bin", "First certificate chain");
DEFINE_string(cert_chain2, "cert_chain2.bin", "Second certificate chain");


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
  channel.close();
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
  channel.close();
}

bool run_me_as_server(const string &host_name,
                      int           port,
                      const string &asn1_root_cert,
                      const string &asn1_peer_root_cert,
                      int           num_certs,
                      string *      cert_chain,
                      key_message & private_key,
                      string &      private_key_cert) {

  printf("running as server\n");

  return server_dispatch(host_name,
                         port,
                         asn1_root_cert,
                         asn1_peer_root_cert,
                         num_certs,
                         cert_chain,
                         private_key,
                         private_key_cert,
                         server_application);
}

bool run_me_as_client(const string &host_name,
                      int           port,
                      const string &asn1_root_cert,
                      const string &peer_asn1_root_cert,
                      int           cert_chain_length,
                      string *      der_certs,
                      key_message & private_key,
                      const string &auth_cert) {

  printf("running as client\n");
  string                       my_role("client");
  secure_authenticated_channel channel(my_role);
  if (!channel.init_client_ssl(host_name,
                               port,
                               asn1_root_cert,
                               peer_asn1_root_cert,
                               cert_chain_length,
                               der_certs,
                               private_key,
                               auth_cert)) {
    printf("Can't init client app\n");
    return false;
  }

  // This is the actual application code.
  client_application(channel);
  return true;
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

bool make_admissions_cert(const string &     role,
                          const key_message &policy_key,
                          const key_message &auth_key,
                          string *           out) {
  string issuer_name("policyAuthority");
  string issuer_organization("root");
  string subject_name(role);
  string subject_organization("1234567890");

  X509 *x509_cert = X509_new();
  if (!produce_artifact((key_message &)policy_key,
                        issuer_name,
                        issuer_organization,
                        (key_message &)auth_key,
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

  if (FLAGS_test_case == "test1") {
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
      printf("unknown operation\n");
      return 1;
    }
  } else if (FLAGS_test_case == "test2") {
    full_cert_chain chain1;
    full_cert_chain chain2;

    string str_chain1;
    string str_chain2;

    if (!read_file_into_string(FLAGS_cert_chain1, &str_chain1)) {
      printf("Can't read %s\n", FLAGS_cert_chain1.c_str());
      return 1;
    }

    if (!read_file_into_string(FLAGS_cert_chain2, &str_chain2)) {
      printf("Can't read %s\n", FLAGS_cert_chain2.c_str());
      return 1;
    }

    if (!chain1.ParseFromString(str_chain1)) {
      printf("Can't parse chain 1\n");
      return 1;
    }
    if (!chain2.ParseFromString(str_chain2)) {
      printf("Can't parse chain 2\n");
      return 1;
    }

    // There should only be two
    if (chain1.list_size() != 2) {
      printf("Invalid client chain size\n");
      return 1;
    }
    if (chain2.list_size() != 2) {
      printf("Invalid server chain size\n");
      return 1;
    }

    // subject_key, signer_key, der_cert
    const key_message &client_root_key = chain1.list(0).signer_key();
    const key_message &client_public_key = chain1.list(1).subject_key();
    key_message        client_private_key;
    client_private_key.CopyFrom(chain1.final_private_key());
    string client_root_cert;
    string client_auth_cert;

    const key_message &server_root_key = chain2.list(0).signer_key();
    const key_message &server_public_key = chain2.list(1).subject_key();
    key_message        server_private_key;
    server_private_key.CopyFrom(chain2.final_private_key());
    string server_root_cert;
    string server_auth_cert;

    client_root_cert.assign((char *)chain1.list(0).der_cert().data(),
                            chain1.list(0).der_cert().size());
    client_auth_cert.assign((char *)chain1.list(1).der_cert().data(),
                            chain1.list(1).der_cert().size());
    server_root_cert.assign((char *)chain2.list(0).der_cert().data(),
                            chain2.list(0).der_cert().size());
    server_auth_cert.assign((char *)chain2.list(1).der_cert().data(),
                            chain2.list(1).der_cert().size());
    client_private_key.set_certificate(client_auth_cert);
    server_private_key.set_certificate(server_auth_cert);

    int    cert_chain_length = 0;
    string der_certs[4];

#ifdef DEBUG
    printf("\nclient root cert:\n");
    X509 *x509_client_root_cert = X509_new();
    asn1_to_x509(client_root_cert, x509_client_root_cert);
    X509_print_fp(stdout, x509_client_root_cert);
    X509 *x509_server_root_cert = X509_new();
    asn1_to_x509(server_root_cert, x509_server_root_cert);
    printf("\nserver root cert:\n");
    X509_print_fp(stdout, x509_server_root_cert);
    X509 *x509_client_auth_cert = X509_new();
    asn1_to_x509(client_auth_cert, x509_client_auth_cert);
    printf("\nClient auth cert:\n");
    X509_print_fp(stdout, x509_client_auth_cert);
    X509 *x509_server_auth_cert = X509_new();
    asn1_to_x509(server_auth_cert, x509_server_auth_cert);
    printf("\nServer auth cert:\n");
    X509_print_fp(stdout, x509_server_auth_cert);
    printf("\nClient auth key::\n");
    print_key(client_private_key);
    printf("\nServer auth key::\n");
    print_key(server_private_key);
#endif

    if (FLAGS_operation == "client") {
      if (!run_me_as_client(FLAGS_app_host.c_str(),
                            FLAGS_app_port,
                            client_root_cert,
                            server_root_cert,
                            cert_chain_length,
                            der_certs,
                            (key_message &)client_private_key,
                            client_auth_cert)) {
        printf("run-me-as-client failed\n");
        return 1;
      }
    } else if (FLAGS_operation == "server") {
      if (!run_me_as_server(FLAGS_app_host.c_str(),
                            FLAGS_app_port,
                            server_root_cert,
                            client_root_cert,
                            cert_chain_length,
                            der_certs,
                            (key_message &)server_private_key,
                            server_auth_cert)) {
        printf("server failed\n");
        return 1;
      }
    } else {
      printf("Unknown operation\n");
      return 1;
    }
  } else {
    printf("Unknown test case\n");
  }

  return 0;
}
