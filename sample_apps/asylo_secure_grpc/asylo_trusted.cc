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

#include <iostream>

#include "support.h"
#include "certifier.h"
#include "simulated_enclave.h"
#include "application_enclave.h"
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

#include "src/asylo/asylo_api.h"

#include "policy_key.cc"

#define FLAGS_print_all true
static string measurement_file("/tmp/binary_trusted_measurements_file.bin");
#define FLAGS_trusted_measurements_file measurement_file
#define FLAGS_read_measurement_file true
#define FLAGS_operation ""
#define FLAGS_client_address "localhost"
#define FLAGS_server_address "localhost"
#define FLAGS_policy_host "localhost"
#define FLAGS_policy_port 8123
#define FLAGS_server_app_host "localhost"
//#define FLAGS_server_app_port 8124
#define FLAGS_server_app_port 39431
static string data_dir = "./app1_data/";

#define FLAGS_policy_store_file "store.bin"
#define FLAGS_platform_file_name "platform_file.bin" 
#define FLAGS_platform_attest_endorsement "platform_attest_endorsement.bin"
#define FLAGS_attest_key_file "attest_key_file.bin" 
#define FLAGS_policy_cert_file "policy_cert_file.bin"
#define FLAGS_measurement_file "example_app.measurement"

static std::string enclave_type; 

cc_trust_data* app_trust_data = nullptr;

static bool simulator_initialized = false;
bool test_local_certify(string& enclave_type,
       bool init_from_file, string& file_name,
       string& evidence_descriptor);


bool trust_data_initialized = false;
key_message privatePolicyKey;
key_message publicPolicyKey;
string serializedPolicyCert;
X509* policy_cert= nullptr;

policy_store pStore;
key_message privateAppKey;
key_message publicAppKey;
const int app_symmetric_key_size = 64;
byte app_symmetric_key[app_symmetric_key_size];
key_message symmertic_key_for_protect;

void print_trust_data() {
  if (!trust_data_initialized)
    return;
  printf("\nTrust data:\n");
  printf("\nPolicy key\n");
  print_key(publicPolicyKey);
  printf("\nPolicy cert\n");
  print_bytes(serializedPolicyCert.size(), (byte*)serializedPolicyCert.data());
  printf("\n");
  printf("\nPrivate app auth key\n");
  print_key(privateAppKey);
  printf("\nPublic app auth key\n");
  print_key(publicAppKey);
  printf("\nBlob key\n");
  print_key(symmertic_key_for_protect);
  printf("\n\n");
}

bool certifier_test_seal(void) {
  string enclave_type("asylo-enclave");
  string enclave_id("local-machine");

  int secret_to_seal_size = 32;
  byte secret_to_seal[secret_to_seal_size];
  int sealed_size_out = 1024;
  byte sealed[sealed_size_out];
  int recovered_size = 32;
  byte recovered[recovered_size];

  memset(sealed, 0, sealed_size_out);
  memset(recovered, 0, recovered_size);
  for (int i = 0; i < secret_to_seal_size; i++)
    secret_to_seal[i]= (7 * i)%16;

  if (FLAGS_print_all) {
    printf("\nSeal\n");
    printf("to seal  (%d): ", secret_to_seal_size); print_bytes(secret_to_seal_size, secret_to_seal); printf("\n");
  }

  if (!Seal(enclave_type, enclave_id, secret_to_seal_size, secret_to_seal, &sealed_size_out, sealed))
    return false;

  if (FLAGS_print_all) {
    printf("sealed   (%d): ", sealed_size_out); print_bytes(sealed_size_out, sealed); printf("\n");
  }

  if (!Unseal(enclave_type, enclave_id, sealed_size_out, sealed, &recovered_size, recovered))
    return false;

  if (FLAGS_print_all) {
    printf("recovered: (%d)", recovered_size); print_bytes(recovered_size, recovered); printf("\n");
  }

  return true;
}

bool asylo_local_certify() {
  string enclave_type("asylo-enclave");
  string evidence_descriptor("asylo-evidence");
  extern bool simulator_init(void);
  if (!simulator_initialized) {
    if (!simulator_init()) {
      return false;
    }
    simulator_initialized = true;
  }

  if (!test_local_certify(enclave_type,
    FLAGS_read_measurement_file,
    FLAGS_trusted_measurements_file,
    evidence_descriptor)) {
    printf("test_local_certify failed\n");
    return false;
  }

  simulator_initialized = false;
  return true;
}

bool asylo_seal() {
  if (!certifier_test_seal()) {
    printf("Sealing test failed\n");
    return false;
  }
  printf("Sealing test succeeded\n");
  return true;
}

bool asylo_setup_certifier_functions(AsyloCertifierServerFunctions asyloFuncs) {
  setFuncs(asyloFuncs);
  return true;
}

bool certifier_init(char* usr_data_dir, size_t usr_data_dir_size) {
  static const char rnd_seed[] =
    "string to make the random number generator think it has entropy";

  RAND_seed(rnd_seed, sizeof rnd_seed);
  std::string usr_data = usr_data_dir;
  data_dir =  usr_data + "/";
  printf("Using data_dir: %s\n", data_dir.c_str());

  if (simulator_initialized) {
    return true;
  }

  SSL_library_init();
  printf("Done SSL init\n");

  string enclave_type("simulated-enclave");
  string purpose("authentication");

  string store_file(data_dir);
  store_file.append(FLAGS_policy_store_file);

  app_trust_data = new cc_trust_data(enclave_type, purpose, store_file);
  if (app_trust_data == nullptr) {
    printf("couldn't initialize trust object\n");
    return 1;
  }

  // Init policy key info
  if (!app_trust_data->init_policy_key(initialized_cert_size,
                                       initialized_cert)) {
    printf("Can't init policy key\n");
    return false;
  }

  // Init simulated enclave
  string attest_key_file_name(data_dir);
  attest_key_file_name.append(FLAGS_attest_key_file);
  string platform_attest_file_name(data_dir);
  platform_attest_file_name.append(FLAGS_platform_attest_endorsement);
  string measurement_file_name(data_dir);
  measurement_file_name.append(FLAGS_measurement_file);
  string attest_endorsement_file_name(data_dir);
  attest_endorsement_file_name.append(FLAGS_platform_attest_endorsement);

  if (!app_trust_data->initialize_simulated_enclave_data(attest_key_file_name,
      measurement_file_name, attest_endorsement_file_name)) {
    printf("Can't init simulated enclave\n");
    return false;
  }

  simulator_initialized = true;  

  return true;
}

bool cold_init() {
  if (!app_trust_data->cold_init()) {
      printf("cold_init failed\n");
      return false;
    }

  return true;
}

bool warm_restart() {
  if (!app_trust_data->warm_restart()) {
      printf("warm_restart failed\n");
      return false;
    }

  return true;
}

bool certify_me() {
  printf("Begin certify_me\n");
  if (!app_trust_data->certify_me(FLAGS_policy_host, FLAGS_policy_port)) {
      printf("certify_me failed\n");
      return false;
    }
  return true;
}

void server_application(X509* x509_policy_cert, SSL* ssl, bool &connected) {
    printf("Server: running server_application, verify SSL accept now...\n");
  // accept and carry out auth
  int res = SSL_accept(ssl);
  if (res != 1) {
    char err[256];
    printf("Server: Can't SSL_accept connection\n");
    unsigned long code = ERR_get_error();
    printf("Accept error: %s\n", ERR_lib_error_string(code));
    print_ssl_error(SSL_get_error(ssl, res));
    ERR_error_string(res, err);
    printf("%s\n", err);
    SSL_free(ssl);
    connected = false;
    return;
  }
  int sd = SSL_get_fd(ssl);
#ifdef DEBUG
  printf("Accepted ssl connection using %s \n", SSL_get_cipher(ssl));
#endif

    // Verify a client certificate was presented during the negotiation
    X509* cert = SSL_get_peer_certificate(ssl);
    if(cert) {
      printf("Server: Peer cert presented in nego\n");
    } else {
      printf("Server: No peer cert presented in nego\n");
    }
  if (!client_auth_server(x509_policy_cert, ssl)) {
    printf("Client auth failed at server\n");
    connected = false;
    return;
  }

  connected = true;
  // Read message from client over authenticated, encrypted channel
  // Todo: use sized_read
  byte in[1024];
  memset(in, 0, 1024);
  int n = SSL_read(ssl, in, 1024);
  printf("SSL server read: %s\n", (const char*) in);

  // Reply over authenticated, encrypted channel
  const char* msg = "Hi from your secret server\n";
  SSL_write(ssl, (byte*)msg, strlen(msg));
  close(sd);
  SSL_free(ssl);
}

bool run_me_as_server(X509* x509_policy_cert, key_message& private_key, const string& host_name, int port) {

  SSL_load_error_strings();

  // Get a socket.
  int sock = -1;
  if (!open_server_socket(host_name, port, &sock)) {
    printf("Can't open server socket\n");
    return false;
  }

  // Set up TLS handshake data.
  SSL_METHOD* method = (SSL_METHOD*) TLS_server_method();
  SSL_CTX* ctx = SSL_CTX_new(method);
  if (ctx == NULL) {
    printf("SSL_CTX_new failed\n");
    return false;
  }
  X509_STORE* cs = SSL_CTX_get_cert_store(ctx);
  X509_STORE_add_cert(cs, x509_policy_cert);

  if (!load_server_certs_and_key(x509_policy_cert, private_key, ctx)) {
    printf("load_server_certs_and_key failed\n");
    return false;
  }

  const long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
  SSL_CTX_set_options(ctx, flags);

  // Verify peer
  // For debug: SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

  SSL_CTX_set_verify_depth(ctx, 4);
  unsigned int len = 0;
  bool connected = false;

  while (1) {
    if (connected) {
      break;
    }
    printf("asylo server at accept\n");
    struct sockaddr_in addr;
    int client = accept(sock, (struct sockaddr*)&addr, &len);
    printf("socket connection: accepted\n");

    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client);
    // This is the server application flow.
    server_application(x509_policy_cert, ssl, connected);
  }

  // Clean up.
  close(sock);
  SSL_CTX_free(ctx);
  return true;
}

bool setup_server_ssl() {
  bool ret = true;
    if (!app_trust_data->warm_restart()) {
      printf("warm-restart failed\n");
      ret = false;
      goto done;
    }
    if (!run_me_as_server(app_trust_data->x509_policy_cert_,
          app_trust_data->private_auth_key_,
          FLAGS_server_app_host, FLAGS_server_app_port)) {
      printf("run-me-as-server failed\n");
      ret = false;
      goto done;
    }

done:
  // app_trust_data->print_trust_data();
  app_trust_data->clear_sensitive_data();
  return ret;
}

void client_application(SSL* ssl) {
  // client sends a message over authenticated, encrypted channel
  const char* msg = "Hi from your secret client\n";
  printf("writing to SSL: %s\n");
  SSL_write(ssl, (byte*)msg, strlen(msg));

  // Get server response over authenticated, encrypted channel and print it
  // Todo: Replace with call to int sized_read(int fd, string* out)
  byte buf[1024];
  memset(buf, 0, 1024);
  int n = SSL_read(ssl, buf, 1024);
  printf("SSL client read: %s\n", (const char*)buf);
}

bool run_me_as_client(X509* x509_policy_cert, key_message& private_key,
      const string& host_name, int port) {

  SSL_load_error_strings();
  int sd = 0;
  SSL_CTX* ctx = nullptr;
  SSL* ssl = nullptr;

  // Set up socket (sd), ssl context and ssl channel.
  if (!init_client_ssl(x509_policy_cert, private_key, host_name, port, &sd, &ctx, &ssl)) {
    printf("init_client_ssl failed\n");
    return false;
  }

  printf("doing client_auth\n");

  // Authenticate client interaction (initiated by server after handshake)
  if (!client_auth_client(x509_policy_cert, private_key, ssl)) {
    printf("Client auth failed at client\n");
    return false;
  }

  printf("done auth, running app code\n");

  // This is the actual application code.
  client_application(ssl);

  // Clean up.
  close_client_ssl(sd, ctx, ssl);
  return true;
}

bool setup_client_ssl() {
  bool ret = true;
    if (!app_trust_data->warm_restart()) {
      printf("warm-restart failed\n");
      ret = false;
      goto done;
    }
    if (!run_me_as_client(app_trust_data->x509_policy_cert_,
          app_trust_data->private_auth_key_,
          FLAGS_server_app_host, FLAGS_server_app_port)) {
      printf("run-me-as-server failed\n");
      ret = false;
      goto done;
    }

done:
  // app_trust_data->print_trust_data();
  app_trust_data->clear_sensitive_data();
  return ret;
}
