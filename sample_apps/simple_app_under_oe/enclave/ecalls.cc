#include <stdio.h>
#include <sys/mount.h>
#include <openssl/rand.h>
#include <openenclave/enclave.h>
#include <openenclave/attestation/attester.h>
#include <openenclave/attestation/custom_claims.h>
#include <openenclave/attestation/verifier.h>
#include <openenclave/bits/report.h>
#include <openenclave/bits/module.h>

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

#include "certifier_framework.h"
#include "certifier_utilities.h"
#include "../policy_key.cc"

using namespace certifier::framework;
using namespace certifier::utilities;

#define FLAGS_print_all true
#define FLAGS_operation ""
#define FLAGS_policy_host "localhost"
#define FLAGS_policy_port 8123
#define FLAGS_server_app_host "localhost"
#define FLAGS_server_app_port 8124
static string data_dir = "app1_data";

#define FLAGS_policy_store_file "store.bin"
#define FLAGS_certificate_file "vse.crt"

static std::string enclave_type; 
cc_trust_data* app_trust_data = nullptr;

static bool oe_initialized = false;
static bool openenclave_initialized = false;
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

// Standard algorithms for the enclave
string public_key_alg("rsa-2048");
string symmetric_key_alg("aes-256-cbc-hmac-sha256");

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

extern "C"
{
  bool openenclave_init(void);
  bool certifier_init(char*, size_t);

  bool cold_init(void);
  bool certify_me(void);
  bool warm_restart(void);
  bool run_me_as_client(void);
  bool run_me_as_server(void);
}

bool openenclave_init(void){
  oe_result_t result = OE_OK;
  result = oe_load_module_host_file_system();
  if (result != OE_OK) {
      printf("Failed to load host file system module: %s\n", oe_result_str(result));
      return false;
  }
  if (mount("/", "/", OE_HOST_FILE_SYSTEM, 0, NULL) != 0) {
      printf("Failed to mount host file system\n");
      return false;
  }

  result = oe_load_module_host_socket_interface();
    if (result != OE_OK) {
      printf("Failed to load socket module: %s\n", oe_result_str(result));
      return false;
  }

  result = oe_load_module_host_resolver();
    if (result != OE_OK) {
      printf("Failed to load resolver module: %s\n", oe_result_str(result));
      return false;
  }
  openenclave_initialized = true;

  return true;
}

bool certifier_init(char* usr_data_dir, size_t usr_data_dir_size) {
  oe_result_t result = OE_OK;
  static const char rnd_seed[] =
    "string to make the random number generator think it has entropy";

  RAND_seed(rnd_seed, sizeof rnd_seed);
  std::string usr_data = usr_data_dir;
  data_dir =  usr_data + "/";
  printf("Using data_dir: %s\n", data_dir.c_str());

  if(!openenclave_initialized){
    openenclave_init();
  }

  // Initialize attester and use the plugin.
  result = oe_attester_initialize();
  if (result != OE_OK)
  {
      printf("oe_attester_initialize failed.\n");
      return false;
  }
  // Initialize verifier and use the plugin.
  result = oe_verifier_initialize();
  if (result != OE_OK)
  {
      printf("oe_verifier_initialize failed.\n");
      return false;
  }

  if (!oe_initialized) {
    SSL_library_init();
    string enclave_type("oe-enclave");
    string purpose("authentication");

    string store_file(data_dir);
    store_file.append(FLAGS_policy_store_file);
    app_trust_data = new cc_trust_data(enclave_type, purpose, store_file);
    if (app_trust_data == nullptr) {
      printf("couldn't initialize trust object\n");
      return false;
    }

    // Init policy key info
    if (!app_trust_data->init_policy_key(initialized_cert_size, initialized_cert)) {
      printf("Can't init policy key\n");
      return false;
    }

    string cert(data_dir);
    cert.append(FLAGS_certificate_file);
    if (!app_trust_data->initialize_oe_enclave_data(cert)) {
      printf("Can't init OE enclave\n");
      return false;
    }

    oe_initialized = true;
  }

  return true;
}

void clear_sensitive_data() {
  // TODO: clear symmetric and private keys
  //    Not necessary on most platforms
}

bool cold_init() {
  return app_trust_data->cold_init(public_key_alg, symmetric_key_alg);
}

bool warm_restart() {
  return app_trust_data->warm_restart();
}

// TODO: replace with new cc_trust_data interface
bool certify_me() {
  return app_trust_data->certify_me(FLAGS_policy_host, FLAGS_policy_port);
}

void server_application(secure_authenticated_channel& channel) {

  printf("Server peer id is %s\n", channel.peer_id_.c_str());
  if (channel.peer_cert_ != nullptr) {
    printf("Server peer cert is:\n");
#ifdef DEBUG
    X509_print_fp(stdout, channel.peer_cert_);
#endif
  }

  // Read message from client over authenticated, encrypted channel
  string out;
  int n = channel.read(&out);
  printf("SSL server read: %s\n", (const char*) out.data());

  // Reply over authenticated, encrypted channel
  const char* msg = "Hi from your secret server\n";
  channel.write(strlen(msg), (byte*)msg);
}

bool run_me_as_server() {
  if (!app_trust_data->warm_restart()) {
    printf("warm-restart failed\n");
    return false;
  }
  printf("running as server\n");
  server_dispatch(FLAGS_server_app_host, FLAGS_server_app_port,
      app_trust_data->serialized_policy_cert_,
        app_trust_data->private_auth_key_,
        app_trust_data->private_auth_key_.certificate(),
        server_application);
  return true;
}

void client_application(secure_authenticated_channel& channel) {

  printf("Client peer id is %s\n", channel.peer_id_.c_str());
  if (channel.peer_cert_ != nullptr) {
    printf("Client peer cert is:\n");
#ifdef DEBUG
    X509_print_fp(stdout, channel.peer_cert_);
#endif
  }

  // client sends a message over authenticated, encrypted channel
  const char* msg = "Hi from your secret client\n";
  channel.write(strlen(msg), (byte*)msg);

  // Get server response over authenticated, encrypted channel and print it
  string out;
  int n = channel.read(&out);
  printf("SSL client read: %s\n", out.data());
}

bool run_me_as_client() {
  if (!app_trust_data->warm_restart()) {
    printf("warm-restart failed\n");
    return false;
  }
  printf("running as client\n");
  if (!app_trust_data->cc_auth_key_initialized_ ||
      !app_trust_data->cc_policy_info_initialized_) {
    printf("trust data not initialized\n");
    return false;
  }
  string my_role("client");
  secure_authenticated_channel channel(my_role);
  if (!channel.init_client_ssl(FLAGS_server_app_host, FLAGS_server_app_port,
        app_trust_data->serialized_policy_cert_,
        app_trust_data->private_auth_key_,
        app_trust_data->private_auth_key_.certificate())) {
    printf("Can't init client app\n");
    return false;
  }

  // This is the actual application code.
  client_application(channel);
  return true;
}
