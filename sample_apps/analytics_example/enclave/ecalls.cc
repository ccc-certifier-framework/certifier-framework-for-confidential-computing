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
#include "../policy_key.cc"

#include "analytics_app.cc"

using namespace certifier::framework;
using namespace certifier::utilities;

#define FLAGS_print_all true
static string measurement_file("/tmp/binary_trusted_measurements_file.bin");
#define FLAGS_trusted_measurements_file measurement_file
#define FLAGS_read_measurement_file     true
#define FLAGS_operation                 ""
#define FLAGS_client_address            "localhost"
#define FLAGS_server_address            "localhost"
#define FLAGS_policy_host               "localhost"
#define FLAGS_policy_port               8123
#define FLAGS_server_app_host           "localhost"
#define FLAGS_server_app_port           8124
static string data_dir = "../app1_data/";

#define FLAGS_policy_store_file           "store.bin"
#define FLAGS_platform_file_name          "platform_file.bin"
#define FLAGS_platform_attest_endorsement "platform_attest_endorsement.bin"
#define FLAGS_attest_key_file             "attest_key_file.bin"
#define FLAGS_policy_cert_file            "policy_cert_file.bin"
#define FLAGS_measurement_file            "example_app.measurement"

static std::string enclave_type;
cc_trust_data *    app_trust_data = nullptr;

static bool simulator_initialized = false;
static bool openenclave_initialized = false;
bool        test_local_certify(string &enclave_type,
                               bool    init_from_file,
                               string &file_name,
                               string &evidence_descriptor);


bool        trust_data_initialized = false;
key_message privatePolicyKey;
key_message publicPolicyKey;
string      serializedPolicyCert;
X509 *      policy_cert = nullptr;

policy_store pStore;
key_message  privateAppKey;
key_message  publicAppKey;
const int    app_symmetric_key_size = 64;
byte         app_symmetric_key[app_symmetric_key_size];
key_message  symmertic_key_for_protect;

// Standard algorithms for the enclave
string public_key_alg(Enc_method_rsa_2048);
string symmetric_key_alg(Enc_method_aes_256_cbc_hmac_sha256);

void print_trust_data() {
  if (!trust_data_initialized)
    return;
  printf("\nTrust data:\n");
  printf("\nPolicy key\n");
  print_key(publicPolicyKey);
  printf("\nPolicy cert\n");
  print_bytes(serializedPolicyCert.size(), (byte *)serializedPolicyCert.data());
  printf("\n");
  printf("\nPrivate app auth key\n");
  print_key(privateAppKey);
  printf("\nPublic app auth key\n");
  print_key(publicAppKey);
  printf("\nBlob key\n");
  print_key(symmertic_key_for_protect);
  printf("\n\n");
}

extern "C" {
bool openenclave_init(void);
bool certifier_init(char *, size_t);

bool cold_init(void);
bool certify_me(void);
bool warm_restart(void);
bool run_me_as_client(void);
bool run_me_as_server(void);
bool temp_test(void);
}

bool openenclave_init(void) {
  oe_result_t result = OE_OK;
  result = oe_load_module_host_file_system();
  if (result != OE_OK) {
    printf("Failed to load host file system module: %s\n",
           oe_result_str(result));
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

bool certifier_init(char *usr_data_dir, size_t usr_data_dir_size) {
  oe_result_t       result = OE_OK;
  static const char rnd_seed[] =
      "string to make the random number generator think it has entropy";

  RAND_seed(rnd_seed, sizeof rnd_seed);
  std::string usr_data = usr_data_dir;
  data_dir = usr_data + "/";
  printf("Using data_dir: %s\n", data_dir.c_str());

  if (!openenclave_initialized) {
    openenclave_init();
  }

  // Initialize attester and use the plugin.
  result = oe_attester_initialize();
  if (result != OE_OK) {
    printf("oe_attester_initialize failed.\n");
    return false;
  }
  // Initialize verifier and use the plugin.
  result = oe_verifier_initialize();
  if (result != OE_OK) {
    printf("oe_verifier_initialize failed.\n");
    return false;
  }

  if (!simulator_initialized) {
    /*
    string at_file(data_dir);
    at_file.append(FLAGS_attest_key_file);
    string measurement_file(data_dir);
    measurement_file.append(FLAGS_measurement_file);
    if (!simulator_init(at_file.c_str(), measurement_file.c_str())) {
        printf("simulator_init failed to initialize.\n");
        return false;
    }
    SSL_library_init();
    */

    SSL_library_init();
    string enclave_type("simulated-enclave");
    string purpose("authentication");

    string store_file(data_dir);
    store_file.append(FLAGS_policy_store_file);
    app_trust_data = new cc_trust_data(enclave_type, purpose, store_file);
    if (app_trust_data == nullptr) {
      printf("couldn't initialize trust object\n");
      return false;
    }

    // Init policy key info
    if (!app_trust_data->init_policy_key(initialized_cert,
                                         initialized_cert_size)) {
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

    if (!app_trust_data->initialize_simulated_enclave_data(
            attest_key_file_name,
            measurement_file_name,
            attest_endorsement_file_name)) {
      printf("Can't init simulated enclave\n");
      return false;
    }

    simulator_initialized = true;
  }

  return true;
}

void clear_sensitive_data() {
  // Todo: clear symmetric and private keys
  //    Not necessary on most platforms
}

bool cold_init() {
  return app_trust_data->cold_init(public_key_alg, symmetric_key_alg);
}

bool warm_restart() {
  return app_trust_data->warm_restart();
}

// Todo: replace with new cc_trust_data interface
bool certify_me() {
  return app_trust_data->certify_me(FLAGS_policy_host, FLAGS_policy_port);
}

void server_application(secure_authenticated_channel &channel) {

  printf("Server peer id is %s\n", channel.peer_id_.c_str());

  // Read message from client over authenticated, encrypted channel
  string out;
  int    n = channel.read(&out);
  printf("SSL server read: %s\n", (const char *)out.data());

  std::string ret = proc_data((const char *)out.c_str());

  // Reply over authenticated, encrypted channel
  channel.write(ret.size(), (byte *)ret.c_str());
}

bool run_me_as_server() {
  if (!app_trust_data->warm_restart()) {
    printf("warm-restart failed\n");
    return false;
  }
  printf("running as server\n");
  server_dispatch(FLAGS_server_app_host,
                  FLAGS_server_app_port,
                  app_trust_data->serialized_policy_cert_,
                  app_trust_data->private_auth_key_,
                  app_trust_data->private_auth_key_.certificate(),
                  server_application);
  return true;
}

void client_application(secure_authenticated_channel &channel) {
  // client starts, in a real application we would likely send a serialized
  // protobuf
  ULDataFrame sales_df;
  sales_df.read((data_dir + "../third_party/dataset/sales.csv").c_str(),
                io_format::csv2);

  std::string msg = sales_df.to_string<double, long>();
  printf("size of the dataframe is %lu\n", msg.size());
  channel.write(msg.size(), (byte *)msg.c_str());

  string buf;
  int    n = channel.read(&buf);
  printf("SSL client read: %s\n", (const char *)buf.c_str());
}

bool run_me_as_client() {
  if (!app_trust_data->warm_restart()) {
    printf("warm-restart failed\n");
    return false;
  }
  printf("running as client\n");
  if (!app_trust_data->cc_auth_key_initialized_
      || !app_trust_data->cc_policy_info_initialized_) {
    printf("trust data not initialized\n");
    return false;
  }
  string                       my_role("client");
  secure_authenticated_channel channel(my_role);
  if (!channel.init_client_ssl(
          FLAGS_server_app_host,
          FLAGS_server_app_port,
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

// not used
bool temp_test() {
  RSA *r = RSA_new();
  if (!key_to_RSA(privateAppKey, r)) {
    return false;
  }
  EVP_PKEY *auth_private_key = EVP_PKEY_new();
  EVP_PKEY_set1_RSA(auth_private_key, r);

  X509 * x509_auth_key_cert = X509_new();
  string auth_cert_str;
  auth_cert_str.assign((char *)privateAppKey.certificate().data(),
                       privateAppKey.certificate().size());
  if (!asn1_to_x509(auth_cert_str, x509_auth_key_cert)) {
    return false;
  }

  STACK_OF(X509) *stack = sk_X509_new_null();
  if (sk_X509_push(stack, policy_cert) == 0) {
    return false;
  }
  if (sk_X509_push(stack, x509_auth_key_cert) == 0) {
    return false;
  }
  X509_STORE *cs = X509_STORE_new();
  X509_STORE_add_cert(cs, policy_cert);
  X509_STORE_CTX *ctx = X509_STORE_CTX_new();

  int res = X509_STORE_CTX_init(ctx, cs, x509_auth_key_cert, stack);
  X509_STORE_CTX_set_cert(ctx, x509_auth_key_cert);
  if (res == 0)
    printf("X509_STORE_CTX_init failed\n");

  res = X509_verify_cert(ctx);
  if (res == 1) {
    printf("Verify succeeded\n");
  } else {
    printf("Verify failed\n");
    long code = X509_STORE_CTX_get_error(ctx);
    printf("Reason: %s\n", X509_verify_cert_error_string(code));
  }

  X509_STORE_CTX_free(ctx);
  X509_STORE_free(cs);

  return true;
}
