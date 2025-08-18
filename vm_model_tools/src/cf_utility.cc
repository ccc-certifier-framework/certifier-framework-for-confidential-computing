//  Copyright (c) 2021-23, VMware Inc, and the Certifier Authors.  All rights
//  reserved.  Copyright (c), 2025, John Manferdelli, Paul England and
//  Datica Researdh.
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
#include "certifier_algorithms.h"

using namespace certifier::framework;
using namespace certifier::utilities;


DEFINE_string(certifier_service_URL, "localhost", "address for service");
DEFINE_int32(service-port, 8124, "port for service");
              "symmetric key algorithm");
DEFINE_string(enclave_type, "simulated-enclave", "supporting enclave type");

DEFINE_bool(init_trust, false, "initialize certification?");
DEFINE_bool(reinit_trust, false, "reinitialize certification?");
DEFINE_bool(generate_symmetric_key, false, "generate symmetric key?");
DEFINE_bool(generate_public_key, false, "generate public key?");
DEFINE_bool(get_item, false, "get item from cryptstore");
DEFINE_bool(put_item, false, "put item into cryptstore");
DEFINE_bool(print_cryptstore, true, "print cryptstore");
DEFINE_bool(save_cryptstore, true, "save cryptstore");

DEFINE_string(public_key_algorithm, Enc_method_rsa_2048, "public key algorithm");
DEFINE_string(symmetric_key_algorithm, Enc_method_aes_256_cbc_hmac_sha256,
    "symmetric algorithm");
DEFINE_string(policy_domain_name, "datica_file_share_1", "policy domain name");
DEFINE_string(policy_key_cert_file, "policy_certificate.policy_domain_1",
    "file name for policy certificate");
DEFINE_string(policy_store_filename, "policy_cert_file.policy_domain_name", );
DEFINE_string(input_format, "serialized-protobuf", "input file format");
DEFINE_string(output_format, "serialized-protobuf", "output file format");
DEFINE_string(policy_store_filename, "policy_store.bin", "policy store file name");
DEFINE_string(encrypted_cryptstore_filename,
    "encrypted_keystore.policy_domain_1",
    "encrypted crypstore filename");
DEFINE_string(sealed_cryptstore_key_filename,
     "sealed_cryptstore_key.policy_domain_1",
     "sealed cryptstore file name");
DEFINE_string(keyname, "primary_store_encryption_key",
     "generated key name");
DEFINE_string(tag, "policy-key", "cryptstore entry tag");
DEFINE_string(version, 0, "cryptstore entry version");
DEFINE_string(type, "key_message_protobuf", "cryptstore data type");
DEFINE_string(output-file, "out_1", "output file name");
DEFINE_string(input-file, "in_1", "input file name");

DEFINE_string(ark_cert_file, "./service/milan_ark_cert.der", "machine ark certificate location");
DEFINE_string(ask_cert_file, "./service/milan_ask_cert.der", "machine ask certificate location");
DEFINE_string(vcek_cert_file, "./service/milan_vcek_cert.der", "machine vcek certificate location");


// -------------------------------------------------------------------------


// cf_utility see ../cf_utility_usage_notes.md for description


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
    goto err;
  }

  if (!read_file_into_string(FLAGS_data_dir + FLAGS_measurement_file,
                             &args[1])) {
    printf("%s() error, line %d, Can't read measurement file\n",
           __func__,
           __LINE__);
    goto err;
  }

  if (!read_file_into_string(FLAGS_data_dir + FLAGS_platform_attest_endorsement,
                             &args[2])) {
    printf("%s() error, line %d, Can't read endorsement file\n",
           __func__,
           __LINE__);
    goto err;
  }

  *n = 3;
  return true;

err:
  delete[] args;
  *s = nullptr;
  return false;
}

void print_os_model_parameters() {
  printf("cf_utility parameters:\n");
  printf("\t address for certifier service: %s\n",
          FLAGS_certifier_service_URL.c_str());
  printf("\tPort for service" %d\n", (int)FLAGS_service_port);
  printf("\tProtecting enclave type: %s\n", FLAGS_enclave_type.c_str());

  if (FLAGS_init_trust)
    printf("\tInitialize certification?: yes\n");
  else
    printf("\tInitialize certification?: no\n");
  if (FLAGS_reinit_trust)
    printf("\tReinitialize certification?: yes\n");
  else
    printf("\tReinitialize certification?: no\n");

  if (FLAGS_generate_symmetric_key)
    printf("\tGenerate symmetric key?: yes\n");
  else
    printf("\tGenerate symmetric key?: no\n");
  if (FLAGS_generate_public_key)
    printf("\tGenerate public key?: yes\n");
  else
    printf("\tGenerate public key?: no\n");
  if (FLAGS_get_item)
    printf("\tRetrieve cryptstore entry?: yes\n");
  else
    printf("\tRetrieve cryptstore entry?: no\n");
  if (FLAGS_put_item)
    printf("\tInsert cryptstore entry?: yes\n");
  else
    printf("\tInsert cryptstore entry?: no\n");
  if (FLAGS_print_cryptstore)
    printf("\tPrint cryptstore?: yes\n");
  else
    printf("\tPrint cryptstore?: no\n");
  if (FLAGS_save_cryptstore)
    printf("\tSave cryptstore?: yes\n");
  else
    printf("\tSave cryptstore?: no\n");

  printf("\tPublic key algorithm: %s\n", FLAGS_public_key_algorithm.c_str());
  printf("\tSymmetric key algorithm: %s\n", FLAGS_symmetric_key_algorithm.c_str());
  printf("\tPolicy doman name: %s\n", FLAGS_policy_domain_name.c_str());
  printf("\tpolicy_key_cert_file: %s\n", FLAGS_policy_key_cert_file.c_str());
  printf("\tPolicy store file name: %s\n", FLAGS)policy_store_filename, "policy_cert_file.policy_domain_name", );
  printf("\tInput file format: : %s\n", FLAGS_input_format, "serialized-protobuf", "input file format");
  printf("\tOutput file format: %s\n", FLAGS_output_format, "serialized-protobuf", "output file format");
  printf("\tPolicy store file name: %s\n", FLAGS_policy_store_filename, "policy_store.bin", "policy store file name");
  printf("\tEncrypted store file name: %s\n", FLAGS_encrypted_cryptstore_filename.c_str());
  printf("\tSealed cypstore file name: %s\n", FLAGS_sealed_cryptstore_key_filename.c_str());
  printf("\tKey name: %s\n", FLAGS_keyname.c_str());
  printf("\tCryptstore entry name: %s\n", FLAGS_tag.c_str());
  printf("\tCryptstore entry version: %d\n", (int)FLAGS_version);
  printf("\tCryptstore entry type: %s\n", FLAGS_type.c_str());
  printf("\tOutput file name: %s\n", FLAGS_output-file, "out_1", "output file name");
  printf("\tInput file name: %s\n", FLAGS_input-file.c_str());
  printf("\tLocation of ARK certificate: %s\n", FLAGS_ark_cert_file.c_str());
  printf("\tLocation of ASK certificate: %s\n", FLAGS_ask_cert_file.c_str());
  printf("\tLocation of VCEK certificate: %s\n", FLAGS_vcek_cert_file.c_str());
}

/*
bool client_application(secure_authenticated_channel &channel) {

  printf("Client peer id is %s\n", channel.peer_id_.c_str());
#ifdef DEBUG
  if (channel.peer_cert_ != nullptr) {
    printf("Client peer cert is:\n");
    X509_print_fp(stdout, channel.peer_cert_);
  }
#endif  // DEBUG

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
#ifdef DEBUG
  if (channel.peer_cert_ != nullptr) {
    printf("Server peer cert is:\n");
    X509_print_fp(stdout, channel.peer_cert_);
  }
#endif  // DEBUG

  // Read message from client over authenticated, encrypted channel
  string out;
  int    n = channel.read(&out);
  printf("SSL server read: %s\n", (const char *)out.data());

  // Reply over authenticated, encrypted channel
  const char *msg = "Hi from your secret server\n";
  channel.write(strlen(msg), (byte *)msg);
  channel.close();
}
*/

// -----------------------------------------------------------------------------------------


#include "policy_key.cc"

cc_trust_manager *trust_mgr = nullptr;

int main(int an, char **av) {
  string usage("cf-osutility");
  gflags::SetUsageMessage(usage);
  gflags::ParseCommandLineFlags(&an, &av, true);
  an = 1;
  ::testing::InitGoogleTest(&an, av);

  if (FLAGS_operation == "") {
    printf("                                                                            (Defaults)\n");
    printf("%s --operation=<op>                                        ; %s", av[0], "(See below)");
    printf("\n\
                  --policy_host=policy-host-address                       ; %s\n\
                  --policy_port=policy-host-port                          ; %d\n\
                  --server_app_host=my-server-host-address                ; %s\n\
                  --server_app_port=my-server-port-number                 ; %d\n\
                  --data_dir=-directory-for-app-data                      ; %s\n\
                  --policy_cert_file=self-signed-policy-cert-file-name    ; \n\
                  --policy_store_file=policy-store-file-name              ; %s\n\
                  --print_all=true|false",
                  FLAGS_policy_host.c_str(),
                  FLAGS_policy_port,
                  FLAGS_server_app_host.c_str(),
                  FLAGS_server_app_port,
                  FLAGS_data_dir.c_str(),
                  FLAGS_policy_store_file.c_str());

#ifdef SIMPLE_APP
    printf("\n\
                  --platform_file_name=platform-cert-bin-file-name        ; %s\n\
                  --platform_attest_endorsement=endorsement-bin-file-name ; %s\n\
                  --measurement_file=measurement-bin-file-name            ; %s\n\
                  --attest_key_file=attest-key-bin-file-name              ; %s\n",
                  FLAGS_platform_file_name.c_str(),
                  FLAGS_platform_attest_endorsement.c_str(),
                  FLAGS_measurement_file.c_str(),
                  FLAGS_attest_key_file.c_str());
#endif  // SIMPLE_APP

#ifdef SEV_SIMPLE_APP
    printf("\n\
                  --ark_cert_file=./service/milan_ark_cert.der \n\
                  --ask_cert_file=./service/milan_ask_cert.der \n\
                  --vcek_cert_file=./service/milan_vcek_cert.der ");
#endif  // SEV_SIMPLE_APP
	//
    printf("\n\nOperations are: cold-init, get-certified, "
           "run-app-as-client, run-app-as-server\n");

    printf("\n\
    --public_key_alg=public-key-algorigthm-name                          : %s\n\
    --auth_symmetric_key_alg=authenticated-symmetric-key-algorigthm-name : %s\n",
            FLAGS_public_key_alg.c_str(),
            FLAGS_auth_symmetric_key_alg.c_str());

    printf("\nPublic-key algorithms supported:\n");
    for (int i = 0; i < Num_public_key_algorithms; i++) {
      printf("  %s\n", Enc_public_key_algorithms[i]);
    }
    printf("\nSymmetric-key algorithms supported:\n");
    for (int i = 0; i < Num_symmetric_key_algorithms; i++) {
      printf("  %s\n", Enc_authenticated_symmetric_key_algorithms[i]);
    }

    return 0;
  }
  // clang-format on

  SSL_library_init();
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
  string *params = nullptr;
  int     n = 0;
  if (!get_enclave_parameters(&params, &n)) {
    printf("%s() error, line %d, get enclave parameters\n", __func__, __LINE__);
    return 1;
  }

  // Init simulated enclave
  if (!trust_mgr->initialize_enclave(n, params)) {
    printf("%s() error, line %d, Can't init enclave\n", __func__, __LINE__);
    return 1;
  }
  if (params != nullptr) {
    delete[] params;
    params = nullptr;
  }

  // Use specified algorithms for the enclave            Defaults:
#ifdef SIMPLE_APP
  // We support --public_key_alg and --auth_symmetric_key_alg only for simple_app
  // (as a way to exercise tests w/ different pairs of algorithms).
  string public_key_alg(FLAGS_public_key_alg);                  // Enc_method_rsa_2048
  string auth_symmetric_key_alg(FLAGS_auth_symmetric_key_alg);  // Enc_method_aes_256_cbc_hmac_sha256
  if (FLAGS_print_all) {
      printf("measurement file='%s', ", FLAGS_measurement_file.c_str());
  }
#else
  string public_key_alg(Enc_method_rsa_2048);
  string auth_symmetric_key_alg(Enc_method_aes_256_cbc_hmac_sha256);
#endif  // SIMPLE_APP

  // clang-format on

  if (FLAGS_print_all && (FLAGS_operation == "cold-init")) {
    printf("public_key_alg='%s', authenticated_symmetric_key_alg='%s\n",
           public_key_alg.c_str(),
           auth_symmetric_key_alg.c_str());
  }

  // Carry out operation
  int ret = 0;
  if (FLAGS_operation == "cold-init") {
    if (!trust_mgr->cold_init(public_key_alg,
                              auth_symmetric_key_alg,
                              "simple-app-home_domain",
                              FLAGS_policy_host,
                              FLAGS_policy_port,
                              FLAGS_server_app_host,
                              FLAGS_server_app_port)) {
      printf("%s() error, line %d, cold-init failed\n", __func__, __LINE__);
      ret = 1;
      goto done;
    }

    // Debug
#ifdef DEBUG
    trust_mgr->print_trust_data();
#endif  // DEBUG
  } else if (FLAGS_operation == "get-certified") {
    if (!trust_mgr->warm_restart()) {
      printf("%s() error, line %d, warm-restart failed\n", __func__, __LINE__);
      ret = 1;
      goto done;
    }
    if (!trust_mgr->certify_me()) {
      printf("%s() error, line %d, certification failed\n", __func__, __LINE__);
      ret = 1;
      goto done;
    }
    // Debug
#ifdef DEBUG
    trust_mgr->print_trust_data();
#endif  // DEBUG
  } else if (FLAGS_operation == "run-app-as-client") {
    string                       my_role("client");
    secure_authenticated_channel channel(my_role);

    if (!trust_mgr->warm_restart()) {
      printf("%s() error, line %d, warm-restart failed\n", __func__, __LINE__);
      ret = 1;
      goto done;
    }

    printf("Running App as client\n");
    if (!trust_mgr->cc_auth_key_initialized_
        || !trust_mgr->cc_policy_info_initialized_) {
      printf("%s() error, line %d, trust data not initialized\n",
             __func__,
             __LINE__);
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
    if (!channel.init_client_ssl(FLAGS_server_app_host,
                                 FLAGS_server_app_port,
                                 *trust_mgr)) {
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
    printf("Running App as server\n");
    if (!server_dispatch(FLAGS_server_app_host,
                         FLAGS_server_app_port,
                         *trust_mgr,
                         server_application)) {
      ret = 1;
      goto done;
    }
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
