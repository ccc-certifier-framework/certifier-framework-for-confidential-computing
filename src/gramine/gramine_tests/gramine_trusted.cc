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

#include "gramine_trusted.h"
#if 0
#include "policy_key.cc"

#define FLAGS_print_all true
static string measurement_file("./binary_trusted_measurements_file.bin");
#define FLAGS_trusted_measurements_file measurement_file
#define FLAGS_read_measurement_file true
#define FLAGS_operation ""
#define FLAGS_client_address "localhost"
#define FLAGS_server_address "localhost"
#define FLAGS_policy_host "localhost"
#define FLAGS_policy_port 8123
#define FLAGS_server_app_host "localhost"
#define FLAGS_server_app_port 8124
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
bool connected = false;

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
  string enclave_type("gramine-enclave");
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

extern RSA* rsa_attestation_key;
extern key_message my_attestation_key;

bool gramine_local_certify() {
  string enclave_type("gramine-enclave");
  string evidence_descriptor("gramine-evidence");

  if (!gramine_Init(FLAGS_trusted_measurements_file)) {
    printf("gramine_Init: Can't read measurement file\n");
    return false;
  }

  rsa_attestation_key = RSA_new();
  if (!generate_new_rsa_key(2048, rsa_attestation_key))
    return false;
  if (!RSA_to_key(rsa_attestation_key, &my_attestation_key))
    return false;
  my_attestation_key.set_key_type("rsa-2048-private");
  my_attestation_key.set_key_name("attestKey");

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

bool gramine_seal() {
  if (!certifier_test_seal()) {
    printf("Sealing test failed\n");
    return false;
  }
  printf("Sealing test succeeded\n");
  return true;
}
#endif
