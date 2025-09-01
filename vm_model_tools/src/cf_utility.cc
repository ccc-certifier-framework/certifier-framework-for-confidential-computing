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

#include <arpa/inet.h>
#include <gflags/gflags.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <sys/socket.h>

#include "certifier_algorithms.h"
#include "certifier_framework.h"
#include "certifier_utilities.h"
#include "cf_support.h"
#include "cryptstore.pb.h"

using namespace certifier::framework;
using namespace certifier::utilities;

// cf_utility see ../cf_utility_usage_notes.md for description

//  -------------------------------------------------------------------

DEFINE_bool(cf_utility_help, false, "provide help");
DEFINE_string(certifier_service_URL, "localhost", "address for service");
DEFINE_int32(service_port, 8124, "port for service");
DEFINE_string(enclave_type, "simulated-enclave", "supporting enclave type");

DEFINE_bool(init_trust, false, "initialize certification?");
DEFINE_bool(reinit_trust, false, "reinitialize certification?");
DEFINE_bool(generate_symmetric_key, false, "generate symmetric key?");
DEFINE_bool(generate_public_key, false, "generate public key?");
DEFINE_bool(get_item, false, "get item from cryptstore");
DEFINE_bool(put_item, false, "put item into cryptstore");
DEFINE_bool(print_cryptstore, true, "print cryptstore");
DEFINE_bool(save_cryptstore, false, "save cryptstore");

DEFINE_string(public_key_algorithm,
              Enc_method_rsa_2048,
              "public key algorithm");
DEFINE_string(symmetric_key_algorithm,
              Enc_method_aes_256_cbc_hmac_sha256,
              "symmetric algorithm");
DEFINE_string(policy_domain_name, "datica", "policy domain name");
DEFINE_string(policy_key_cert_file,
              "policy_certificate.datica",
              "file name for policy certificate");
DEFINE_string(data_dir, "./", "supporting file directory");
DEFINE_string(input_format, "serialized-protobuf", "input file format");
DEFINE_string(output_format, "serialized-protobuf", "output file format");

DEFINE_string(policy_store_filename,
              "policy_store.bin.datica",
              "policy store file name");
DEFINE_string(encrypted_cryptstore_filename,
              "encrypted_cryptstore.datica",
              "encrypted cryptstore file name");
DEFINE_string(keyname, "primary-store-encryption-key", "generated key name");
DEFINE_double(duration, 24.0 * 365.0, "duration of key");
DEFINE_string(tag, "policy-key", "cryptstore entry tag");
DEFINE_int32(entry_version, 0, "cryptstore entry version");
DEFINE_string(type,
              "key-message-serialized-protobuf",
              "cryptstore entry data type");

DEFINE_string(output_file, "out_1", "output file name");
DEFINE_string(input_file, "in_1", "input file name");

// For SEV
DEFINE_string(ark_cert_file,
              "./service/ark_cert.der",
              "machine ark certificate location");
DEFINE_string(ask_cert_file,
              "./service/ask_cert.der",
              "machine ask certificate location");
DEFINE_string(vcek_cert_file,
              "./service/vcek_cert.der",
              "machine vcek certificate location");

// For simulated-enclave
DEFINE_string(attest_key_file,
              "./provisioning/attest_key_file.bin",
              "simulated attestation key");
DEFINE_string(measurement_file,
              "./provisioning/cf_utility.measurement",
              "simulated enclave measurement");
DEFINE_string(platform_attest_endorsement_file,
              "./provisioning/platform_attest_endorsement.bin",
              "platform endorsement");

// -------------------------------------------------------------------------

void print_os_model_parameters() {
  printf("cf_utility parameters:\n");
  printf("\n");

  if (FLAGS_init_trust)
    printf("  Initialize certification?: yes\n");
  else
    printf("  Initialize certification?: no\n");
  if (FLAGS_reinit_trust)
    printf("  Reinitialize certification?: yes\n");
  else
    printf("  Reinitialize certification?: no\n");

  if (FLAGS_generate_symmetric_key)
    printf("  Generate symmetric key?: yes\n");
  else
    printf("  Generate symmetric key?: no\n");
  if (FLAGS_generate_public_key)
    printf("  Generate public key?: yes\n");
  else
    printf("  Generate public key?: no\n");
  if (FLAGS_get_item)
    printf("  Retrieve cryptstore entry?: yes\n");
  else
    printf("  Retrieve cryptstore entry?: no\n");
  if (FLAGS_put_item)
    printf("  Insert cryptstore entry?: yes\n");
  else
    printf("  Insert cryptstore entry?: no\n");
  if (FLAGS_print_cryptstore)
    printf("  Print cryptstore?: yes\n");
  else
    printf("  Print cryptstore?: no\n");
  if (FLAGS_save_cryptstore)
    printf("  Save cryptstore?: yes\n");
  else
    printf("  Save cryptstore?: no\n");
  printf("\n");
  printf("  Policy doman name: %s\n", FLAGS_policy_domain_name.c_str());
  printf("  Policy_key_cert_file: %s\n", FLAGS_policy_key_cert_file.c_str());
  printf("  Policy store file name: %s\n", FLAGS_policy_store_filename.c_str());
  printf("  Encrypted cryptstore file name: %s\n",
         FLAGS_encrypted_cryptstore_filename.c_str());
  printf("  Directory for cf_utility supporting data for this policy: %s\n",
         FLAGS_data_dir.c_str());
  printf("\n");
  printf("  Protecting enclave type: %s\n", FLAGS_enclave_type.c_str());
  printf("  Address for certifier service: %s\n",
         FLAGS_certifier_service_URL.c_str());
  printf("  Port for service %d\n", (int)FLAGS_service_port);
  printf("\n");
  printf("  Input file format: %s\n", FLAGS_input_format.c_str());
  printf("  Output file format: %s\n", FLAGS_output_format.c_str());
  printf("  Input file name: %s\n", FLAGS_input_file.c_str());
  printf("  Output file name: %s\n", FLAGS_output_file.c_str());
  printf("\n");
  printf("  Public key algorithm: %s\n", FLAGS_public_key_algorithm.c_str());
  printf("  Symmetric key algorithm: %s\n",
         FLAGS_symmetric_key_algorithm.c_str());
  printf("  Key name: %s\n", FLAGS_keyname.c_str());
  printf("  Duration: %lf\n", FLAGS_duration);
  printf("  Cryptstore entry name: %s\n", FLAGS_tag.c_str());
  printf("  Cryptstore entry version: %d\n", (int)FLAGS_entry_version);
  printf("  Cryptstore entry type: %s\n", FLAGS_type.c_str());
  printf("\n");
  printf("  ARK certificate file: %s\n", FLAGS_ark_cert_file.c_str());
  printf("  ASK certificate file: %s\n", FLAGS_ask_cert_file.c_str());
  printf("  VCEK certificate file: %s\n", FLAGS_vcek_cert_file.c_str());
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

  if (!read_file_into_string(
          FLAGS_data_dir + FLAGS_platform_attest_endorsement_file,
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

bool get_sev_enclave_parameters(string **s, int *n) {
  // ark cert file, ask cert file, vcek cert file
  string *args = new string[3];
  if (args == nullptr) {
    return false;
  }
  *s = args;

  if (!read_file_into_string(FLAGS_data_dir + FLAGS_ark_cert_file, &args[0])) {
    printf("%s() error, line %d, Can't read attest file\n", __func__, __LINE__);
    goto err;
  }

  if (!read_file_into_string(FLAGS_data_dir + FLAGS_ask_cert_file, &args[1])) {
    printf("%s() error, line %d, Can't read measurement file\n",
           __func__,
           __LINE__);
    goto err;
  }

  if (!read_file_into_string(FLAGS_data_dir + FLAGS_vcek_cert_file, &args[2])) {
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

void print_help() {
  printf("cf_utility.exe\n");
  printf("  --cf_utility_help=false, print this help message\n");
  printf("\n");
  printf("  --policy_domain_name=%s, name of policy domain\n",
         FLAGS_policy_domain_name.c_str());
  printf("  --enclave_type=sev-enclave, enclave type\n");
  printf("  --policy_key_cert_file=policy_cert_file.datica,"
         " name of file with policy domain root cert\n");
  printf("  --policy_store_filename=\"\", name of policy store (as used in "
         "certifier\n");
  printf(
      "  --encrypted_cryptstore_filename=encrypted_store.policy_domain_name, "
      "file"
      " containing encrypted store\n");
  printf("  --data_dir=./cf_data, directory for configuration data.\n");
  printf("\n");
  printf("  --init_trust=false, initialize trust domain if needed\n");
  printf("  --reinit_trust=false, unconditionally initialize trust domain if "
         "needed\n");
  printf("  --symmetric_algorithm=aes-256-gcm, key type of selected symmetric "
         "key\n");
  printf(
      "  --public_key_algorithm=rsa_2048, key type of selected public key\n");
  printf("  --generate_symmetric_key=false, generate a symmetric key of "
         "specified key type\n");
  printf("  --generate_public_key=false, generate a public key of specified "
         "key type\n");
  printf("  --print_cryptstore=true, print cryptstore\n");
  printf("  --save_cryptstore=false, save cryptstore (normally automatic)\n");
  printf("\n");
  printf("  --tag=\"\", value of tag for put_item\n");
  printf("  --version=0, value of version for put_item\n");
  printf("  --type=\"\", value of type for put_item\n");
  printf("    Possible types: X509-der-cert, key-message-serialized-protobuf, "
         "binary-blob\n");
  printf("  --get_item=false, get cryptstore enty of specified tag/value, "
         "write to output file\n");
  printf("  --put_item=false, set cryptstore entry of specified tag/value from "
         "input file\n");
  printf("  --keyname=store_encryption_key_1, name of keys generated by above "
         "calls\n");
  printf("  --duration=time in hours, duration of keys or certs\n");
  printf("\n");
  printf("  --certifier_service_URL=%s, URL for Certifier Service\n",
         FLAGS_certifier_service_URL.c_str());
  printf("  --service_port=%d, port-for-certifier-service\n",
         (int)FLAGS_service_port);
  printf("\n");
  printf("  --input_format=key-message-serialized-protobuf, input format\n");
  printf("  --output_format=key-message-serialized-protobuf, output format\n");
  printf("\n");
  printf("  --input_file=%s, input file name\n", FLAGS_input_file.c_str());
  printf("  --output_file=%s, output file name\n", FLAGS_output_file.c_str());
  printf("\n");
  printf("  SEV enclave specific arguments\n");
  printf("    --ark_cert_file=%s, file with ark certificate for this machine\n",
         FLAGS_ark_cert_file.c_str());
  printf("    --ask_cert_file=%s, file with ark certificate for this machine\n",
         FLAGS_ask_cert_file.c_str());
  printf(
      "    --vcek_cert_file=%s, file with ark certificate for this machine\n",
      FLAGS_vcek_cert_file.c_str());
  printf("\n");

  printf("\nPublic-key algorithms supported:\n");
  for (int i = 0; i < Num_public_key_algorithms; i++) {
    printf("    %s\n", Enc_public_key_algorithms[i]);
  }
  printf("\nSymmetric-key algorithms supported:\n");
  for (int i = 0; i < Num_symmetric_key_algorithms; i++) {
    printf("    %s\n", Enc_authenticated_symmetric_key_algorithms[i]);
  }
}

// -------------------------------------------------------------------------------------

cc_trust_manager *trust_mgr = nullptr;

#define DEBUG3

bool add_key_and_cert(cryptstore &cs) {

  if (!trust_mgr->cc_auth_key_initialized_) {
    printf("%s() error, line %d, no existing auth key\n", __func__, __LINE__);
    return false;
  }

  certifiers *c =
      trust_mgr->find_certifier_by_domain_name(FLAGS_policy_domain_name);
  if (c == nullptr) {
    printf("%s() error, line %d, can't find this domain\n", __func__, __LINE__);
    return false;
  }

  if (!c->is_certified_) {
    printf("%s() error, line %d, domain not initialized\n", __func__, __LINE__);
    return false;
  }

  time_point tp;
  if (!time_now(&tp)) {
    printf("%s() error, line %d, Can't get current time\n", __func__, __LINE__);
    return false;
  }
  string tp_str;
  if (!time_to_string(tp, &tp_str)) {
    printf("%s() error, line %d, Can't convert time to string\n",
           __func__,
           __LINE__);
    return false;
  }

  string tag1(FLAGS_policy_domain_name);
  tag1.append("-admission-certificate");
  int    version = 1;
  string type("X509-der-cert");

  cryptstore_entry *ce = cs.add_entries();
  int               l = 0;
  int               h = 0;
  if (version_range_in_cryptstore(cs, tag1, &l, &h)) {
    version = h + 1;
  } else {
    version = 1;
  }
  ce->set_tag(tag1);
  ce->set_type(type);
  ce->set_version(version);
  ce->set_time_entered(tp_str);
  ce->set_blob((byte *)c->admissions_cert_.data(), c->admissions_cert_.size());

  string tag2(FLAGS_policy_domain_name);
  tag2.append("-private-auth-key");
  version = 1;
  type.assign("key-message-serialized-protobuf");

  ce = cs.add_entries();
  l = 0;
  h = 0;
  if (version_range_in_cryptstore(cs, tag2, &l, &h)) {
    version = h + 1;
  } else {
    version = 1;
  }
  ce->set_tag(tag2);
  ce->set_type(type);
  ce->set_version(version);
  ce->set_time_entered(tp_str);

  string serialized_key;
  if (!trust_mgr->private_auth_key_.SerializeToString(&serialized_key)) {
    printf("%s() error, line %d, Can't serialize key\n", __func__, __LINE__);
    return false;
  }

  ce->set_blob((byte *)serialized_key.data(), serialized_key.size());
  return true;
}

bool generate_symmetric_key(key_message *km,
                            string      &name,
                            string      &key_type,
                            string      &tag) {
  cryptstore cs;
  string     key_format("vse-key");
  double     duration_in_hours = FLAGS_duration;

  if (!cf_generate_symmetric_key(km,
                                 FLAGS_keyname,
                                 FLAGS_symmetric_key_algorithm,
                                 key_format,
                                 duration_in_hours)) {
    printf("%s() error, line %d, cannot  generate key\n", __func__, __LINE__);
    return false;
  }
  if (!open_cryptstore(&cs,
                       FLAGS_data_dir,
                       FLAGS_encrypted_cryptstore_filename,
                       FLAGS_duration,
                       FLAGS_enclave_type,
                       FLAGS_symmetric_key_algorithm)) {
    printf("%s() error, line %d, cannot open cryptstore\n", __func__, __LINE__);
    return false;
  }

  // update cryptstore
  int               l, h;
  cryptstore_entry *ce = nullptr;
  ce = cs.add_entries();
  if (version_range_in_cryptstore(cs, tag, &l, &h)) {
    ce->set_version(h + 1);
  } else {
    ce->set_version(1);
  }
  ce->set_tag(tag);
  ce->set_type("key-message-serialized-protobuf");
  time_point tp;
  if (!time_now(&tp)) {
    printf("%s() error, line %d, Can't get current time\n", __func__, __LINE__);
    return false;
  }
  string tp_str;
  if (!time_to_string(tp, &tp_str)) {
    printf("%s() error, line %d, Can't convert time to string\n",
           __func__,
           __LINE__);
    return false;
  }
  ce->set_time_entered(tp_str);

  string serialized_key;
  if (!km->SerializeToString(&serialized_key)) {
    printf("%s() error, line %d, cannot serialize key\n", __func__, __LINE__);
    return false;
  }
  ce->set_blob((byte *)serialized_key.data(), serialized_key.size());

  // save store
  if (!save_cryptstore(cs,
                       FLAGS_data_dir,
                       FLAGS_encrypted_cryptstore_filename,
                       FLAGS_duration,
                       FLAGS_enclave_type,
                       FLAGS_symmetric_key_algorithm)) {
    printf("%s() error, line %d, cannot save cryptstore\n", __func__, __LINE__);
    return false;
  }
  return true;
}

bool generate_public_key(key_message *km,
                         string      &name,
                         string      &key_type,
                         string      &tag) {
  cryptstore cs;
  string     key_format("vse-key");
  double     duration_in_hours = FLAGS_duration;

  if (!cf_generate_public_key(km,
                              FLAGS_keyname,
                              FLAGS_public_key_algorithm,
                              key_format,
                              duration_in_hours)) {
    printf("%s() error, line %d, cannot  generate key\n", __func__, __LINE__);
    return false;
  }
  if (!open_cryptstore(&cs,
                       FLAGS_data_dir,
                       FLAGS_encrypted_cryptstore_filename,
                       FLAGS_duration,
                       FLAGS_enclave_type,
                       FLAGS_symmetric_key_algorithm)) {
    printf("%s() error, line %d, cannot open cryptstore\n", __func__, __LINE__);
    return false;
  }

  // update cryptstore
  int               l, h;
  cryptstore_entry *ce = nullptr;
  ce = cs.add_entries();
  if (version_range_in_cryptstore(cs, tag, &l, &h)) {
    ce->set_version(h + 1);
  } else {
    ce->set_version(1);
  }
  ce->set_tag(tag);
  ce->set_type("key-message-serialized-protobuf");
  time_point tp;
  if (!time_now(&tp)) {
    printf("%s() error, line %d, Can't get current time\n", __func__, __LINE__);
    return false;
  }

  string tp_str;
  if (!time_to_string(tp, &tp_str)) {
    printf("%s() error, line %d, Can't convert time to string\n",
           __func__,
           __LINE__);
    return false;
  }
  ce->set_time_entered(tp_str);

  string serialized_key;
  if (!km->SerializeToString(&serialized_key)) {
    printf("%s() error, line %d, cannot serialize key\n", __func__, __LINE__);
    return false;
  }
  ce->set_blob((byte *)serialized_key.data(), serialized_key.size());

  // save store
  if (!save_cryptstore(cs,
                       FLAGS_data_dir,
                       FLAGS_encrypted_cryptstore_filename,
                       FLAGS_duration,
                       FLAGS_enclave_type,
                       FLAGS_symmetric_key_algorithm)) {
    printf("%s() error, line %d, cannot save cryptstore\n", __func__, __LINE__);
    return false;
  }
  return true;
}

//  ---------------------------------------------------------------------------------

bool reinit_domain_and_update() {
  string purpose("authentication");

  // read policy cert
  string der_policy_cert;
  string der_policy_cert_file_name(FLAGS_data_dir);
  der_policy_cert_file_name.append("./provisioning/");
  der_policy_cert_file_name.append(FLAGS_policy_key_cert_file);
  if (!read_file_into_string(der_policy_cert_file_name, &der_policy_cert)) {
    printf("%s() error, line %d, couldn't read, policy domain cert in %s\n",
           __func__,
           __LINE__,
           der_policy_cert.c_str());
    return false;
  }

  // re-init domain
  if (!trust_mgr->initialize_new_domain(FLAGS_policy_domain_name,
                                        purpose,
                                        der_policy_cert,
                                        FLAGS_certifier_service_URL,
                                        FLAGS_service_port)) {
    printf("%s() error, line %d, Can't initialize domain\n",
           __func__,
           __LINE__);
    return false;
  }

  // get or initialize cryptstore
  cryptstore cs;
  string     cryptstore_file_name(FLAGS_data_dir);
  cryptstore_file_name.append(FLAGS_encrypted_cryptstore_filename);

#ifdef DEBUG3
  printf("cryptstore name: %s\n", cryptstore_file_name.c_str());
#endif
  if (file_size(cryptstore_file_name) < 0) {
    if (!create_cryptstore(cs,
                           FLAGS_data_dir,
                           FLAGS_encrypted_cryptstore_filename,
                           FLAGS_duration,
                           FLAGS_enclave_type,
                           FLAGS_symmetric_key_algorithm)) {
      printf("%s() error, line %d, cannot create cryptstore\n",
             __func__,
             __LINE__);
      return false;
    }
  } else {
    // Read existing cryptstore
    if (!open_cryptstore(&cs,
                         FLAGS_data_dir,
                         FLAGS_encrypted_cryptstore_filename,
                         FLAGS_duration,
                         FLAGS_enclave_type,
                         FLAGS_symmetric_key_algorithm)) {
      printf("%s() error, line %d, cannot open cryptstore\n",
             __func__,
             __LINE__);
      return false;
    }
  }

  // add keys and certificates
  if (!add_key_and_cert(cs)) {
    printf("%s() error, line %d, couldn't add domain and cert to cryptstore\n",
           __func__,
           __LINE__);
    return false;
  }
  if (!save_cryptstore(cs,
                       FLAGS_data_dir,
                       FLAGS_encrypted_cryptstore_filename,
                       FLAGS_duration,
                       FLAGS_enclave_type,
                       FLAGS_symmetric_key_algorithm)) {
    printf("%s() error, line %d, cannot save cryptstore\n", __func__, __LINE__);
    return false;
  }
#ifdef DEBUG3
  print_cryptstore(cs);
#endif
  return true;
}


int main(int an, char **av) {
  string usage("cf-osutility");
  gflags::SetUsageMessage(usage);
  gflags::ParseCommandLineFlags(&an, &av, true);
  an = 1;
  int ret = 0;

  SSL_library_init();
  string purpose("authentication");

  if (FLAGS_cf_utility_help) {
    print_help();
    return ret;
  }
  print_os_model_parameters();

  // Get parameters
  string *params = nullptr;
  int     n = 0;
  if (FLAGS_enclave_type == "simulated-enclave") {
    if (!get_simulated_enclave_parameters(&params, &n)) {
      printf("%s() error, line %d, get enclave parameters\n",
             __func__,
             __LINE__);
      return false;
    }
  } else if (FLAGS_enclave_type == "sev-enclave") {
    if (!get_sev_enclave_parameters(&params, &n)) {
      printf("%s() error, line %d, get enclave parameters\n",
             __func__,
             __LINE__);
      return false;
    }
  } else {
    printf("%s() error, line %d, unsupported enclave\n", __func__, __LINE__);
    return false;
  }

  // Create trust manager
  string store_file(FLAGS_data_dir);
  store_file.append(FLAGS_policy_store_filename);
#ifdef DEBUG3
  printf("\npolicy store: %s\n", store_file.c_str());
#endif
  trust_mgr = new cc_trust_manager(FLAGS_enclave_type, purpose, store_file);
  if (trust_mgr == nullptr) {
    printf("%s() error, line %d, couldn't initialize trust object\n",
           __func__,
           __LINE__);
    return 1;
  }

  // Init enclave
  if (!trust_mgr->initialize_enclave(n, params)) {
    printf("%s() error, line %d, Can't init enclave\n", __func__, __LINE__);
    return 1;
  }
#ifdef DEBUG3
  printf("Enclave initialized\n");
#endif

  if (params != nullptr) {
    delete[] params;
    params = nullptr;
  }

  // Initialize store
  if (!trust_mgr->initialize_store()) {
    printf("%s() error, line %d, Can't init store\n", __func__, __LINE__);
    ret = 1;
    goto done;
  }

  // Initialize keys
  if (!trust_mgr->initialize_keys(FLAGS_public_key_algorithm,
                                  FLAGS_symmetric_key_algorithm,
                                  false)) {
    printf("%s() error, line %d, Can't init keys\n", __func__, __LINE__);
    ret = 1;
    goto done;
  }

  // Operation?
  if (FLAGS_init_trust) {

    if (trust_mgr->initialize_existing_domain(FLAGS_policy_domain_name)) {
      certifiers *c =
          trust_mgr->find_certifier_by_domain_name(FLAGS_policy_domain_name);
      if (c != nullptr) {
        if (c->is_certified_) {
          // Domain exists and is certified, return
          printf("Domain already exists and is certified\n");
          goto done;
        }
      }
    }

    if (!reinit_domain_and_update()) {
      ret = 1;
      goto done;
    }
  } else if (FLAGS_reinit_trust) {

    if (!reinit_domain_and_update()) {
      ret = 1;
      goto done;
    }
    goto done;
  } else if (FLAGS_generate_symmetric_key) {
    printf("\ngenerate_symmetric_key %s\n",
           FLAGS_symmetric_key_algorithm.c_str());

    if (!trust_mgr->initialize_existing_domain(FLAGS_policy_domain_name)) {
      printf("%s() error, line %d, domain %s does not init\n",
             __func__,
             __LINE__,
             FLAGS_policy_domain_name.c_str());
      ret = 1;
      goto done;
    }
    certifiers *c =
        trust_mgr->find_certifier_by_domain_name(FLAGS_policy_domain_name);
    if (c == nullptr) {
      printf("%s() error, line %d, can't find certifier for %s\n",
             __func__,
             __LINE__,
             FLAGS_policy_domain_name.c_str());
      ret = 1;
      goto done;
    }
    if (!c->is_certified_) {
      printf("%s() error, line %d, domain %s snot certified\n",
             __func__,
             __LINE__,
             FLAGS_policy_domain_name.c_str());
      ret = 1;
      goto done;
    }

    cryptstore cs;
    if (!open_cryptstore(&cs,
                         FLAGS_data_dir,
                         FLAGS_encrypted_cryptstore_filename,
                         FLAGS_duration,
                         FLAGS_enclave_type,
                         FLAGS_symmetric_key_algorithm)) {
      printf("%s() error, line %d, cannot open cryptstore\n",
             __func__,
             __LINE__);
      ret = 1;
      goto done;
    }

    key_message km;
    string      key_name(FLAGS_keyname);
    string      key_type(FLAGS_symmetric_key_algorithm);
    string      tag(FLAGS_keyname);

    if (!generate_symmetric_key(&km, key_name, key_type, FLAGS_keyname)) {
      printf("%s() error, line %d, cannot generate symmetric key\n",
             __func__,
             __LINE__);
      ret = 1;
      goto done;
    }

    time_point tp;
    if (!time_now(&tp)) {
      printf("%s() error, line %d, Can't get current time\n",
             __func__,
             __LINE__);
      return false;
    }

    string tp_str;
    if (!time_to_string(tp, &tp_str)) {
      printf("%s() error, line %d, Can't convert time to string\n",
             __func__,
             __LINE__);
      return false;
    }

    int    version = 1;
    string type("key-message-serialized-protobuf");

    cryptstore_entry *ce = cs.add_entries();
    int               l = 0;
    int               h = 0;
    if (version_range_in_cryptstore(cs, tag, &l, &h)) {
      version = h + 1;
    } else {
      version = 1;
    }
    ce->set_tag(tag);
    ce->set_type(type);
    ce->set_version(version);
    ce->set_time_entered(tp_str);

    string serialized_key;
    if (!km.SerializeToString(&serialized_key)) {
      printf("%s() error, line %d, Can't generate serialized key\n",
             __func__,
             __LINE__);
      return false;
    }
    ce->set_blob((byte *)serialized_key.data(), serialized_key.size());

    if (!save_cryptstore(cs,
                         FLAGS_data_dir,
                         FLAGS_encrypted_cryptstore_filename,
                         FLAGS_duration,
                         FLAGS_enclave_type,
                         FLAGS_symmetric_key_algorithm)) {
      printf("%s() error, line %d, cannot save cryptstore\n",
             __func__,
             __LINE__);
      ret = 1;
      goto done;
    }
#ifdef DEBUG3
    print_cryptstore(cs);
#endif
    goto done;
  } else if (FLAGS_generate_public_key) {

    if (!trust_mgr->initialize_existing_domain(FLAGS_policy_domain_name)) {
      printf("%s() error, line %d, domain %s does not init\n",
             __func__,
             __LINE__,
             FLAGS_policy_domain_name.c_str());
      ret = 1;
      goto done;
    }
    certifiers *c =
        trust_mgr->find_certifier_by_domain_name(FLAGS_policy_domain_name);
    if (c == nullptr) {
      printf("%s() error, line %d, can't find certifier for %s\n",
             __func__,
             __LINE__,
             FLAGS_policy_domain_name.c_str());
      ret = 1;
      goto done;
    }
    if (!c->is_certified_) {
      printf("%s() error, line %d, domain %s snot certified\n",
             __func__,
             __LINE__,
             FLAGS_policy_domain_name.c_str());
      ret = 1;
      goto done;
    }

    cryptstore cs;
    if (!open_cryptstore(&cs,
                         FLAGS_data_dir,
                         FLAGS_encrypted_cryptstore_filename,
                         FLAGS_duration,
                         FLAGS_enclave_type,
                         FLAGS_symmetric_key_algorithm)) {
      printf("%s() error, line %d, cannot open cryptstore\n",
             __func__,
             __LINE__);
      ret = 1;
      goto done;
    }

    key_message km;
    string      key_name(FLAGS_keyname);
    string      key_type(FLAGS_public_key_algorithm);
    string      tag(FLAGS_keyname);
    if (!generate_public_key(&km, key_name, key_type, tag)) {
      printf("%s() error, line %d, cannot generate public key\n",
             __func__,
             __LINE__);
      ret = 1;
      goto done;
    }

    // add key to store and save it
    if (!save_cryptstore(cs,
                         FLAGS_data_dir,
                         FLAGS_encrypted_cryptstore_filename,
                         FLAGS_duration,
                         FLAGS_enclave_type,
                         FLAGS_symmetric_key_algorithm)) {
      printf("%s() error, line %d, cannot save cryptstore\n",
             __func__,
             __LINE__);
      ret = 1;
      goto done;
    }
    goto done;
  } else if (FLAGS_get_item) {

    if (!trust_mgr->initialize_existing_domain(FLAGS_policy_domain_name)) {
      printf("%s() error, line %d, domain %s does not init\n",
             __func__,
             __LINE__,
             FLAGS_policy_domain_name.c_str());
      ret = 1;
      goto done;
    }
    certifiers *c =
        trust_mgr->find_certifier_by_domain_name(FLAGS_policy_domain_name);
    if (c == nullptr) {
      printf("%s() error, line %d, can't find certifier for %s\n",
             __func__,
             __LINE__,
             FLAGS_policy_domain_name.c_str());
      ret = 1;
      goto done;
    }
    if (!c->is_certified_) {
      printf("%s() error, line %d, domain %s snot certified\n",
             __func__,
             __LINE__,
             FLAGS_policy_domain_name.c_str());
      ret = 1;
      goto done;
    }

    cryptstore cs;
    string     entry_tag;
    string     entry_type;
    int        entry_version;
    string     entry_tp;
    string     value;

    if (!open_cryptstore(&cs,
                         FLAGS_data_dir,
                         FLAGS_encrypted_cryptstore_filename,
                         FLAGS_duration,
                         FLAGS_enclave_type,
                         FLAGS_symmetric_key_algorithm)) {
      printf("%s() error, line %d, cannot open cryptstore\n",
             __func__,
             __LINE__);
      ret = 1;
      goto done;
    }
    if (!get_item(cs,
                  entry_tag,
                  &entry_type,
                  &entry_version,
                  &entry_tp,
                  &value)) {
      printf("%s() error, line %d, cannot find %s entry\n",
             __func__,
             __LINE__,
             entry_tag.c_str());
      ret = 1;
      goto done;
    }
#ifdef DEBUG3
    print_cryptstore(cs);
#endif
    goto done;
  } else if (FLAGS_put_item) {

    if (!trust_mgr->initialize_existing_domain(FLAGS_policy_domain_name)) {
      printf("%s() error, line %d, domain %s does not init\n",
             __func__,
             __LINE__,
             FLAGS_policy_domain_name.c_str());
      ret = 1;
      goto done;
    }
    certifiers *c =
        trust_mgr->find_certifier_by_domain_name(FLAGS_policy_domain_name);
    if (c == nullptr) {
      printf("%s() error, line %d, can't find certifier for %s\n",
             __func__,
             __LINE__,
             FLAGS_policy_domain_name.c_str());
      ret = 1;
      goto done;
    }
    if (!c->is_certified_) {
      printf("%s() error, line %d, domain %s snot certified\n",
             __func__,
             __LINE__,
             FLAGS_policy_domain_name.c_str());
      ret = 1;
      goto done;
    }

    cryptstore cs;
    if (!open_cryptstore(&cs,
                         FLAGS_data_dir,
                         FLAGS_encrypted_cryptstore_filename,
                         FLAGS_duration,
                         FLAGS_enclave_type,
                         FLAGS_symmetric_key_algorithm)) {
      printf("%s() error, line %d, cannot open cryptstore\n",
             __func__,
             __LINE__);
      ret = 1;
      goto done;
    }
    string     entry_tag;
    string     entry_type;
    int        entry_version;
    time_point entry_tp;
    string     value;
    if (!put_item(cs, entry_tag, entry_type, entry_version, value)) {
      printf("%s() error, line %d, cannot insert %s entry\n",
             __func__,
             __LINE__,
             entry_tag.c_str());
      ret = 1;
      goto done;
    }
    if (!save_cryptstore(cs,
                         FLAGS_data_dir,
                         FLAGS_encrypted_cryptstore_filename,
                         FLAGS_duration,
                         FLAGS_enclave_type,
                         FLAGS_symmetric_key_algorithm)) {
      printf("%s() error, line %d, cannot save cryptstore\n",
             __func__,
             __LINE__);
      ret = 1;
      goto done;
    }
#ifdef DEBUG3
    print_cryptstore(cs);
#endif
    goto done;
  } else if (FLAGS_print_cryptstore) {
    cryptstore cs;
    if (!open_cryptstore(&cs,
                         FLAGS_data_dir,
                         FLAGS_encrypted_cryptstore_filename,
                         FLAGS_duration,
                         FLAGS_enclave_type,
                         FLAGS_symmetric_key_algorithm)) {
      printf("%s() error, line %d, cannot open cryptstore\n",
             __func__,
             __LINE__);
      ret = 1;
      goto done;
    }
    print_cryptstore(cs);
    goto done;
  } else {
    printf("No action\n");
    goto done;
  }

done:
  trust_mgr->clear_sensitive_data();
  if (trust_mgr != nullptr) {
    delete trust_mgr;
  }
  if (ret == 0) {
    printf("Succeeded\n");
  } else {
    printf("Failed\n");
  }
  return ret;
}

// -------------------------------------------------------------------------------
