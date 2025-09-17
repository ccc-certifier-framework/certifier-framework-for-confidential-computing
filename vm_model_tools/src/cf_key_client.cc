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

// cf_key_client

//  -------------------------------------------------------------------

DEFINE_bool(cf_key_client_help, false, "provide help");
DEFINE_string(enclave_type, "simulated-enclave", "supporting enclave type");

DEFINE_string(policy_domain_name, "datica", "policy domain name");
DEFINE_string(policy_key_cert_file,
              "policy_certificate.datica",
              "file name for policy certificate");

DEFINE_bool(print_cryptstore, true, "print cryptstore");

DEFINE_string(public_key_algorithm,
              Enc_method_rsa_2048,
              "public key algorithm");
DEFINE_string(symmetric_key_algorithm,
              Enc_method_aes_256_cbc_hmac_sha256,
              "symmetric algorithm");

DEFINE_string(data_dir, "./cf_data", "supporting file directory");
DEFINE_string(input_format, "cryptstore-entry", "input format");
DEFINE_string(output_format, "cryptstore-entry", "output format");
DEFINE_string(input_file, "in", "input file");
DEFINE_string(output_file, "out", "output file");

DEFINE_string(policy_store_filename,
              "policy_store.bin.datica",
              "policy store file name");
DEFINE_string(encrypted_cryptstore_filename,
              "encrypted_cryptstore.datica",
              "encrypted cryptstore file name");
DEFINE_string(key_server_url, "localhost", "address of the key service");
DEFINE_int32(key_server_port, 8120, "port for key service");

DEFINE_double(duration, 24.0 * 365.0, "duration of key");
DEFINE_string(resource_name, "", "resource name");
DEFINE_int32(version, 0, "version");
DEFINE_string(action, "retrieve", "retrieve or store");

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

void print_parameters() {
  printf("cf_key_client parameters:\n");
  printf("\n");

  if (FLAGS_print_cryptstore)
    printf("  Print cryptstore?: yes\n");
  else
    printf("  Print cryptstore?: no\n");
  printf("\n");

  printf("  Policy doman name: %s\n", FLAGS_policy_domain_name.c_str());
  printf("  Policy_key_cert_file: %s\n", FLAGS_policy_key_cert_file.c_str());
  printf("  key-server url: %s\n", FLAGS_key_server_url.c_str());
  printf("  key-server port: %d\n", (int)FLAGS_key_server_port);
  printf("\n");

  printf("  Policy store file name: %s\n", FLAGS_policy_store_filename.c_str());
  printf("  Encrypted cryptstore file name: %s\n",
         FLAGS_encrypted_cryptstore_filename.c_str());
  printf("  Directory for cf_utility supporting data for this policy: %s\n",
         FLAGS_data_dir.c_str());
  printf("\n");
  printf("  Protecting enclave type: %s\n", FLAGS_enclave_type.c_str());
  printf("  Input file name: %s\n", FLAGS_input_file.c_str());
  printf("  Output file name: %s\n", FLAGS_output_file.c_str());
  printf("\n");

  printf("  Public key algorithm: %s\n", FLAGS_public_key_algorithm.c_str());
  printf("  Symmetric key algorithm: %s\n",
         FLAGS_symmetric_key_algorithm.c_str());
  printf("  Duration: %lf\n", FLAGS_duration);
  printf("\n");
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

  if (!read_file_into_string(FLAGS_attest_key_file, &args[0])) {
    printf("%s() error, line %d, Can't read attest file\n", __func__, __LINE__);
    goto err;
  }

  if (!read_file_into_string(FLAGS_measurement_file, &args[1])) {
    printf("%s() error, line %d, Can't read measurement file\n",
           __func__,
           __LINE__);
    goto err;
  }

  if (!read_file_into_string(FLAGS_platform_attest_endorsement_file,
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
  printf("cf_key_client.exe\n");
  printf("  --cf_key_client_help=false, print this help message\n");
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

  printf("  --action=retrieve|store, value of version\n");
  printf("  --version=0, value of version for put_item\n");
  printf("  --get_item=false, get cryptstore enty of specified tag/value, "
         "write to output file\n");
  printf("  --put_item=false, set cryptstore entry of specified tag/value from "
         "input file\n");
  printf("  --keyname=store_encryption_key_1, name of keys generated by above "
         "calls\n");
  printf("  --duration=time in hours, duration of keys or certs\n");
  printf("\n");

  printf("  --input_format=key-message-serialized-protobuf, input format\n");
  printf("  --output_format=key-message-serialized-protobuf, output format\n");
  printf("\n");

  printf("  --input_format=%s, input format (crayptstore-entry or raw)\n",
         FLAGS_input_format.c_str());
  printf("  --output_format=%s, output format (crayptstore-entry or raw)\n",
         FLAGS_output_format.c_str());
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
cryptstore        g_cs;
string            g_serialized_policy_cert;
key_message       g_my_private_key;
string            g_serialized_admissions_cert;

bool error_response(key_service_message_response *response,
                    string                       *serialized_response) {
  response->set_status("failed");
  return response->SerializeToString(serialized_response);
}

bool client_application(secure_authenticated_channel &channel) {

  key_service_message_request  request;
  key_service_message_response response;
  string                       serialized_request;
  string                       serialized_response;

  printf("Client peer id is %s\n", channel.peer_id_.c_str());

#ifdef DEBUG7
  if (channel.peer_cert_ != nullptr) {
    printf("Client peer cert is:\n");
    X509_print_fp(stdout, channel.peer_cert_);
  }
#endif  // DEBUG

  // Construct request
  cryptstore_entry cf;
  string           serialized_cs_entry;
  request.set_resource_name(FLAGS_resource_name);
  request.set_version(FLAGS_version);

  if (FLAGS_action == "retrieve") {
    request.set_request_type("retrieve");
  } else if (FLAGS_action == "store") {

    string tag;
    string type;
    string value;
    int    version;
    string time_entered;
    bool   exportable;

    request.set_request_type("store");
    if (FLAGS_input_format == "raw") {

      if (!read_file_into_string(FLAGS_input_file, &value)) {
        printf("Can't read %s\n", FLAGS_input_file.c_str());
        if (error_response(&response, &serialized_response))
          channel.write((int)serialized_response.size(),
                        (byte *)serialized_response.data());
        channel.close();
        return true;
      }
      request.set_resource_name(FLAGS_resource_name);
      request.set_version(FLAGS_version);
      request.set_value_type("binary-blob");
      request.set_data(value);

    } else if (FLAGS_input_format == "cryptstore-entry") {

      if (!read_file_into_string(FLAGS_input_file, &serialized_cs_entry)) {
        printf("Can't read %s\n", FLAGS_input_file.c_str());
        if (error_response(&response, &serialized_response))
          channel.write((int)serialized_response.size(),
                        (byte *)serialized_response.data());
        channel.close();
        return true;
      }
      if (!cf.ParseFromString(serialized_cs_entry)) {
        printf("Can't parse string\n");
        if (error_response(&response, &serialized_response))
          channel.write((int)serialized_response.size(),
                        (byte *)serialized_response.data());
        channel.close();
        return true;
      }

      request.set_resource_name(cf.tag());
      request.set_version(cf.version());
      request.set_value_type(request.value_type());
      request.set_data(serialized_cs_entry);

    } else {

      printf("Unknown input format\n");
      if (error_response(&response, &serialized_response))
        channel.write((int)serialized_response.size(),
                      (byte *)serialized_response.data());
      channel.close();
      return true;
    }

  } else {
    channel.close();
    return true;
  }

#ifdef DEBUG7
  printf("cf_key_client request to send\n");
  print_request_packet(request);
#endif

  // Serialize request
  if (!request.SerializeToString(&serialized_request)) {
    printf("Couldn't serialize request\n");
    if (error_response(&response, &serialized_response))
      channel.write((int)serialized_response.size(),
                    (byte *)serialized_response.data());
    channel.close();
    return true;
  }

  // Send serialized request over authenticated, encrypted channel
  channel.write((int)serialized_request.size(),
                (byte *)serialized_request.data());

  // Get server response over authenticated, encrypted channel
  int n = channel.read(&serialized_response);

#ifdef DEBUG7
  printf("SSL client read: %d\n", (int)serialized_response.size());
#endif
  channel.close();

  if (!response.ParseFromString(serialized_response)) {
    printf("Couldn't parse response\n");
    return true;
  }

#ifdef DEBUG7
  printf("cf_key_client response received\n");
  print_response_packet(response);
#endif

  if (response.status() != "succeeded") {
    printf("Request for %s failed\n", response.resource_name().c_str());
    return true;
  }

#ifdef DEBUG7
  printf("Request succeeded\n");
#endif

  // print data and write value
  cryptstore_entry ce;
  string           serialized_cryptstore_entry;

  serialized_cryptstore_entry.assign((char *)response.data().data(),
                                     (int)response.data().size());
  if (!ce.ParseFromString(serialized_cryptstore_entry)) {
    printf("Couldn't parse cryptstore in response\n");
    return true;
  }

#ifdef DEBUG7
  printf("\nResponse entry:\n");
  print_cryptstore_entry(ce);
#endif

  if (FLAGS_output_format == "cryptstore-entry") {
    if (!write_file_from_string(FLAGS_output_file,
                                serialized_cryptstore_entry)) {
      printf("Couldn't write output file %s\n", FLAGS_output_file.c_str());
      return true;
    }
  } else {
    string value;
    value.assign((char *)ce.blob().data(), (int)ce.blob().size());
    if (!write_file_from_string(FLAGS_output_file, value)) {
      printf("Couldn't write output file %s\n", FLAGS_output_file.c_str());
      return true;
    }
    return true;
  }

  return true;
}


int main(int an, char **av) {
  string usage("cf_key_client");
  gflags::SetUsageMessage(usage);
  gflags::ParseCommandLineFlags(&an, &av, true);
  an = 1;
  int         ret = 0;
  certifiers *c = nullptr;
  string      tag;
  string      type;
  string      value;
  int         version;
  string      tp;
  bool        exportable;
  string      policy_cert_file_name;
  string      my_role("client");

  SSL_library_init();
  string purpose("authentication");

  if (FLAGS_cf_key_client_help) {
    print_help();
    return ret;
  }
  print_parameters();

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

  secure_authenticated_channel channel(my_role);

  string store_file(FLAGS_data_dir);
  store_file.append(FLAGS_policy_store_filename);
#ifdef DEBUG3
  printf("\npolicy store: %s\n", store_file.c_str());
#endif

  // Create trust manager
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

  if (!trust_mgr->initialize_existing_domain(FLAGS_policy_domain_name)) {
    printf("%s() error, line %d, domain %s does not init\n",
           __func__,
           __LINE__,
           FLAGS_policy_domain_name.c_str());
    ret = 1;
    goto done;
  }
  c = trust_mgr->find_certifier_by_domain_name(FLAGS_policy_domain_name);
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

  // Get policy-cert, admissions_cert and private-key
  // Put them in
  //    g_serialized_policy_cert;
  //    g_serialized_admissions_cert;  tag is domain-name-admission-certificate
  //    g_my_private_key;  tag is domain-name-private-auth-key
  policy_cert_file_name = FLAGS_data_dir;
  policy_cert_file_name.append("cf_data/");
  policy_cert_file_name.append(FLAGS_policy_key_cert_file);
  if (!read_file_into_string(policy_cert_file_name,
                             &g_serialized_policy_cert)) {
    printf("%s() error, line %d, can't read policy cert \n",
           __func__,
           __LINE__);
    ret = 1;
    goto done;
  }

  // Admissions cert tag is domain-name-admission-certificate
  //    g_serialized_admissions_cert
  // Private key tag is domain-name-private-auth-key
  //    g_my_private_key
  tag = FLAGS_policy_domain_name;
  tag.append("-admission-certificate");
  if (!get_item(g_cs,
                tag,
                &type,
                &version,
                &tp,
                &g_serialized_admissions_cert,
                &exportable)) {
    printf("%s() error, line %d, can't retrieve admissions cert\n",
           __func__,
           __LINE__);
    ret = 1;
    goto done;
  }
  // g_my_private_key tag is domain-name-private-auth-key
  tag.clear();
  type.clear();
  tp.clear();
  version = 0;
  tag = FLAGS_policy_domain_name;
  tag.append("-private-auth-key");
  if (!get_item(g_cs, tag, &type, &version, &tp, &value, &exportable)) {
    printf("%s() error, line %d, can't retrieve private key\n",
           __func__,
           __LINE__);
    ret = 1;
    goto done;
  }
  if (!g_my_private_key.ParseFromString(value)) {
    printf("%s() error, line %d, can't parse private key\n",
           __func__,
           __LINE__);
    ret = 1;
    goto done;
  }

  if (!channel.init_client_ssl(FLAGS_policy_domain_name,
                               FLAGS_key_server_url,
                               FLAGS_key_server_port,
                               *trust_mgr)) {
    printf("%s() error, line %d, Can't init client app\n", __func__, __LINE__);
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
