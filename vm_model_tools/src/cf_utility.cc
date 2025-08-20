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

DEFINE_string(public_key_algorithm, Enc_method_rsa_2048, "public key algorithm");
DEFINE_string(symmetric_key_algorithm, Enc_method_aes_256_cbc_hmac_sha256,
    "symmetric algorithm");
DEFINE_string(policy_domain_name, "datica", "policy domain name");
DEFINE_string(policy_key_cert_file, "policy_certificate.datica",
    "file name for policy certificate");
DEFINE_string(data_dir, "./", "supporting file directory");
DEFINE_string(input_format, "serialized-protobuf", "input file format");
DEFINE_string(output_format, "serialized-protobuf", "output file format");
DEFINE_string(policy_store_filename, "policy_store.bin.datica",
                "policy store file name");
DEFINE_string(encrypted_cryptstore_filename,
    "encrypted_cryptstore.datica",
    "encrypted cryptstore file name");
DEFINE_string(sealed_cryptstore_key_filename,
     "sealed_cryptstore_key.datica",
     "sealed cryptstore file name");
DEFINE_string(keyname, "primary_store_encryption_key",
     "generated key name");
DEFINE_string(tag, "policy-key", "cryptstore entry tag");
DEFINE_int32(entry_version, 0, "cryptstore entry version");
DEFINE_string(type, "key-message-serialized-protobuf",
                "cryptstore entry data type");
DEFINE_string(output_file, "out_1", "output file name");
DEFINE_string(input_file, "in_1", "input file name");

// For SEV
DEFINE_string(ark_cert_file, "./service/milan_ark_cert.der",
                "machine ark certificate location");
DEFINE_string(ask_cert_file, "./service/milan_ask_cert.der",
                "machine ask certificate location");
DEFINE_string(vcek_cert_file, "./service/milan_vcek_cert.der",
                "machine vcek certificate location");

// For simulated-enclave
DEFINE_string(attest_key_file, "./provisioning/attest_key_file.bin",
                "simulated attestation key");
DEFINE_string(measurement_file, "./provisioning/cf_utility.measurement",
                "simulated enclave measurement");
DEFINE_string(platform_attest_endorsement_file, "./provisioning/platform_attest_endorsement.bin",
                "platform endorsement");

// -------------------------------------------------------------------------

void print_cryptstore_entry(const cryptstore_entry& ent) {
  if (ent.has_tag()) {
    printf("tag: %s\n", ent.tag().c_str());
  }
  if (ent.has_type()) {
    printf("type: %s\n", ent.type().c_str());
  }
  if (ent.has_version()) {
    printf("version: %d\n", (int)ent.version());
  }
  if (ent.has_time_entered()) {
    printf("time entered:\n");
    time_point tp;
    if (tp.ParseFromString(ent.time_entered())) {
      print_time_point(tp);
    } else {
      printf("Can't parse time entered\n");
    }
  }
  if (ent.has_blob()) {
    if (ent.type() == "key_message_serialized-protobuf") {
      key_message km;
      if (km.ParseFromString(ent.blob())) {
        print_key(km);
        printf("\n");
      } else {
        printf("Can't deserialize key message\n");
      }
    } else if (ent.type() == "X509-der-cert") {
      X509* cert= X509_new();
      if (cert != nullptr) {
        if (asn1_to_x509(ent.blob(), cert)) {
          X509_print_fp(stdout, cert);
        } else {
          printf("Can't decode der encoded cert\n");
        }
      }
      X509_free(cert);
    } else {
      printf("Value:\n");
      print_bytes(ent.blob().size(), (byte*)ent.blob().data());
      printf("\n");
    }
  }
}

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
  printf("  Policy store file name: %s\n",
                  FLAGS_policy_store_filename.c_str());
  printf("  Encrypted cryptstore file name: %s\n",
                  FLAGS_encrypted_cryptstore_filename.c_str());
  printf("  Sealed cryptstore key file name: %s\n",
                  FLAGS_sealed_cryptstore_key_filename.c_str());
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
  printf("  Cryptstore entry name: %s\n", FLAGS_tag.c_str());
  printf("  Cryptstore entry version: %d\n", (int)FLAGS_entry_version);
  printf("  Cryptstore entry type: %s\n", FLAGS_type.c_str());
  printf("\n");
  printf("  ARK certificate file: %s\n", FLAGS_ark_cert_file.c_str());
  printf("  ASK certificate file: %s\n", FLAGS_ask_cert_file.c_str());
  printf("  VCEK certificate file: %s\n", FLAGS_vcek_cert_file.c_str());
}

// -----------------------------------------------------------------------------------------

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

  if (!read_file_into_string(FLAGS_data_dir + FLAGS_platform_attest_endorsement_file,
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
  printf("  --policy_key_cert_file=policy_cert_file.datica,"\
                 " name of file with policy domain root cert\n");
  printf("  --policy_store_filename=\"\", name of policy store (as used in certifier\n");
  printf("  --encrypted_cryptstore_filename=encrypted_store.policy_domain_name, file"\
                  " containing encrypted store\n");
  printf("  --sealed_cryptstore_key_filename=encrypted_store.datica.sealed_key, "\
                  "file name of file containing sealed cryptstore key\n");
  printf("  --data_dir=./cf_data, directory for configuration data.\n");
  printf("\n");
  printf("  --init_trust=false, initialize trust domain if needed\n");
  printf("  --reinit_trust=false, unconditionally initialize trust domain if needed\n");
  printf("  --symmetric_algorithm=aes-256-gcm, key type of selected symmetric key\n");
  printf("  --public_key_algorithm=rsa_2048, key type of selected public key\n");
  printf("  --generate_symmetric_key=false, generate a symmetric key of specified key type\n");
  printf("  --generate_public_key=false, generate a public key of specified key type\n");
  printf("  --print_cryptstore=true, print cryptstore\n");
  printf("  --save_cryptstore=false, save cryptstore (normally automatic)\n");
  printf("\n");
  printf("  --tag=\"\", value of tag for put_item\n");
  printf("  --version=0, value of version for put_item\n");
  printf("  --type=\"\", value of type for put_item\n");
  printf("    Possible types: X509-der-cert, key-message-serialized-protobuf, binary-blob\n");
  printf("  --get_item=false, get cryptstore enty of specified tag/value, write to output file\n");
  printf("  --put_item=false, set cryptstore entry of specified tag/value from input file\n");
  printf("  --keyname=store_encryption_key_1, name of keys generated by above calls\n");
  printf("\n");
  printf("  --certifier_service_URL=%s, URL for Certifier Service\n", FLAGS_certifier_service_URL.c_str());
  printf("  --service_port=%d, port-for-certifier-service\n", (int)FLAGS_service_port);
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
  printf("    --vcek_cert_file=%s, file with ark certificate for this machine\n",
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

/*
  optional rsa_message rsa_key              = 4;
  optional ecc_message ecc_key              = 5;
  optional bytes certificate                = 7;
  optional string not_before                = 9;
  optional string not_after                 = 10;
  bool time_now(time_point *t);
  bool time_to_string(time_point &t, string *s);
  bool string_to_time(const string &s, time_point *t);
  bool add_interval_to_time_point(time_point &t_in,
                                  double      hours,
                                  time_point *out);
  int  compare_time(time_point &t1, time_point &t2);
*/

bool cf_generate_symmetric_key(
   key_message* key,
   string key_name,
   string key_type,
   string key_format,
   double duration_in_hours) {

  int num_key_bytes;
  if (key_type == Enc_method_aes_256_cbc_hmac_sha256
      || key_type == Enc_method_aes_256_cbc_hmac_sha384
      || key_type == Enc_method_aes_256_gcm) {
    num_key_bytes = cipher_key_byte_size(key_type.c_str());
    if (num_key_bytes <= 0) {
      printf("%s() error, line %d, Can't recover symmetric alg key size\n",
             __func__,
             __LINE__);
      return false;
    }
  } else {
    printf("%s() error, line %d, unsupported encryption algorithm: '%s'\n",
           __func__,
           __LINE__,
           key_type.c_str());
    return false;
  }
  byte key_bytes[num_key_bytes];
  memset(key_bytes, 0, num_key_bytes);
  if (!get_random(8 * num_key_bytes, key_bytes)) {
    printf("%s() error, line %d, Can't get random bytes for app key\n",
           __func__,
           __LINE__);
    return false;
  }
  key->set_key_name(key_name);
  key->set_key_type(key_type);
  key->set_key_format("vse-key");
  key->set_secret_key_bits((byte*)key_bytes, num_key_bytes);
  time_point tp_not_before;
  time_point tp_not_after;
  if (!time_now(&tp_not_before)) {
    printf("%s() error, line %d, Can't get current time\n",
           __func__,
           __LINE__);
    return false;
  }
  if (!add_interval_to_time_point(tp_not_before,
                                duration_in_hours,
                                &tp_not_after)) {
    printf("%s() error, line %d, Can't add time points\n",
           __func__,
           __LINE__);
    return false;
  }
  string nb_str;
  string na_str;
  if (!time_to_string(tp_not_before, &nb_str)) {
    printf("%s() error, line %d, Can't convert time to string\n",
           __func__,
           __LINE__);
    return false;
  }
  if (!time_to_string(tp_not_after, &na_str)) {
    printf("%s() error, line %d, Can't convert time to string\n",
           __func__,
           __LINE__);
    return false;
  }
  key->set_not_before(nb_str);
  key->set_not_after(na_str);

  return true;
}

bool cf_generate_public_key(
   key_message* key,
   string key_name,
   string key_type,
   string key_format,
   double duration_in_hours) {

  if (key_type == Enc_method_rsa_2048) {
    if (!make_certifier_rsa_key(2048, key)) {
      printf("%s() error, line %d, Can't generate private key\n",
             __func__,
             __LINE__);
      return false;
    }
  } else if (key_type == Enc_method_rsa_3072) {
    if (!make_certifier_rsa_key(3072, key)) {
      printf("%s() error, line %d, Can't generate App private key\n",
             __func__,
             __LINE__);
      return false;
    }
  } else if (key_type == Enc_method_rsa_4096) {
    if (!make_certifier_rsa_key(4096, key)) {
      printf("%s() error, line %d, Can't generate App private key\n",
             __func__,
             __LINE__);
      return false;
    }
  } else if (key_type == Enc_method_ecc_384) {
    if (!make_certifier_ecc_key(384, key)) {
      printf("%s() error, line %d, Can't generate App private key\n",
             __func__,
            __LINE__);
      return false;
    }
  } else {
    printf("%s() error, line %d, Unsupported public key algorithm: '%s'\n",
           __func__,
           __LINE__,
           key_type.c_str());
    return false;
  }

  key->set_key_name(key_name);
  key->set_key_type(key_type);
  key->set_key_format("vse-key");

  time_point tp_not_before;
  time_point tp_not_after;
  if (!time_now(&tp_not_before)) {
    printf("%s() error, line %d, Can't get current time\n",
           __func__,
           __LINE__);
    return false;
  }
  if (!add_interval_to_time_point(tp_not_before,
                                duration_in_hours,
                                &tp_not_after)) {
    printf("%s() error, line %d, Can't add time points\n",
           __func__,
           __LINE__);
    return false;
  }
  string nb_str;
  string na_str;
  if (!time_to_string(tp_not_before, &nb_str)) {
    printf("%s() error, line %d, Can't convert time to string\n",
           __func__,
           __LINE__);
    return false;
  }
  if (!time_to_string(tp_not_after, &na_str)) {
    printf("%s() error, line %d, Can't convert time to string\n",
           __func__,
           __LINE__);
    return false;
  }
  key->set_not_before(nb_str);
  key->set_not_after(na_str);

  return true;
}


// -------------------------------------------------------------------------------------

cc_trust_manager *trust_mgr = nullptr;


bool create_cryptstore(cryptstore& cs) {
  string sealed_key_file_name(FLAGS_data_dir);
  sealed_key_file_name.append(FLAGS_sealed_cryptstore_key_filename);
  string cryptstore_file_name(FLAGS_data_dir);
  cryptstore_file_name.append(FLAGS_encrypted_cryptstore_filename);

  // generate sealing key
  // serialize it
  // encrypt it
  // write file
  return false;
}

bool save_cryptstore(cryptstore& cs) {
  string sealed_key_file_name(FLAGS_data_dir);
  sealed_key_file_name.append(FLAGS_sealed_cryptstore_key_filename);

  string cryptstore_file_name(FLAGS_data_dir);
  cryptstore_file_name.append(FLAGS_encrypted_cryptstore_filename);

  /*
   * int file_size(const string &file_name);

bool read_file(const string &file_name, int *size, byte *data);
bool write_file(const string &file_name, int size, byte *data);

bool read_file_into_string(const string &file_name, string *out);
bool write_file_from_string(const string &file_name, const string &in);

bool digest_message(const char  *alg,
                    const byte  *message,
                    int          message_len,
                    byte        *digest,
                    unsigned int digest_len);


bool authenticated_encrypt(const char *alg,
                           byte       *in,
                           int         in_len,
                           byte       *key,
                           int         key_len,
                           byte       *iv,
                           int         iv_len,
                           byte       *out,
                           int        *out_size);
bool authenticated_decrypt(const char *alg,
                           byte       *in,
                           int         in_len,
                           byte       *key,
                           int         key_len,
                           byte       *out,
                           int        *out_size);
                           bool time_t_to_tm_time(time_t *t, struct tm *tm_time);
bool tm_time_to_time_point(struct tm *tm_time, time_point *tp);
bool asn1_time_to_tm_time(const ASN1_TIME *s, struct tm *tm_time);
bool get_not_before_from_cert(X509 *c, time_point *tp);
bool get_not_after_from_cert(X509 *c, time_point *tp);
bool time_now(time_point *t);
bool time_to_string(time_point &t, string *s);
bool string_to_time(const string &s, time_point *t);
bool add_interval_to_time_point(time_point &t_in,
                                double      hours,
                                time_point *out);
int  compare_time(time_point &t1, time_point &t2);
void print_time_point(time_point &t);
void print_entity(const entity_message &em);
void print_key(const key_message &k);
void print_key(const key_message &k);
  bool generate_symmetric_key(bool regen);
  bool generate_sealing_key(bool regen);
  bool generate_auth_key(bool regen);
  bool generate_service_key(bool regen);

   */
  // get sealing key
  // serialize store 
  // encrypt it
  // write file
  return false;
}

bool open_cryptstore(cryptstore* cs) {
  string sealed_key_file_name(FLAGS_data_dir);
  sealed_key_file_name.append(FLAGS_sealed_cryptstore_key_filename);
  string cryptstore_file_name(FLAGS_data_dir);
  cryptstore_file_name.append(FLAGS_encrypted_cryptstore_filename);

  // get sealing key
  // get encrypted store
  // decrypt it
  // Deserialize
  return false;
}

bool get_existing_trust_domain() {
  string purpose("authentication");
  string store_file(FLAGS_data_dir);
  store_file.append(FLAGS_policy_store_filename);

#if 1
  if (trust_mgr == nullptr) {
    trust_mgr = new cc_trust_manager(FLAGS_enclave_type, purpose, store_file);
    if (trust_mgr == nullptr) {
      printf("%s() error, line %d, couldn't initialize trust object\n",
            __func__,
            __LINE__);
      return false;
    }
  }

  if (!trust_mgr->warm_restart()) {
      printf("%s() error, line %d, warm-restart failed\n", __func__, __LINE__);
      return false;
    }
  return true;
#else
  return false;
#endif
}

bool initialize_new_trust_domain() {
  string purpose("authentication");
  string store_file(FLAGS_policy_store_filename);

#if 1
  if (trust_mgr == nullptr) {
    trust_mgr = new cc_trust_manager(FLAGS_enclave_type, purpose, store_file);
    if (trust_mgr == nullptr) {
      printf("%s() error, line %d, couldn't initialize trust object\n",
            __func__,
            __LINE__);
      return false;
    }
  }

  // read policy cert
  string der_policy_cert_file_name(FLAGS_data_dir);
  der_policy_cert_file_name.append("/provisioning/");
  der_policy_cert_file_name.append(FLAGS_policy_key_cert_file);
  string der_policy_cert;
  if (!read_file_into_string(der_policy_cert_file_name, &der_policy_cert)) {
      printf("%s() error, line %d, couldn't read %s\n",
            __func__,
            __LINE__,
            der_policy_cert.c_str());
      return false;
  }

  // Init policy key info
  if (!trust_mgr->init_policy_key((byte*)der_policy_cert.data(), der_policy_cert.size())) {
    printf("%s() error, line %d, Can't init policy key\n", __func__, __LINE__);
    return false;
  }

  // Get parameters
  string *params = nullptr;
  int     n = 0;
  if (FLAGS_enclave_type == "simulated-enclave") {
    if (!get_simulated_enclave_parameters(&params, &n)) {
      printf("%s() error, line %d, get enclave parameters\n", __func__, __LINE__);
      return false;
    }
  } else if (FLAGS_enclave_type == "sev-enclave") {
    if (!get_sev_enclave_parameters(&params, &n)) {
      printf("%s() error, line %d, get enclave parameters\n", __func__, __LINE__);
      return false;
    }
  } else {
    printf("%s() error, line %d, unsupported enclave\n", __func__, __LINE__);
    return false;
  }

  // Init enclave
  if (!trust_mgr->initialize_enclave(n, params)) {
    printf("%s() error, line %d, Can't init enclave\n", __func__, __LINE__);
    return false;
  }
  if (params != nullptr) {
    delete[] params;
    params = nullptr;
  }

  // app host and port not needed
  string app_host;
  int app_port= 0;
  if (!trust_mgr->cold_init(FLAGS_public_key_algorithm,
                            FLAGS_symmetric_key_algorithm,
                            FLAGS_policy_domain_name,
                            FLAGS_certifier_service_URL,
                            FLAGS_service_port,
                            app_host,
                            app_port)) {
      printf("%s() error, line %d, cold-init failed\n", __func__, __LINE__);
      return false;
    }

  if (!trust_mgr->certify_me()) {
    printf("%s() error, line %d, certification failed\n", __func__, __LINE__);
    return false;
  }
#ifdef DEBUG
  trust_mgr->print_trust_data();
#endif  // DEBUG
  return true;
#else
  return false;
#endif
}

bool generate_symmetric_key(key_message* km, string& name, string& key_type) {
  return false;
}

bool generate_public_key(key_message* km, string& name, string& key_type) {
  return false;
}

bool get_item(string& tag, string* type, int* version, time_point* tp,
                string* blob) {
  return false;
}

bool put_item(string& tag, string& type, int& version, string& blob) {
  return false;
}

void print_cryptstore(cryptstore& cs) {
  printf("\nCryptstore:\n");
  for (int i = 0; i < cs.entries_size(); i++) {
    print_cryptstore_entry(cs.entries(i));
  }
}


int main(int an, char **av) {
  string usage("cf-osutility");
  gflags::SetUsageMessage(usage);
  gflags::ParseCommandLineFlags(&an, &av, true);
  an = 1;
  ::testing::InitGoogleTest(&an, av);
  int ret = 0;

  if (FLAGS_cf_utility_help) {
    print_help();
    return ret;
  }
  print_os_model_parameters();

  SSL_library_init();
  string purpose("authentication");

  if (FLAGS_init_trust) {

    if (!get_existing_trust_domain()) {
      if (!initialize_new_trust_domain()) {
        printf("%s() error, line %d, cannot initialize new trust domain\n",
               __func__, __LINE__);
        ret= 1;
        goto done;
      } 

      // get or initialize cryptstore
      cryptstore cs;
      if (!open_cryptstore(&cs)) {
        printf("%s() error, line %d, cannot open cryptstore\n",
              __func__, __LINE__);
        ret= 1;
        goto done;
      }
      // add keys and certificates
      if (!save_cryptstore(cs)) {
        printf("%s() error, line %d, cannot save cryptstore\n",
              __func__, __LINE__);
        ret= 1;
        goto done;
      }
    }
    goto done;
  } else if (FLAGS_reinit_trust) {
    cryptstore cs;
    if (!initialize_new_trust_domain()) {
      printf("%s() error, line %d, cannot initialize new trust domain\n",
             __func__, __LINE__);
      ret= 1;
      goto done;
    }

    // get or initialize cryptstore
    if (!open_cryptstore(&cs)) {
      printf("%s() error, line %d, cannot open cryptstore\n",
            __func__, __LINE__);
      ret= 1;
      goto done;
    }
    // add keys and certificates
    if (!save_cryptstore(cs)) {
      printf("%s() error, line %d, cannot save cryptstore\n",
            __func__, __LINE__);
      ret= 1;
      goto done;
    }
    goto done;
  } else if (FLAGS_generate_symmetric_key) {

    // open existing trust domain to get cryptstore
    if (!get_existing_trust_domain()) {
      printf("%s() error, line %d, cannot recover existing domain\n",
             __func__, __LINE__);
      ret= 1;
      goto done;
    }
    cryptstore cs;

    if (!open_cryptstore(&cs)) {
      printf("%s() error, line %d, cannot open cryptstore\n",
             __func__, __LINE__);
      ret= 1;
      goto done;
    }
    key_message km;
    string key_name;
    string key_type;
    if (!generate_symmetric_key(&km, key_name, key_type)) {
      printf("%s() error, line %d, cannot generate symmetric key\n",
            __func__, __LINE__);
      ret= 1;
      goto done;
    }
    // add key to store and save it
    if (!save_cryptstore(cs)) {
      printf("%s() error, line %d, cannot save cryptstore\n",
            __func__, __LINE__);
      ret= 1;
      goto done;
    }
    goto done;
  } else if (FLAGS_generate_public_key) {

    // open existing trust domain to get cryptstore
    if (!get_existing_trust_domain()) {
      printf("%s() error, line %d, cannot recover existing domain\n",
             __func__, __LINE__);
      ret= 1;
      goto done;
    }
    cryptstore cs;

    if (!open_cryptstore(&cs)) {
      printf("%s() error, line %d, cannot open cryptstore\n",
             __func__, __LINE__);
      ret= 1;
      goto done;
    }
    key_message km;
    string key_name;
    string key_type;
    if (!generate_public_key(&km, key_name, key_type)) {
      printf("%s() error, line %d, cannot generate public key\n",
            __func__, __LINE__);
      ret= 1;
      goto done;
    }
    // add key to store and save it
    if (!save_cryptstore(cs)) {
      printf("%s() error, line %d, cannot save cryptstore\n",
            __func__, __LINE__);
      ret= 1;
      goto done;
    }
    goto done;
  } else if (FLAGS_get_item) {

    // open existing trust domain to get cryptstore
    if (!get_existing_trust_domain()) {
      printf("%s() error, line %d, cannot recover existing domain\n",
             __func__, __LINE__);
      ret= 1;
      goto done;
    }
    cryptstore cs;

    string entry_tag;
    string entry_type;
    int entry_version;
    time_point entry_tp;
    string value;

    if (!open_cryptstore(&cs)) {
      printf("%s() error, line %d, cannot open cryptstore\n",
             __func__, __LINE__);
      ret= 1;
      goto done;
    }
    if (!get_item(entry_tag, &entry_type, &entry_version, &entry_tp, &value)) {
      printf("%s() error, line %d, cannot find %s entry\n",
            __func__, __LINE__, entry_tag.c_str());
      ret= 1;
      goto done;
    }
    goto done;
  } else if (FLAGS_put_item) {

    // open existing trust domain to get cryptstore
    if (!get_existing_trust_domain()) {
      printf("%s() error, line %d, cannot recover existing domain\n",
             __func__, __LINE__);
      ret= 1;
      goto done;
    }
    cryptstore cs;

    if (!open_cryptstore(&cs)) {
      printf("%s() error, line %d, cannot open cryptstore\n",
             __func__, __LINE__);
      ret= 1;
      goto done;
    }

    string entry_tag;
    string entry_type;
    int entry_version;
    time_point entry_tp;
    string value;
    if (!put_item(entry_tag, entry_type, entry_version, value)) {
      printf("%s() error, line %d, cannot insert %s entry\n",
            __func__, __LINE__, entry_tag.c_str());
      ret= 1;
      goto done;
    }
    // add key to store and save it
    if (!save_cryptstore(cs)) {
      printf("%s() error, line %d, cannot save cryptstore\n",
            __func__, __LINE__);
      ret= 1;
      goto done;
    }
    goto done;
  } else if (FLAGS_print_cryptstore) {

    // open existing trust domain to get cryptstore
    if (!get_existing_trust_domain()) {
      printf("%s() error, line %d, cannot recover existing domain\n",
             __func__, __LINE__);
      ret= 1;
      goto done;
    }
    cryptstore cs;

    if (!open_cryptstore(&cs)) {
      printf("%s() error, line %d, cannot open cryptstore\n",
             __func__, __LINE__);
      ret= 1;
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
  return ret;
}
