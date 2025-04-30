// Copyright 2014-2025 John Manferdelli, All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// or in the the file LICENSE-2.0.txt in the top level sourcedirectory
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License
// File: satandalone_app.cc

#include <gtest/gtest.h>
#include <gflags/gflags.h>
#include <stdio.h>

#include "certifier.h"
#include "support.h"
#include "certifier.pb.h"
#include "acl.pb.h"
#include "acl_support.h"
#include "acl.h"
#include "acl_rpc.h"

using namespace certifier::framework;
using namespace certifier::utilities;
using namespace certifier::acl_lib;

DEFINE_bool(print_all, false, "verbose");

// operations:
//    make_access_keys_and_files, test_constructed_keys_and_files,
//    make_additional_channel_keys
//    run_as_client, run_as_server
DEFINE_string(operation, "", "operation");

DEFINE_string(app_host, "localhost", "address for server");
DEFINE_int32(app_port, 8124, "port for server");

DEFINE_string(data_dir, "./test_data/", "directory for files");
DEFINE_string(policy_cert_file, "policy_cert_file.bin", "policy cert file");
DEFINE_string(policy_key_file, "policy_key_file.bin", "policy key file");
DEFINE_string(client_auth_key_file,
              "client_auth_key_file.bin",
              "client auth key file");
DEFINE_string(client_auth_cert_file,
              "client_auth_cert_file.bin",
              "client auth cert file");
DEFINE_string(server_auth_key_file,
              "server_auth_key_file.bin",
              "server auth key file");
DEFINE_string(server_auth_cert_file,
              "server_auth_cert_file.bin",
              "server auth cert file");
DEFINE_string(cert_chain1, "cert_chain1.bin", "First certificate chain");
DEFINE_string(cert_chain2, "cert_chain2.bin", "Second certificate chain");
DEFINE_string(identity_root_signing_key,
              "identity_root_signing_key.bin",
              "Identity root's signing key");
DEFINE_string(client1_signing_key,
              "client1_signing_key.bin",
              "First client's signing key");
DEFINE_string(client2_signing_key,
              "client2_signing_key.bin",
              "Second client's signing key");
DEFINE_string(resource_list, "saved_resources.bin", "resource list file");
DEFINE_string(principal_list, "saved_principals.bin", "principal list file");


#define DEBUG

// Now that these are global, updates must lock it.
namespace certifier {
namespace acl_lib {

resource_list  g_rl;
principal_list g_pl;
}  // namespace acl_lib
}  // namespace certifier

bool construct_sample_principals(principal_list *pl) {
  string p1("john");
  string p2("paul");
  string alg("none");
  string cred;
  if (!add_principal_to_proto_list(p1, alg, cred, pl)) {
    return false;
  }
  if (!add_principal_to_proto_list(p2, alg, cred, pl)) {
    return false;
  }
  return true;
}

bool construct_sample_resources(resource_list *rl) {
  string     p1("john");
  string     p2("paul");
  string     r1("file_1");
  string     r2("file_2");
  string     l1;
  string     l2;
  string     t;
  string     ty("file");
  time_point tp;

  l1 = FLAGS_data_dir + r1;
  l2 = FLAGS_data_dir + r2;

  if (!time_now(&tp))
    return false;
  if (!encode_time(tp, &t))
    return false;
  if (!add_resource_to_proto_list(r1, ty, l1, t, t, rl)) {
    return false;
  }
  if (!add_resource_to_proto_list(r2, ty, l2, t, t, rl)) {
    return false;
  }
  if (!add_reader_to_resource_proto_list(p1, rl->mutable_resources(0)))
    return false;
  if (!add_reader_to_resource_proto_list(p2, rl->mutable_resources(1)))
    return false;
  if (!add_reader_to_resource_proto_list(p1, rl->mutable_resources(1)))
    return false;
  if (!add_writer_to_resource_proto_list(p1, rl->mutable_resources(0)))
    return false;
  if (!add_writer_to_resource_proto_list(p2, rl->mutable_resources(1)))
    return false;
  if (!add_writer_to_resource_proto_list(p1, rl->mutable_resources(1)))
    return false;
  if (!add_creator_to_resource_proto_list(p1, rl->mutable_resources(0)))
    return false;
  if (!add_creator_to_resource_proto_list(p2, rl->mutable_resources(1)))
    return false;
  return true;
}

bool make_keys_and_certs(string      &root_issuer_name,
                         string      &root_issuer_org,
                         string      &signing_subject_name,
                         string      &signing_subject_org,
                         key_message *root_key,
                         key_message *signer_key,
                         buffer_list *list) {
  bool ret = true;

  key_message public_root_key;
  key_message public_signer_key;
  const char *alg = Enc_method_rsa_2048_sha256_pkcs_sign;

  RSA  *r1 = nullptr;
  RSA  *r2 = nullptr;
  X509 *root_cert = nullptr;
  X509 *signing_cert = nullptr;

  string root_asn1_cert_str;
  string signing_asn1_cert_str;

  uint64_t sn = 1;
  uint64_t duration = 86400 * 366;

  int     sig_size = 256;
  byte    sig[sig_size];
  string *ptr_str = nullptr;

  r1 = RSA_new();
  if (r1 == nullptr) {
    printf("%s() error, line: %d, cannt RSA_new \n", __func__, __LINE__);
    ret = false;
    goto done;
  }
  if (!generate_new_rsa_key(2048, r1)) {
    printf("%s() error, line: %d, generate_new_rsa_key failed\n",
           __func__,
           __LINE__);
    return false;
  }
  if (!RSA_to_key(r1, root_key)) {
    printf("%s() error, line: %d, RSA_to_key failed\n", __func__, __LINE__);
    ret = false;
    goto done;
  }
  root_key->set_key_name("identity-root");
  if (FLAGS_print_all) {
    printf("root key:\n");
    print_key((const key_message)*root_key);
  }
  if (!private_key_to_public_key(*root_key, &public_root_key)) {
    printf("%s() error, line: %d, private_to_public failed\n",
           __func__,
           __LINE__);
    ret = false;
    goto done;
  }

  r2 = RSA_new();
  if (r2 == nullptr) {
    printf("%s() error, line: %d, cannt RSA_new \n", __func__, __LINE__);
    ret = false;
    goto done;
  }
  if (!generate_new_rsa_key(2048, r2)) {
    printf("%s() error, line: %d, generate_new_rsa_key failed\n",
           __func__,
           __LINE__);
    ret = false;
    goto done;
  }
  if (!RSA_to_key(r2, signer_key)) {
    printf("%s() error, line: %d, RSA_to_key failed\n", __func__, __LINE__);
    ret = false;
    goto done;
  }
  signer_key->set_key_name("johns_signing-key");
  if (FLAGS_print_all) {
    printf("signing key:\n");
    print_key((const key_message &)*signer_key);
  }
  if (!private_key_to_public_key(*signer_key, &public_signer_key)) {
    printf("%s() error, line: %d, private_to_public failed\n",
           __func__,
           __LINE__);
    ret = false;
    goto done;
  }

  // root cert
  root_cert = X509_new();
  if (!produce_artifact(*root_key,
                        root_issuer_name,
                        root_issuer_org,
                        public_root_key,
                        root_issuer_name,
                        root_issuer_org,
                        sn,
                        duration,
                        root_cert,
                        true)) {
    printf("%s() error, line %d: cant generate root cert\n",
           __func__,
           __LINE__);
    ret = false;
    goto done;
  }
  sn++;
  if (!x509_to_asn1(root_cert, &root_asn1_cert_str)) {
    printf("%s() error, line %d: cant asn1 translate root cert\n",
           __func__,
           __LINE__);
    ret = false;
    goto done;
  }

  // signing cert
  signing_cert = X509_new();
  if (!produce_artifact(*root_key,
                        root_issuer_name,
                        root_issuer_org,
                        public_signer_key,
                        signing_subject_name,
                        signing_subject_org,
                        sn,
                        duration,
                        signing_cert,
                        false)) {
    printf("%s() error, line %d: cant generate signing cert\n",
           __func__,
           __LINE__);
    ret = false;
    goto done;
  }
  if (!x509_to_asn1(signing_cert, &signing_asn1_cert_str)) {
    printf("%s() error, line %d: cant asn1 translate signing cert\n",
           __func__,
           __LINE__);
    ret = false;
    goto done;
  }

  if (FLAGS_print_all) {
    printf("root cert:\n");
    X509_print_fp(stdout, root_cert);
    printf("\n");
    printf("signing cert:\n");
    X509_print_fp(stdout, signing_cert);
    printf("\n");
  }

  ptr_str = list->add_blobs();
  if (ptr_str == nullptr) {
    printf("%s() error, line %d: cant allocate blobs\n", __func__, __LINE__);
    ret = false;
    goto done;
  }
  *ptr_str = root_asn1_cert_str;
  ptr_str = list->add_blobs();
  if (ptr_str == nullptr) {
    printf("%s() error, line %d: cant allocate blobs\n", __func__, __LINE__);
    ret = false;
    goto done;
  }
  *ptr_str = signing_asn1_cert_str;

done:
  if (r1 != nullptr) {
    RSA_free(r1);
    r1 = nullptr;
  }
  if (r2 != nullptr) {
    RSA_free(r2);
    r2 = nullptr;
  }
  if (root_cert != nullptr) {
    X509_free(root_cert);
    root_cert = nullptr;
  }
  if (signing_cert != nullptr) {
    X509_free(signing_cert);
    signing_cert = nullptr;
  }
  return ret;
}

bool make_admissions_cert(const string      &role,
                          const key_message &policy_key,
                          const key_message &auth_key,
                          string            *out) {
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

// the policy key and cert are created by cert_utility
// we need to add admission certificate and keys for
// the client and server
bool make_additional_channel_keys() {
  // make auth keys and admissions certs

  key_message policy_key;
  string      policy_cert;

  string policy_cert_file_name = FLAGS_data_dir + FLAGS_policy_cert_file;
  string policy_key_file_name = FLAGS_data_dir + FLAGS_policy_key_file;
  string serialized_policy_key;

  bool ret = true;

  uint64_t sn = 1;
  uint64_t duration = 86400 * 366;
  RSA     *r1 = nullptr;
  RSA     *r2 = nullptr;

  key_message client_auth_key;
  key_message client_public_auth_key;
  string      client_auth_cert;
  key_message server_auth_key;
  key_message server_public_auth_key;
  string      server_auth_cert;
  string      role;

  string client_auth_key_str;
  string server_auth_key_str;

  string client_auth_key_file_name =
      FLAGS_data_dir + FLAGS_client_auth_key_file;
  string client_auth_cert_file_name =
      FLAGS_data_dir + FLAGS_client_auth_cert_file;
  string server_auth_key_file_name =
      FLAGS_data_dir + FLAGS_server_auth_key_file;
  string server_auth_cert_file_name =
      FLAGS_data_dir + FLAGS_server_auth_cert_file;

  // first read the policy key and policy cert
  if (!read_file_into_string(policy_cert_file_name, &policy_cert)) {
    printf("%s() error, line: %d, can't read policy cert\n",
           __func__,
           __LINE__);
    ret = false;
    goto done;
  }
  if (!read_file_into_string(policy_key_file_name, &serialized_policy_key)) {
    printf("%s() error, line: %d, can't read policy key\n", __func__, __LINE__);
    ret = false;
    goto done;
  }

  if (!policy_key.ParseFromString(serialized_policy_key)) {
    printf("%s() error, line: %d, can't deserialize policy key\n",
           __func__,
           __LINE__);
    ret = false;
    goto done;
  }

  r1 = RSA_new();
  if (r1 == nullptr) {
    printf("%s() error, line: %d, can't RSA_new \n", __func__, __LINE__);
    ret = false;
    goto done;
  }
  if (!generate_new_rsa_key(2048, r1)) {
    printf("%s() error, line: %d, generate_new_rsa_key failed\n",
           __func__,
           __LINE__);
    return false;
  }
  if (!RSA_to_key(r1, &client_auth_key)) {
    printf("%s() error, line: %d, RSA_to_key failed\n", __func__, __LINE__);
    ret = false;
    goto done;
  }
  client_auth_key.set_key_name("client-auth-key");
  if (FLAGS_print_all) {
    printf("client auth key:\n");
    print_key((const key_message)client_auth_key);
  }

  if (!private_key_to_public_key(client_auth_key, &client_public_auth_key)) {
    printf("%s() error, line: %d, private_to_public failed\n",
           __func__,
           __LINE__);
    ret = false;
    goto done;
  }

  r2 = RSA_new();
  if (r2 == nullptr) {
    printf("%s() error, line: %d, cannt RSA_new \n", __func__, __LINE__);
    ret = false;
    goto done;
  }
  if (!generate_new_rsa_key(2048, r2)) {
    printf("%s() error, line: %d, generate_new_rsa_key failed\n",
           __func__,
           __LINE__);
    ret = false;
    goto done;
  }
  if (!RSA_to_key(r2, &server_auth_key)) {
    printf("%s() error, line: %d, RSA_to_key failed\n", __func__, __LINE__);
    ret = false;
    goto done;
  }
  server_auth_key.set_key_name("server-auth-key");
  if (FLAGS_print_all) {
    printf("server auth key:\n");
    print_key((const key_message &)server_auth_key);
  }
  if (!private_key_to_public_key(server_auth_key, &server_public_auth_key)) {
    printf("%s() error, line: %d, private_to_public failed\n",
           __func__,
           __LINE__);
    ret = false;
    goto done;
  }

  role = "client";
  if (!make_admissions_cert(role,
                            policy_key,
                            client_auth_key,
                            &client_auth_cert)) {
    printf("%s, error, line %d can't make client admissions cert\n",
           __func__,
           __LINE__);
    ret = false;
    goto done;
  }
  client_auth_key.set_certificate(client_auth_cert);


  role = "server";
  if (!make_admissions_cert(role,
                            policy_key,
                            server_auth_key,
                            &server_auth_cert)) {
    printf("%s, error, line %d can't make server admissions cert\n",
           __func__,
           __LINE__);
    ret = false;
    goto done;
  }
  server_auth_key.set_certificate(server_auth_cert);

  // Save all the keys and certs

  if (!client_auth_key.SerializeToString(&client_auth_key_str)) {
    printf("%s, error, line %d can't serialize client auth key\n",
           __func__,
           __LINE__);
    ret = false;
    goto done;
  }
  if (!server_auth_key.SerializeToString(&server_auth_key_str)) {
    printf("%s, error, line %d can't serialize server auth key\n",
           __func__,
           __LINE__);
    ret = false;
    goto done;
  }

  if (!write_file(client_auth_cert_file_name,
                  client_auth_cert.size(),
                  (byte *)client_auth_cert.data())) {
    printf("%s, error, line %d can't write client auth cert\n",
           __func__,
           __LINE__);
    ret = false;
    goto done;
  }
  if (!write_file(server_auth_cert_file_name,
                  server_auth_cert.size(),
                  (byte *)server_auth_cert.data())) {
    printf("%s, error, line %d can't write server auth cert\n",
           __func__,
           __LINE__);
    ret = false;
    goto done;
  }
  if (!write_file(client_auth_key_file_name,
                  client_auth_key_str.size(),
                  (byte *)client_auth_key_str.data())) {
    printf("%s, error, line %d can't write client auth key\n",
           __func__,
           __LINE__);
    ret = false;
    goto done;
  }
  if (!write_file(server_auth_key_file_name,
                  server_auth_key_str.size(),
                  (byte *)server_auth_key_str.data())) {
    printf("%s, error, line %d can't write server auth key\n",
           __func__,
           __LINE__);
    ret = false;
    goto done;
  }

done:
  return ret;
}

// These are the keys and certs for the file access (acl_lib)
// functionality.  We trust the root of the file access signing
// regime but in a real application, you need to decide how to
// do this securely.
bool make_access_keys_and_files() {

  bool        ret = true;
  string      signing_subject_name("john");
  string      signing_subject_org("datica");
  string      root_issuer_name("datica-identity-root");
  string      root_issuer_org("datica");
  const char *auth_alg = Enc_method_rsa_2048_sha256_pkcs_sign;
  EVP_PKEY   *pkey = nullptr;
  RSA        *r2 = nullptr;
  string      serialized_cert_chain_str;
  string      identity_root_asn1_cert_str;
  key_message identity_root_key;
  key_message client1_signing_key;
  key_message client2_signing_key;
  string      client1_signing_cert;
  string      client2_signing_cert;
  string      serialized_identity_root_key;
  string      serialized_client1_key;
  string      serialized_client2_key;
  string      serialized_principals;
  string      serialized_resources;
  buffer_list credentials;

  principal_list pl;
  resource_list  rl;

  string prin_name("john");
  string res1_name("file_1");
  string res2_name("file_2");
  string acc1("read");
  string acc2("write");
  string cert_chain1_file_name = FLAGS_data_dir + FLAGS_cert_chain1;
  string cert_chain2_file_name = FLAGS_data_dir + FLAGS_cert_chain2;
  string identity_root_signing_key_file_name =
      FLAGS_data_dir + FLAGS_identity_root_signing_key;
  string client1_signing_key_file_name =
      FLAGS_data_dir + FLAGS_client1_signing_key;
  string client2_signing_key_file_name =
      FLAGS_data_dir + FLAGS_client2_signing_key;
  string principal_list_file_name = FLAGS_data_dir + FLAGS_principal_list;
  string resource_list_file_name = FLAGS_data_dir + FLAGS_resource_list;

  int i = 0;

  if (!make_keys_and_certs(root_issuer_name,
                           root_issuer_org,
                           signing_subject_name,
                           signing_subject_org,
                           &identity_root_key,
                           &client1_signing_key,
                           &credentials)) {
    printf("%s() error, line: %d: Can't make credentials\n",
           __func__,
           __LINE__);
    ret = false;
    goto done;
  }

  if (credentials.blobs_size() < 1) {
    printf("%s() error, line: %d: credentials wrong size\n",
           __func__,
           __LINE__);
    ret = false;
    goto done;
  }
  identity_root_asn1_cert_str = credentials.blobs(0);

  if (credentials.blobs_size() < 1) {
    printf("%s() error, line %d: cant find root in credentials\n",
           __func__,
           __LINE__);
    return false;
  }
  identity_root_asn1_cert_str = credentials.blobs(0);

  if (!credentials.SerializeToString(&serialized_cert_chain_str)) {
    printf("%s() error, line %d: cant serialize credentials\n",
           __func__,
           __LINE__);
    ret = false;
    goto done;
  }

  if (!construct_sample_principals(&pl)) {
    printf("%s() error, line %d: Cant construct principals\n",
           __func__,
           __LINE__);
    return false;
  }
  if (!construct_sample_resources(&rl)) {
    printf("%s() error, line %d: Cant construct resources\n",
           __func__,
           __LINE__);
    return false;
  }

  // put it on principal list
  for (i = 0; i < pl.principals_size(); i++) {
    if (pl.principals(i).principal_name() == prin_name) {
      pl.mutable_principals(i)->set_credential(serialized_cert_chain_str);
      pl.mutable_principals(i)->set_authentication_algorithm(auth_alg);
      break;
    }
  }
  if (i >= pl.principals_size()) {
    printf("%s() error, line %d: couldn't put credentials on principal list\n",
           __func__,
           __LINE__);
    ret = false;
    goto done;
  }

  if (!identity_root_key.SerializeToString(&serialized_identity_root_key)) {
    printf("%s() error, line %d: couldn't serialize identity root key\n",
           __func__,
           __LINE__);
    ret = false;
    goto done;
  }
  if (!client1_signing_key.SerializeToString(&serialized_client1_key)) {
    printf("%s() error, line %d: couldn't serialize client 1 signing key\n",
           __func__,
           __LINE__);
    ret = false;
    goto done;
  }
  if (!pl.SerializeToString(&serialized_principals)) {
    printf("%s() error, line %d: couldn't serialize principals list\n",
           __func__,
           __LINE__);
    ret = false;
    goto done;
  }
  if (!rl.SerializeToString(&serialized_resources)) {
    printf("%s() error, line %d: couldn't serialize resource list\n",
           __func__,
           __LINE__);
    ret = false;
    goto done;
  }

  // save all the keys and certs and lists
  if (!write_file_from_string(resource_list_file_name, serialized_resources)) {
    printf("%s() error, line %d: couldn't write serialized resources\n",
           __func__,
           __LINE__);
    ret = false;
    goto done;
  }
  if (!write_file_from_string(principal_list_file_name,
                              serialized_principals)) {
    printf("%s() error, line %d: couldn't write serialized principals\n",
           __func__,
           __LINE__);
    ret = false;
    goto done;
  }
  if (!write_file_from_string(identity_root_signing_key_file_name,
                              serialized_identity_root_key)) {
    printf("%s() error, line %d: couldn't write serialized root key\n",
           __func__,
           __LINE__);
    ret = false;
    goto done;
  }
  // identity_root_signing_key_file_name
  if (!write_file_from_string(cert_chain1_file_name,
                              serialized_cert_chain_str)) {
    printf("%s() error, line %d: couldn't write serialized credentials\n",
           __func__,
           __LINE__);
    ret = false;
    goto done;
  }
  if (!write_file_from_string(client1_signing_key_file_name,
                              serialized_client1_key)) {
    printf("%s() error, line %d: couldn't serialized client 1 signing key\n",
           __func__,
           __LINE__);
    ret = false;
    goto done;
  }

  // cert_chain2_file_name
  // client2_signing_key_file_name

done:
  return ret;
}

bool init_channel_keys(key_message *policy_key,
                       key_message *client_auth_key,
                       key_message *server_auth_key,
                       string      *policy_cert_str,
                       string      *client_auth_cert_str,
                       string      *server_auth_cert_str) {

  string policy_cert_file_name(FLAGS_data_dir);
  policy_cert_file_name.append(FLAGS_policy_cert_file);
  string policy_key_file_name(FLAGS_data_dir);
  policy_key_file_name.append(FLAGS_policy_key_file);
  int    sz;
  string policy_key_str;
  string client_auth_key_str;
  string server_auth_key_str;

  X509 *x509_policy_cert = nullptr;
  X509 *x509_client_auth_cert = nullptr;
  X509 *x509_server_auth_cert = nullptr;

  string client_auth_key_file_name =
      FLAGS_data_dir + FLAGS_client_auth_key_file;
  string client_auth_cert_file_name =
      FLAGS_data_dir + FLAGS_client_auth_cert_file;
  string server_auth_key_file_name =
      FLAGS_data_dir + FLAGS_server_auth_key_file;
  string server_auth_cert_file_name =
      FLAGS_data_dir + FLAGS_server_auth_cert_file;

  bool ret = true;

  sz = file_size(policy_cert_file_name);
  if (sz < 0) {
    printf("%s, error, line %d can't size policy cert in %s\n",
           __func__,
           __LINE__,
           policy_cert_file_name.c_str());
    ret = false;
    goto done;
  }
  if (!read_file_into_string(policy_cert_file_name, policy_cert_str)) {
    printf("%s, error, line %d can't read policy cert in %s\n",
           __func__,
           __LINE__,
           policy_cert_file_name.c_str());
    ret = false;
    goto done;
  }
  sz = file_size(policy_key_file_name);
  if (sz < 0) {
    printf("%s, error, line %d can't read policy key in %s\n",
           __func__,
           __LINE__,
           policy_key_file_name.c_str());
    ret = false;
    goto done;
  }
  if (!read_file_into_string(policy_key_file_name, &policy_key_str)) {
    printf("%s, error, line %d can't read policy key in %s\n",
           __func__,
           __LINE__,
           policy_key_file_name.c_str());
    ret = false;
    goto done;
  }

  x509_policy_cert = X509_new();
  if (!asn1_to_x509(*policy_cert_str, x509_policy_cert)) {
    printf("%s, error, line %d can't translate cert\n", __func__, __LINE__);
    ret = false;
    goto done;
  }
  if (!policy_key->ParseFromString(policy_key_str)) {
    printf("%s, error, line %d can't parse policy key\n", __func__, __LINE__);
    ret = false;
    goto done;
  }
  policy_key->set_certificate((byte *)policy_cert_str->data(),
                              policy_cert_str->size());

  // client and server auth key and certs
  if (!read_file_into_string(client_auth_cert_file_name,
                             client_auth_cert_str)) {
    printf("%s, error, line %d can't read client auth cert in %s\n",
           __func__,
           __LINE__,
           client_auth_cert_file_name.c_str());
    ret = false;
    goto done;
  }
  if (!read_file_into_string(server_auth_cert_file_name,
                             server_auth_cert_str)) {
    printf("%s, error, line %d can't read server auth cert in %s\n",
           __func__,
           __LINE__,
           server_auth_cert_file_name.c_str());
    ret = false;
    goto done;
  }
  if (!read_file_into_string(client_auth_key_file_name, &client_auth_key_str)) {
    printf("%s, error, line %d can't read client auth key in %s\n",
           __func__,
           __LINE__,
           client_auth_key_file_name.c_str());
    ret = false;
    goto done;
  }
  if (!read_file_into_string(server_auth_key_file_name, &server_auth_key_str)) {
    printf("%s, error, line %d can't read server auth key in %s\n",
           __func__,
           __LINE__,
           server_auth_key_file_name.c_str());
    ret = false;
    goto done;
  }
  if (!client_auth_key->ParseFromString(client_auth_key_str)) {
    printf("%s, error, line %d can't parse client auth key in %s\n",
           __func__,
           __LINE__,
           client_auth_key_file_name.c_str());
    ret = false;
    goto done;
  }
  if (!server_auth_key->ParseFromString(server_auth_key_str)) {
    printf("%s, error, line %d can't parse client auth key in %s\n",
           __func__,
           __LINE__,
           server_auth_key_file_name.c_str());
    ret = false;
    goto done;
  }

  if (FLAGS_print_all) {
    x509_client_auth_cert = X509_new();
    x509_server_auth_cert = X509_new();
    printf("\nPolicy cert:\n");
    X509_print_fp(stdout, x509_policy_cert);
    printf("\nPolicy key:\n");
    print_key(*policy_key);


    printf("\nClient auth key:\n");
    print_key(*client_auth_key);
    printf("\n");
    if (!asn1_to_x509(*client_auth_cert_str, x509_client_auth_cert)) {
      printf("%s, error, line %d can't asn translate client cert\n",
             __func__,
             __LINE__);
      ret = false;
      goto done;
    }
    printf("\nClient admissions cert:\n");
    X509_print_fp(stdout, x509_client_auth_cert);
    printf("Server cert:\n");
    print_bytes(server_auth_cert_str->size(),
                (byte *)server_auth_cert_str->data());
    printf("\n");
    printf("\nServer auth key:\n");
    print_key(*server_auth_key);
    printf("\n");
    if (!asn1_to_x509(*server_auth_cert_str, x509_server_auth_cert)) {
      printf("%s, error, line %d can't asn translate server cert\n",
             __func__,
             __LINE__);
      ret = false;
      goto done;
    }
    printf("\nServer admissions cert:\n");
    X509_print_fp(stdout, x509_server_auth_cert);
    printf("\n");
  }

done:
  return ret;
}

bool init_access_keys_and_files(key_message    *identity_root_key,
                                key_message    *client1_signing_key,
                                key_message    *client2_signing_key,
                                buffer_list    *credentials,
                                principal_list *pl,
                                resource_list  *rl) {
  bool   ret = true;
  string serialized_cert_chain_str;
  string identity_root_cert;
  string client1_signing_cert;
  string client2_signing_cert;
  string serialized_identity_root_key;
  string serialized_client1_key;
  string serialized_client2_key;
  string serialized_principals;
  string serialized_resources;
  string serialized_credentials;

  string cert_chain1_file_name = FLAGS_data_dir + FLAGS_cert_chain1;
  string cert_chain2_file_name = FLAGS_data_dir + FLAGS_cert_chain2;
  string identity_root_signing_key_file_name =
      FLAGS_data_dir + FLAGS_identity_root_signing_key;
  string client1_signing_key_file_name =
      FLAGS_data_dir + FLAGS_client1_signing_key;
  string client2_signing_key_file_name =
      FLAGS_data_dir + FLAGS_client2_signing_key;
  string principal_list_file_name = FLAGS_data_dir + FLAGS_principal_list;
  string resource_list_file_name = FLAGS_data_dir + FLAGS_resource_list;

  if (!read_file_into_string(cert_chain1_file_name, &serialized_credentials)) {
    printf("%s, error, line %d can't read credentials\n", __func__, __LINE__);
    ret = false;
    goto done;
  }
  if (!credentials->ParseFromString(serialized_credentials)) {
    printf("%s, error, line %d can't parse credentials\n", __func__, __LINE__);
    ret = false;
    goto done;
  }

  // second chain?

  if (credentials->blobs_size() < 2) {
    printf("%s, error, line %d credentials list too small\n",
           __func__,
           __LINE__);
    ret = false;
    goto done;
  }
  identity_root_cert = credentials->blobs(0);
  client1_signing_cert = credentials->blobs(1);

  if (!read_file_into_string(identity_root_signing_key_file_name,
                             &serialized_identity_root_key)) {
    printf("%s, error, line %d can't read identity root signing key\n",
           __func__,
           __LINE__);
    ret = false;
    goto done;
  }
  if (!identity_root_key->ParseFromString(serialized_identity_root_key)) {
    printf("%s, error, line %d can't parse identity root signing key\n",
           __func__,
           __LINE__);
    ret = false;
    goto done;
  }
  if (!read_file_into_string(client1_signing_key_file_name,
                             &serialized_client1_key)) {
    printf("%s, error, line %d can't read identity root signing key\n",
           __func__,
           __LINE__);
    ret = false;
    goto done;
  }
  if (!client1_signing_key->ParseFromString(serialized_client1_key)) {
    printf("%s, error, line %d can't parse identity root signing key\n",
           __func__,
           __LINE__);
    ret = false;
    goto done;
  }

  if (!read_file_into_string(principal_list_file_name,
                             &serialized_principals)) {
    printf("%s, error, line %d can't serialized principals\n",
           __func__,
           __LINE__);
    ret = false;
    goto done;
  }
  if (!pl->ParseFromString(serialized_principals)) {
    printf("%s, error, line %d can't parse credentials\n", __func__, __LINE__);
    ret = false;
    goto done;
  }
  if (!read_file_into_string(resource_list_file_name, &serialized_resources)) {
    printf("%s, error, line %d can't serialized resources\n",
           __func__,
           __LINE__);
    ret = false;
    goto done;
  }
  if (!rl->ParseFromString(serialized_resources)) {
    printf("%s, error, line %d can't parse credentials\n", __func__, __LINE__);
    ret = false;
    goto done;
  }

  if (FLAGS_print_all) {
    X509 *x509_identity_root_cert = X509_new();
    if (!asn1_to_x509(identity_root_cert, x509_identity_root_cert)) {
      printf("%s, error, line %d can't parse identity root signing key\n",
             __func__,
             __LINE__);
      ret = false;
      goto done;
    }
    printf("\nIdentity root cert:\n");
    X509_print_fp(stdout, x509_identity_root_cert);
    printf("\n");
    printf("Identity root key:\n");
    print_key(*identity_root_key);
    printf("\n");
    X509_free(x509_identity_root_cert);
    x509_identity_root_cert = nullptr;
    X509 *x509_client1_cert = X509_new();
    if (!asn1_to_x509(client1_signing_cert, x509_client1_cert)) {
      printf("%s, error, line %d can't parse client1 signing key\n",
             __func__,
             __LINE__);
      ret = false;
      goto done;
    }
    printf("\nClient 1 cert:\n");
    X509_print_fp(stdout, x509_client1_cert);
    printf("\n");
    printf("Client 1 key:\n");
    print_key(*client1_signing_key);
    printf("\n");

    printf("Principals:\n");
    print_principal_list(*pl);
    printf("\n");
    printf("Resources:\n");
    print_resource_list(*rl);
    printf("\n");
  }

done:
  return ret;
}

// ---------------------------------------------------------

void server_application(secure_authenticated_channel &channel) {

  printf("Server peer id is %s\n", channel.peer_id_.c_str());

  // Read message from client over authenticated, encrypted channel
  string              out;
  bool                ret = true;
  acl_server_dispatch server_dispatch(channel.ssl_);

  // not needed
#if 0
  server_dispatch.guard_.load_principals(pl);
  server_dispatch.guard_.load_resources(rl);

  server_dispatch.guard_.init_root_cert(der_identity_root_cert);
  server_dispatch.guard_.authentication_algorithm_name_ = auth_alg;
  string principal_name;
  server_dispatch.guard_.accept_credentials(principal_name,
                          auth_alg, der_identity_root_cert, pl);
  server_dispatch.guard_.load_resources(rl);
  server_dispatch.guard_.load_principals(pl);
#endif

  for (;;) {
    server_dispatch.service_request();
  }
  channel.close();
}

void client_application(secure_authenticated_channel &channel,
                        const buffer_list            &creds,
                        const key_message            &signing_key) {

  bool        ret = true;
  string      prin_name("john");
  const char *alg = Enc_method_rsa_2048_sha256_pkcs_sign;
  string      res1_name("file_1");
  string      res2_name("file_2");
  string      acc1("read");
  string      acc2("write");
  string      bytes_written_to_file("Hello there");
  string      bytes_read_from_file;
  const char *dig_alg = Digest_method_sha_256;
  EVP_PKEY   *pkey = nullptr;
  RSA        *r2 = nullptr;

  string nonce;
  string signed_nonce;
  int    size_nonce = 32;
  byte   buf[size_nonce];
  int    size_sig = 512;
  byte   sig[size_sig];

  string serialized_creds;

  printf("Client peer id is %s\n", channel.peer_id_.c_str());
  if (!creds.SerializeToString(&serialized_creds)) {
    printf("%s() error, line %d: cannot serialize creds\n", __func__, __LINE__);
    return;
  }

  // The channel was negotiated with the client/server
  // auth keys.
  if (!channel.channel_initialized_) {
    printf("%s() error, line %d: channel not initialized\n",
           __func__,
           __LINE__);
    return;
  }

  acl_client_dispatch client_dispatch(channel.ssl_);

  ret =
      client_dispatch.rpc_authenticate_me(prin_name, serialized_creds, &nonce);
  if (!ret) {
    printf("%s() error, line %d: client.rpc_authenticate_me failed\n",
           __func__,
           __LINE__);
    return;
  }

  // sign nonce
  if (strcmp(alg, Enc_method_rsa_2048_sha256_pkcs_sign) == 0) {
    dig_alg = Digest_method_sha_256;
  } else if (strcmp(alg, Enc_method_rsa_1024_sha256_pkcs_sign) == 0) {
    dig_alg = Digest_method_sha_256;
  } else if (strcmp(alg, Enc_method_rsa_3072_sha384_pkcs_sign) == 0) {
    dig_alg = Digest_method_sha_384;
  } else {
    printf("%s() error, line %d: unsupported rsa signing alg %s\n",
           __func__,
           __LINE__,
           alg);
    ret = false;
    goto done;
  }

  pkey = pkey_from_key(signing_key);
  if (pkey == nullptr) {
    printf("%s() error, line %d: Can't get pkey\n", __func__, __LINE__);
    ret = false;
    goto done;
  }
  r2 = EVP_PKEY_get1_RSA(pkey);
  if (r2 == nullptr) {
    printf("%s() error, line %d: Can't get rsa key\n", __func__, __LINE__);
    ret = false;
    goto done;
  }

  // sign nonce
  if (!rsa_sign(dig_alg,
                r2,
                nonce.size(),
                (byte *)nonce.data(),
                &size_sig,
                sig)) {
    printf("%s() error, line %d: sign failed\n", __func__, __LINE__);
    ret = false;
    goto done;
  }
  signed_nonce.assign((char *)sig, size_sig);

  ret = client_dispatch.rpc_verify_me(prin_name, signed_nonce);
  if (!ret) {
    printf("%s() error, line %d: rpc_verify_me failed\n", __func__, __LINE__);
    ret = false;
    goto done;
  }

  ret = client_dispatch.rpc_open_resource(res1_name, acc1);
  if (!ret) {
    printf("%s() error, line %d: rpc_open_resource failed\n",
           __func__,
           __LINE__);
    ret = false;
    goto done;
  }

  ret = client_dispatch.rpc_read_resource(res1_name, 14, &bytes_read_from_file);
  if (!ret) {
    printf("%s() error, line %d: rpc_read_resource failed\n",
           __func__,
           __LINE__);
    ret = false;
    goto done;
  }
  printf("Bytes: %s\n", bytes_read_from_file.c_str());

  ret = client_dispatch.rpc_close_resource(res1_name);
  if (!ret) {
    printf("%s() error, line %d: rpc_close_resource failed\n",
           __func__,
           __LINE__);
    ret = false;
    goto done;
  }

  ret = client_dispatch.rpc_open_resource(res2_name, acc2);
  if (!ret) {
    printf("%s() error, line %d: rpc_open_resource failed\n",
           __func__,
           __LINE__);
    ret = false;
    goto done;
  }

  ret = client_dispatch.rpc_write_resource(res2_name, bytes_written_to_file);
  if (!ret) {
    printf("%s() error, line %d: rpc_write_resource failed\n",
           __func__,
           __LINE__);
    ret = false;
    goto done;
  }

  ret = client_dispatch.rpc_close_resource(res2_name);
  if (!ret) {
    printf("%s() error, line %d: rpc_close_resource failed\n",
           __func__,
           __LINE__);
    ret = false;
    goto done;
  }

done:
  if (ret) {
    printf("client_application succeeded\n");
  } else {
    printf("client_application failed\n");
  }
  if (pkey != nullptr) {
    EVP_PKEY_free(pkey);
    pkey = nullptr;
  }
  return;

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
                      string       *cert_chain,
                      key_message  &private_key,
                      string       &private_key_cert) {

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

bool run_me_as_client(const string      &host_name,
                      int                port,
                      const string      &asn1_root_cert,
                      const string      &peer_asn1_root_cert,
                      int                cert_chain_length,
                      string            *der_certs,
                      key_message       &private_key,
                      const string      &auth_cert,
                      const key_message &client_signing_key,
                      const buffer_list &credentials) {

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
  client_application(channel, credentials, client_signing_key);
  return true;
}

bool test_constructed_keys_and_files() {

  // channel keys and certs
  key_message policy_key;
  key_message client_auth_key;
  key_message server_auth_key;
  X509       *policy_cert = nullptr;
  string      policy_key_cert_str;
  string      client_auth_cert_str;
  string      server_auth_cert_str;

  // access keys
  key_message identity_root_key;
  key_message client1_signing_key;
  key_message client2_signing_key;

  const char *alg = Enc_method_rsa_2048_sha256_pkcs_sign;
  buffer_list credentials;

  if (!init_channel_keys(&policy_key,
                         &client_auth_key,
                         &server_auth_key,
                         &policy_key_cert_str,
                         &client_auth_cert_str,
                         &server_auth_cert_str)) {
    printf("Can't init channel keys\n");
    return false;
  }
  if (FLAGS_print_all) {
    printf("Policy key:\n");
    print_key(policy_key);
    printf("\n");
    printf("Client auth key:\n");
    print_key(client_auth_key);
    printf("\n");
    printf("server auth  key:\n");
    print_key(server_auth_key);
    printf("\n");
    X509 *x509_policy_cert = X509_new();
    X509 *x509_client_auth_cert = X509_new();
    X509 *x509_server_auth_cert = X509_new();

    if (!asn1_to_x509(policy_key_cert_str, x509_policy_cert)) {
      printf("%s() error, line: %d: can't asn translate policy cert\n",
             __func__,
             __LINE__);
      return false;
    }
    if (!asn1_to_x509(client_auth_cert_str, x509_client_auth_cert)) {
      printf("%s() error, line: %d: can't asn translate client auth cert\n",
             __func__,
             __LINE__);
      return false;
    }
    if (!asn1_to_x509(server_auth_cert_str, x509_server_auth_cert)) {
      printf("%s() error, line: %d: can't asn translate server auth cert\n",
             __func__,
             __LINE__);
      return false;
    }
    printf("\nPolicy cert:\n");
    X509_print_fp(stdout, x509_policy_cert);
    printf("\n");
    printf("\nClient auth cert:\n");
    X509_print_fp(stdout, x509_client_auth_cert);
    printf("\n");
    printf("\nServer auth cert:\n");
    X509_print_fp(stdout, x509_server_auth_cert);
    printf("\n");
  }

  if (!init_access_keys_and_files(&identity_root_key,
                                  &client1_signing_key,
                                  &client2_signing_key,
                                  &credentials,
                                  &g_pl,
                                  &g_rl)) {
    printf("%s() error, line: %d: Can't init access keys and files\n",
           __func__,
           __LINE__);
    return false;
  }

  if (FLAGS_print_all) {
    printf("Identity root key:\n");
    print_key(identity_root_key);
    printf("\n");
    printf("Client 1 key:\n");
    print_key(client1_signing_key);
    printf("\n");

    printf("Principals:\n");
    print_principal_list(g_pl);
    printf("\n");
    printf("Resources:\n");
    print_resource_list(g_rl);
    printf("\n");
    printf("\nCredentials:\n");
    for (int i = 0; i < credentials.blobs_size(); i++) {
      X509 *cert = X509_new();
      if (cert == nullptr)
        break;
      if (!asn1_to_x509(credentials.blobs(i), cert)) {
        printf("%s() error, line: %d: Can't asn1 translate cert\n",
               __func__,
               __LINE__);
        return false;
      }
      X509_print_fp(stdout, cert);
      printf("\n");
      X509_free(cert);
      cert = nullptr;
      printf("\n");
    }
  }

  return true;
}

// ----------------------------------------------------


int main(int an, char **av) {
  gflags::ParseCommandLineFlags(&an, &av, true);
  an = 1;
  ::testing::InitGoogleTest(&an, av);

  SSL_library_init();

  if (!certifier::acl_lib::init_crypto()) {
    printf("Couldn't init crypto\n");
    return 1;
  }

  // channel keys and certs
  key_message policy_key;
  key_message client_auth_key;
  key_message server_auth_key;
  X509       *policy_cert = nullptr;
  string      policy_key_cert_str;
  string      client_auth_cert_str;
  string      server_auth_cert_str;

  key_message identity_root_key;
  key_message client1_signing_key;
  key_message client2_signing_key;
  buffer_list credentials;

  string identity_root_asn1_cert_str;
  string client1_asn_cert_str;
  string client2_asn_cert_str;

  resource_list  rl;
  principal_list pl;

  const char *alg = Enc_method_rsa_2048_sha256_pkcs_sign;

  if (FLAGS_operation == "make_additional_channel_keys") {
    if (!make_additional_channel_keys()) {
      printf("%s() error, line: %d: unknown access mode\n", __func__, __LINE__);
      return 1;
    }
    printf("make_additional_channel_keys succeeded\n");
  } else if (FLAGS_operation == "make_access_keys_and_files") {
    if (!make_access_keys_and_files()) {
      printf("%s() error, line: %d: couldn't make identity keys and files\n",
             __func__,
             __LINE__);
      return 1;
    }
    printf("make_access_keys_and_files succeeded\n");
  } else if (FLAGS_operation == "test_constructed_keys_and_files") {
    if (test_constructed_keys_and_files()) {
      printf("Files and keys are valid\n");
    } else {
      printf("Files and keys are invalid\n");
    }
  } else if (FLAGS_operation == "run_as_client") {
    if (!init_channel_keys(&policy_key,
                           &client_auth_key,
                           &server_auth_key,
                           &policy_key_cert_str,
                           &client_auth_cert_str,
                           &server_auth_cert_str)) {
      printf("Can't init channel keys\n");
      return false;
    }
    if (!init_access_keys_and_files(&identity_root_key,
                                    &client1_signing_key,
                                    &client2_signing_key,
                                    &credentials,
                                    &g_pl,
                                    &g_rl)) {
      printf("%s() error, line: %d: Can't init access keys and files\n",
             __func__,
             __LINE__);
      return false;
    }

    // der certs are cert chain from policy key
    int    cert_chain_length = 2;
    string der_certs[2];
    der_certs[0] = policy_key_cert_str;
    der_certs[1] = client_auth_cert_str;
    if (!run_me_as_client(FLAGS_app_host.c_str(),
                          FLAGS_app_port,
                          client_auth_cert_str,
                          server_auth_cert_str,
                          cert_chain_length,
                          der_certs,
                          (key_message &)client_auth_key,
                          client_auth_cert_str,
                          client1_signing_key,
                          credentials)) {
      printf("run-me-as-client failed\n");
      return 1;
    }
  } else if (FLAGS_operation == "run_as_server") {
    if (!init_channel_keys(&policy_key,
                           &client_auth_key,
                           &server_auth_key,
                           &policy_key_cert_str,
                           &client_auth_cert_str,
                           &server_auth_cert_str)) {
      printf("Can't init channel keys\n");
      return false;
    }
    if (!init_access_keys_and_files(&identity_root_key,
                                    &client1_signing_key,
                                    &client2_signing_key,
                                    &credentials,
                                    &g_pl,
                                    &g_rl)) {
      printf("%s() error, line: %d: Can't init access keys and files\n",
             __func__,
             __LINE__);
      return false;
    }
#if 0
      if (!run_me_as_server(FLAGS_app_host.c_str(),
                            FLAGS_app_port,
                            server_root_cert,
                            client_root_cert,
                            cert_chain_length,
                            der_certs,
                            (key_message &)server_auth_key,
                            server_auth_cert)) {
        printf("server failed\n");
        return 1;
      }
#endif
  } else {
    printf("Unknown operation\n");
    return 1;
  }

  certifier::acl_lib::close_crypto();
  return 0;
}
