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
//    make_access_keys_and_files, test_constructed_files,
//    run_as_client, run_as_server
DEFINE_string(operation, "", "operation");

DEFINE_string(app_host, "localhost", "address for server");
DEFINE_int32(app_port, 8124, "port for server");

DEFINE_string(data_dir, "./test_data/", "directory for files");
DEFINE_string(policy_cert_file, "policy_cert_file.bin", "policy cert file");
DEFINE_string(policy_key_file, "policy_key_file.bin", "policy key file");
DEFINE_string(auth_key_file, "auth_key_file.bin", "auth key file");
DEFINE_string(cert_chain1, "cert_chain1.bin", "First certificate chain");
DEFINE_string(cert_chain2, "cert_chain2.bin", "Second certificate chain");

#define DEBUG

#if 1
acl_server_dispatch g_server(nullptr);
#endif

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

// These are the keys and certs for the file access (acl_lib)
// functionality.  We trust the root of the file access signing
// regime but in a real application, you need to decide how to
// do this securely.
bool make_access_keys_and_files() {
  bool ret = true;
#if 0
  string      signing_subject_name("johns-signing-key");
  string      signing_subject_org("datica");
  string      root_issuer_name("johns-root");
  string      root_issuer_org("datica");
  const char *alg = Enc_method_rsa_2048_sha256_pkcs_sign;
  EVP_PKEY   *pkey = nullptr;
  RSA        *r2 = nullptr;
  string      serialized_cert_chain_str;
  key_message identity_root_key;
  key_message client1_signing_key;
  key_message client2_signing_key;
  string      client1_signing_cert;
  string      client2_signing_cert;
  buffer_list credentials;

  principal_list pl;
  resource_list  rl;

  string prin_name("john");
  string res1_name("file_1");
  string res2_name("file_2");
  string acc1("read");
  string acc2("write");
  string serialized_cert_chain_str;

  if (!make_keys_and_certs(root_issuer_name,
                           root_issuer_org,
                           signing_subject_name,
                           signing_subject_org,
                           &root_key,
                           &signing_key,
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
  root_asn1_cert_str = credentials.blobs(0);

  if (credentials.blobs_size() < 1) {
    printf("%s() error, line %d: cant find root in credentials\n",
           __func__,
           __LINE__);
    return false;
  }
  asn1_cert_str = credentials.blobs(0);

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
#endif

done:
  return ret;
}

bool init_channel_keys() {
    // read in policy key and my key
    key_message policy_key;
    key_message auth_key;
    X509       *policy_cert = nullptr;

    string policy_cert_file(FLAGS_data_dir);
    policy_cert_file.append(FLAGS_policy_cert_file);
    int sz = file_size(policy_cert_file);
    if (sz < 0) {
      printf("%s, error, line %d can't size policy cert in %s\n",
                      __func__, __LINE__, policy_cert_file.c_str());
      return 1;
    }
    byte policy_cert_buf[sz];
    if (!read_file(policy_cert_file, &sz, policy_cert_buf)) {
      printf("%s, error, line %d can't read policy cert in %s\n",
                      __func__, __LINE__, policy_cert_file.c_str());
      return 1;
    }
    string str_policy_cert;
    str_policy_cert.assign((char *)policy_cert_buf, sz);

    // policy_key_file
    string policy_key_file(FLAGS_data_dir);
    policy_key_file.append(FLAGS_policy_key_file);
    sz = file_size(policy_key_file);
    if (sz < 0) {
      printf("%s, error, line %d can't size policy key %s\n", 
             __func__, __LINE__, policy_key_file.c_str());
      return 1;
    }
    byte policy_key_buf[sz];
    if (!read_file(policy_key_file, &sz, policy_key_buf)) {
      printf("%s, error, line %d can't read policy key %s\n", 
             __func__, __LINE__, policy_key_file.c_str());
      return 1;
    }
    string str_policy_key;
    str_policy_key.assign((char *)policy_key_buf, sz);

    // auth_key_file
    string auth_key_file(FLAGS_data_dir);
    auth_key_file.append(FLAGS_auth_key_file);
    sz = file_size(auth_key_file);
    if (sz < 0) {
      printf("%s, error, line %d can't size auth key %s\n", 
             __func__, __LINE__, auth_key_file.c_str());
      return 1;
    }
    byte auth_key_buf[sz];
    if (!read_file(auth_key_file, &sz, auth_key_buf)) {
      printf("%s, error, line %d can't read auth key %s\n", 
             __func__, __LINE__, auth_key_file.c_str());
      return 1;
    }
    string str_auth_key;
    str_auth_key.assign((char *)auth_key_buf, sz);

    policy_cert = X509_new();
    if (!asn1_to_x509(str_policy_cert, policy_cert)) {
      printf("%s, error, line %d can't translate cert\n",
             __func__, __LINE__);
      return 1;
    }
    if (!policy_key.ParseFromString(str_policy_key)) {
      printf("%s, error, line %d can't parse policy key\n",
             __func__, __LINE__);
      return 1;
    }
    policy_key.set_certificate((byte *)str_policy_cert.data(),
                               str_policy_cert.size());

    // make admissions cert
    string auth_cert;
    string role;
    if (!make_admissions_cert(role,
                              policy_key,
                              auth_key,
                              &auth_cert)) {
      printf("%s, error, line %d can't make admissions cert\n",
             __func__, __LINE__);
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
  return true;
}

bool init_access_keys_and_files() {
#if 0
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

#  ifdef DEBUG
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
#  endif

#endif
  return true;
}

// ---------------------------------------------------------

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

bool run_as_client() {

#if 0
  // initialize keys and certs

  ret = client.rpc_authenticate_me(prin_name, &nonce);
  if (!ret) {
    printf("%s() error, line %d: client.rpc_authenticate_me failed\n",
           __func__,
           __LINE__);
    return false;
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
  if (!rsa_sign(dig_alg.c_str(),
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

  ret = client.rpc_verify_me(prin_name, signed_nonce);
  if (!ret) {
    printf("%s() error, line %d: rpc_verify_me failed\n", __func__, __LINE__);
    ret = false;
    goto done;
  }

  ret = client.rpc_open_resource(res1_name, acc1);
  if (!ret) {
    printf("%s() error, line %d: rpc_open_resource failed\n",
           __func__,
           __LINE__);
    ret = false;
    goto done;
  }

  ret = client.rpc_read_resource(res1_name, 14, &bytes_read_from_file);
  if (!ret) {
    printf("%s() error, line %d: rpc_read_resource failed\n",
           __func__,
           __LINE__);
    ret = false;
    goto done;
  }
  printf("Bytes: %s\n", bytes_read_from_file.c_str());

  ret = client.rpc_close_resource(res1_name);
  if (!ret) {
    printf("%s() error, line %d: rpc_close_resource failed\n",
           __func__,
           __LINE__);
    ret = false;
    goto done;
  }

  ret = client.rpc_open_resource(res2_name, acc2);
  if (!ret) {
    printf("%s() error, line %d: rpc_open_resource failed\n",
           __func__,
           __LINE__);
    ret = false;
    goto done;
  }

  ret = client.rpc_write_resource(res2_name, bytes_written_to_file);
  if (!ret) {
    printf("%s() error, line %d: rpc_write_resource failed\n",
           __func__,
           __LINE__);
    ret = false;
    goto done;
  }

  ret = client.rpc_close_resource(res2_name);
  if (!ret) {
    printf("%s() error, line %d: rpc_close_resource failed\n",
           __func__,
           __LINE__);
    ret = false;
    goto done;
  }

done:
  if (pkey != nullptr) {
    EVP_PKEY_free(pkey);
    pkey = nullptr;
  }
  return ret;
#endif
  return true;
}

bool run_as_server() {
#if 0 
  // initialize server

  if (!g_server.guard_.init_root_cert(asn1_cert_str)) {
    printf("%s() error, line %d: Can't init_root\n", __func__, __LINE__);
    return false;
  }

  if (!g_server.load_principals(pl)) {
    printf("%s() error, line %d: Cant load principals\n", __func__, __LINE__);
    return false;
  }

  if (!g_server.load_resources(rl)) {
    printf("%s() error, line %d: Cant load resources\n", __func__, __LINE__);
    return false;
  }
#endif
  return true;
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

bool run_me_as_client(const string &host_name,
                      int           port,
                      const string &asn1_root_cert,
                      const string &peer_asn1_root_cert,
                      int           cert_chain_length,
                      string       *der_certs,
                      key_message  &private_key,
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

bool test_constructed_keys_and_files() {

  // channel keys and certs
  key_message policy_key;
  key_message auth_key;
  X509       *policy_cert = nullptr;
  string      policy_cert_file(FLAGS_data_dir);
  policy_cert_file.append(FLAGS_policy_cert_file);

  key_message server_root_key;
  key_message server_public_key;
  key_message server_private_key;
  // server_private_key.CopyFrom(chain2.final_private_key());
  string server_root_cert;
  string server_auth_cert;

  key_message client_root_key;
  key_message client_public_key;
  key_message client_private_key;
  // client_private_key.CopyFrom(chain1.final_private_key());
  string client_root_cert;
  string client_auth_cert;

  // acl keys and certs
  key_message public_root_key;
  key_message public_signing_key;
  const char *alg = Enc_method_rsa_2048_sha256_pkcs_sign;
  buffer_list credentials;

  if (!init_channel_keys()) {
  }
  if (FLAGS_print_all) {
  }

  if (!init_access_keys_and_files()) {
  }
  if (FLAGS_print_all) {
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
  key_message auth_key;
  X509       *policy_cert = nullptr;
  string      policy_cert_file(FLAGS_data_dir);
  policy_cert_file.append(FLAGS_policy_cert_file);

  key_message server_root_key;
  key_message server_public_key;
  key_message server_private_key;
  // server_private_key.CopyFrom(chain2.final_private_key());
  string server_root_cert;
  string server_auth_cert;

  key_message client_root_key;
  key_message client_public_key;
  key_message client_private_key;
  // client_private_key.CopyFrom(chain1.final_private_key());
  string client_root_cert;
  string client_auth_cert;

  // acl keys and certs
  key_message public_root_key;
  key_message public_signing_key;
  const char *alg = Enc_method_rsa_2048_sha256_pkcs_sign;
  buffer_list credentials;

  if (FLAGS_operation == "make_access_keys_and_files") {
  } else if (FLAGS_operation == "test_constructed_keys_and_files") {
    if(test_constructed_keys_and_files()) {
        printf("Files and keys are valid\n");
    } else {
        printf("Files and keys are invalid\n");
    }
  } else if (FLAGS_operation == "init_access_keys_and_files") {
  } else if (FLAGS_operation == "run_as_client") {
#if 0
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
#endif
  } else if (FLAGS_operation == "run_as_server") {
#if 0
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
#endif
  } else {
    printf("Unknown operation\n");
    return 1;
  }

  certifier::acl_lib::close_crypto();
  return 0;
}
