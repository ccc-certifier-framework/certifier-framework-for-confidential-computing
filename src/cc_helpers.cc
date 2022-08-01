#include <gtest/gtest.h>
#include <gflags/gflags.h>

#include "support.h"
#include "certifier.h"
#include "simulated_enclave.h"
#include "cc_helpers.h"

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


//  This is a collection of functions that accomplish almost all the
//  Confidential Computing functions for basic enclaves including:
//    Initializing policy key information
//    Initializing authentication key (if purpose is "authentication")
//    Initializing service key (if purpose is "attestation")
//    Initializing symmetric keys (if purpose is "authentication")
//    Initializing sealing keys (if purpose is "attestation")
//    Encrypting and saving the policy store
//    Reading and decrypting the policy store and filling in trust data from it
//
//  You may want to augment these or write replacements if your needs are fancier.

cc_trust_data::cc_trust_data(const string& enclave_type, const string& purpose,
    const string& policy_store_name) {
  if (purpose == "authentication" || purpose == "attestation") {
    purpose_= purpose;
    cc_basic_data_initialized_ = true;
  } else {
    cc_basic_data_initialized_ = false;
    purpose_ = "unknown";
  }
  enclave_type_ = enclave_type;
  store_file_name_ = policy_store_name;
  cc_policy_cert_initialized_ = false;
  cc_policy_store_initialized_ = false;
  cc_service_key_initialized_ = false;
  cc_service_cert_initialized_ = false;
  cc_service_platform_rule_initialized_ = false;
  cc_sealing_key_initialized_ = false;
  cc_provider_provisioned_ = false;
  x509_policy_cert= nullptr;
}

cc_trust_data::cc_trust_data() {
  cc_basic_data_initialized_ = false;
  cc_policy_cert_initialized_ = false;
  cc_policy_store_initialized_ = false;
  cc_service_key_initialized_ = false;
  cc_service_cert_initialized_ = false;
  cc_service_platform_rule_initialized_ = false;
  cc_sealing_key_initialized_ = false;
  cc_provider_provisioned_ = false;
  x509_policy_cert= nullptr;
}

cc_trust_data::~cc_trust_data() {
}

bool cc_trust_data::cc_all_initialized() {
  if (purpose_ == "authentication")
    return cc_policy_cert_initialized_ & cc_auth_key_initialized_ &
           cc_symmetric_key_initialized_& cc_policy_info_initialized_ &
           cc_provider_provisioned_ & cc_policy_store_initialized_;
  } else if (purpose_ == "attestation") {
    return cc_policy_cert_initialized_ & cc_sealing_key_initialized_ &
           cc_service_key_initialized_ & cc_service_platform_rule_initialized_ &
           cc_provider_provisioned_ & cc_policy_store_initialized_;
  } else {
    return false;
  }
}

bool cc_trust_data::initialize_simulated_enclave_data(const string& attest_key_file_name,
      const string& measurement_file_name, const string& attest_endorsement_file_name) {
  // cc_provider_provisioned_ = true;
  return false;
}

bool cc_trust_data::init_policy_key(int asn1_cert_size, asn1_cert) {
  cc_policy_info_initialized_ = true;
  return false;
}

void cc_trust_data::print_trust_data() {
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
  printf("\n\n");
}

bool cc_trust_data::save_store() {
  string serialized_store;

  if (!pStore.Serialize(&serialized_store)) {
    printf("save_store() can't serialize store\n"); 
    return false;
  }
  int size_protected_store = serialized_store.size() + 4096;
  byte protected_store[size_protected_store];
  if (!Protect_Blob(enclave_type, symmertic_key_for_protect, serialized_store.size(),
          (byte*)serialized_store.data(), &size_protected_store, protected_store)) {
    printf("save_store can't protect blob\n");
    return false;
  }

  string store_file(FLAGS_data_dir);
  store_file.append(FLAGS_policy_store_file);
  if (!write_file(store_file, size_protected_store, protected_store)) {
    printf("save_store can't write %s\n", store_file.c_str());
    return false;
  }
  return true;
}

bool cc_trust_data::fetch_store() {
  string store_file(FLAGS_data_dir);
  store_file.append(FLAGS_policy_store_file);

  int size_protected_blob = file_size(store_file) + 1;
  byte protected_blob[size_protected_blob];
  int size_unprotected_blob = size_protected_blob;
  byte unprotected_blob[size_unprotected_blob];

  if (!read_file(store_file, &size_protected_blob, protected_blob)) {
    printf("fetch_store can't read %s\n", store_file.c_str());
    return false;
  }
  
  if (!Unprotect_Blob(enclave_type, size_protected_blob, protected_blob,
        &symmertic_key_for_protect, &size_unprotected_blob, unprotected_blob)) {
    printf("fetch_store can't Unprotect\n");
    return false;
  }

  // read policy store
  string serialized_store;
  serialized_store.assign((char*)unprotected_blob, size_unprotected_blob);
  if (!pStore.Deserialize(serialized_store)) {
    printf("fetch_store can't deserialize store\n");
    return false;
  }

  return true;
}

void cc_trust_data::clear_sensitive_data() {
  // Todo: clear symmetric and private keys
  //    Not necessary on most platforms
}

bool cc_trust_data::cold_init() {

  if (cc_policy_info_initialized_) {
      printf("policy key should have been initialized\n");
      return false;
  }

  if (purpose_ == "authentication") {

    // make up some symmetric keys for app
    if (!get_random(8 * cc_helper_symmetric_key_size, symmetric_key_)) {
      printf("Can't get random bytes for app key\n");
      return false;
    }

    // make app private and public key
    if (!make_certifier_rsa_key(2048,  &private_auth_key_)) {
      printf("Can't generate App private key\n");
      return false;
    }
    private_auth_key_.set_key_name("app-auth-key");
    if (!private_key_to_public_key(private_auth_key_, &public_auth_key_)) {
      printf("Can't make public Auth key\n");
      return false;
    }

    // put private auth key and symmetric keys in store
    if (!store_.replace_policy_key(public_policy_key_)) {
      printf("Can't store policy key\n");
      return false;
    }

    string key_tag("auth-key");
    if (!store_.add_authentication_key(key_tag, private_auth_key_)) {
      printf("Can't store auth key\n");
      return false;
    }
    cc_symmetric_key_initialized_ = true;
    cc_auth_key_initialized_ = true;

  } else if (purpose_ == "attestation") {

    // make up sealing key for service
    if (!get_random(8 * cc_helper_symmetric_key_size, service_symmetric_key_)) {
      printf("Can't get random bytes for app key\n");
      return false;
    }

    // make service private and public key
    if (!make_certifier_rsa_key(2048,  &private_auth_key_)) {
      printf("Can't generate App private key\n");
      return false;
    }
    private_service_key_.set_key_name("app-auth-key");
    if (!private_key_to_public_key(private_auth_key_, &public_auth_key_)) {
      printf("Can't make public Auth key\n");
      return false;
    }

    // put private auth key and symmetric keys in store
    if (!store_.replace_policy_key(public_policy_key_)) {
      printf("Can't store policy key\n");
      return false;
    }

    string key_tag("service-key");
    if (!store_.add_authentication_key(auth_tag, private_auth_key_)) {
      printf("Can't store auth key\n");
      return false;
    }
    cc_symmetric_key_initialized_ = true;
    cc_auth_key_initialized_ = true;
  } else {
    printf("invalid cold_init purpose\n");
    return false;
  }

  if (!store_.save_store()) {
    printf("Can't save storen");
    return false;
  }
  return true;
}

bool cc_trust_data::warm_restart() {

  if (!cc_policy_store_initialized_) {
    if (!fetch_store()) {
      printf("Can't fetch store\n");
      return false;
    }
  }

  // initialize trust data from store
  string tag("blob-key");
  const key_message* pk = pStore.get_policy_key();
  if (pk == nullptr) {
    printf("warm-restart error 1\n");
    return false;
  }

  string auth_tag("auth-key");
  const key_message* ak = pStore.get_authentication_key_by_tag(auth_tag);
  if (ak == nullptr) {
    printf("warm-restart error 2\n");
    return false;
  }

  publicPolicyKey.CopyFrom(*pk);
  privateAppKey.CopyFrom(*ak);
  if (!private_key_to_public_key(privateAppKey, &publicAppKey)) {
    printf("Can't make public App key\n");
    return false;
  }
  serializedPolicyCert = publicPolicyKey.certificate();
  policy_cert = X509_new();
  const byte* p = (const byte*) serializedPolicyCert.data();
  if (d2i_X509(&policy_cert, &p, (int)serializedPolicyCert.size()) == NULL) {
    printf("warm-restart error 5\n");
    return false;
  }
  trust_data_initialized = true;

  if (FLAGS_print_all) {
    print_trust_data();
  }
  return trust_data_initialized;
}

bool cc_trust_data::certify_me() {
printf("certify_me\n");
  if (!warm_restart(enclave_type)) {
    printf("warm restart failed\n");
    return false;
  }
  
  // Get the signed claim "platform-key says attestation-key is trusted"
  signed_claim_message signed_platform_says_attest_key_is_trusted;
  if (!simulated_GetAttestClaim(&signed_platform_says_attest_key_is_trusted)) {
    printf("Can't get signed attest claim\n");
    return false;
  }
  if (FLAGS_print_all) {
    printf("Got platform claims\n");
    print_signed_claim(signed_platform_says_attest_key_is_trusted);
  }

  vse_clause vc;
  if (!get_vse_clause_from_signed_claim(signed_platform_says_attest_key_is_trusted, &vc)) {
    printf("Can't get vse platform claim\n");
    return false;
  }

  //  The platform statement is "platform-key says attestation-key is-trusted-for-attestation"
  //  We retrieve the entity describing the attestation key from this.
  entity_message attest_key_entity = vc.clause().subject();

  // Here we generate a vse-attestation which is
  // a claim, signed by the attestation key that signed a statement
  // the user requests (Some people call this the "user data" in an
  // attestation.  Formats for an attestation will vary among platforms
  // but they must always convery the information we do here.
  // most of this is boiler plate

  string enclave_id("");
  string descript("test-attest");
  string at_format("vse-attestation");

  // now construct the vse clause "attest-key says authentication key speaks-for measurement"
  // there are three entities in the attest: the attest-key, the auth-key and the measurement
  int my_measurement_size = 32;
  byte my_measurement[my_measurement_size];
  if (!Getmeasurement(enclave_type, enclave_id, &my_measurement_size, my_measurement)) {
    printf("Getmeasurement failed\n");
    return false;
  }
  string measurement;
  measurement.assign((char*)my_measurement, my_measurement_size);
  entity_message measurement_entity;
  if (!make_measurement_entity(measurement, &measurement_entity)) {
    printf("certify_me error 1\n");
    return false;
  }
  entity_message auth_key_entity;
  if (!make_key_entity(publicAppKey, &auth_key_entity)) {
    printf("certify_me error 2\n");
    return false;
  }

  // construct the vse attestation
  vse_clause vse_attest_clause;
  if (!construct_attestation(attest_key_entity, auth_key_entity,
        measurement_entity, &vse_attest_clause)) {
  }
  // Create the attestation and sign it
  string serialized_attestation;
  if (!vse_attestation(descript, enclave_type, enclave_id, vse_attest_clause, &serialized_attestation)) {
    printf("certify_me error 5\n");
    return false;
  }
  int size_out = 8192;
  byte out[size_out];
  if (!Attest(enclave_type, serialized_attestation.size(),
        (byte*) serialized_attestation.data(), &size_out, out)) {
    printf("certify_me error 6\n");
    return false;
  }
  string the_attestation_str;
  the_attestation_str.assign((char*)out, size_out);
  signed_claim_message the_attestation;
  if (!the_attestation.ParseFromString(the_attestation_str)) {
    printf("certify_me error 7\n");
    return false;
  }

  if (FLAGS_print_all) {
    printf("\nPlatform vse claim:\n");
    print_vse_clause(vc);
    printf("\n");
    printf("attest vse claim:\n");
    print_vse_clause(vse_attest_clause);
    printf("\n\n");
    printf("attestation signed claim\n");
    print_signed_claim(the_attestation);
    printf("\n");
    printf("attestation underlying claim\n");
    claim_message tcm;
    string ser_claim_str;
    ser_claim_str.assign((char*)the_attestation.serialized_claim_message().data(),
        the_attestation.serialized_claim_message().size());
    tcm.ParseFromString(ser_claim_str);
    print_claim(tcm);
    printf("\n");
  }

  // Get certified
  trust_request_message request;
  trust_response_message response;

  // Should trust_request_message should be signed by auth key
  //   to prevent MITM attacks?  Probably not.
  request.set_requesting_enclave_tag("requesting-enclave");
  request.set_providing_enclave_tag("providing-enclave");
  request.set_submitted_evidence_type("platform-attestation-only");
  request.set_purpose("authentication");


  // Construct the evidence package
  // put platform attest claim and attestation in the following order
  // platform_says_attest_key_is_trusted, the_attestation
  evidence_package* ep = new(evidence_package);
  if (!construct_platform_evidence_package(signed_platform_says_attest_key_is_trusted,
        the_attestation, ep))  {
  }
  request.set_allocated_support(ep);

  // Serialize request
  string serialized_request;
  if (!request.SerializeToString(&serialized_request)) {
    printf("certify_me error 8\n");
    return false;
  }

  if (FLAGS_print_all) {
    printf("\nRequest:\n");
    print_trust_request_message(request);
  }

  // dial service
  struct sockaddr_in address;
  memset((byte*)&address, 0, sizeof(struct sockaddr_in));
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0) {
    return false;
  }
  struct hostent* he = gethostbyname(FLAGS_policy_host.c_str());
  if (he == nullptr) {
    return false;
  }
  memcpy(&(address.sin_addr.s_addr), he->h_addr, he->h_length);
  address.sin_family = AF_INET;
  address.sin_port = htons(FLAGS_policy_port);
  if(connect(sock,(struct sockaddr *) &address, sizeof(address)) != 0) {
    return false;
  }
  
  // write request
  if (write(sock, (byte*)serialized_request.data(), serialized_request.size()) < 0) {
    return false;
  }

  // read response
  // Todo: Replace with call to int sized_read(int fd, string* out)
  int size_response_buf = 32000;
  byte response_buf[size_response_buf];
  int n = read(sock, response_buf, size_response_buf);
  if (n < 0) {
     printf("Can't read response\n");
    return false;
  }

  string serialized_response;
  serialized_response.assign((char*)response_buf, n);
  if (!response.ParseFromString(serialized_response)) {
    printf("Can't parse response\n");
    return false;
  }

  if (FLAGS_print_all) {
    printf("\nResponse:\n");
    print_trust_response_message(response);
  }

  if (response.status() != "succeeded") {
    printf("Certification failed\n");
    return false;
  }
  // store cert in authentication key
  publicAppKey.set_certificate(response.artifact());
  privateAppKey.set_certificate(response.artifact());

  X509* art_cert = X509_new();
  string d_str;
  d_str.assign((char*)response.artifact().data(),response.artifact().size());
  if (asn1_to_x509(d_str, art_cert)) {
     X509_print_fp(stdout, art_cert);
  }
  close(sock);

  // Update store and save it
  string auth_tag("auth-key");
  const key_message* km = pStore.get_authentication_key_by_tag(auth_tag);
  if (km == nullptr) {
    printf("Can't find authentication key in store\n");
    return false;
  }
  ((key_message*) km)->set_certificate((byte*)response.artifact().data(), response.artifact().size());
  return save_store(enclave_type);
}

// SSL support

int SSL_my_client_callback(SSL *s, int *al, void *arg) {
  printf("callback\n");
  return 1;
}

// this is used to test the signature chain is verified properly
int verify_callback(int preverify, X509_STORE_CTX* x509_ctx) {
  int depth = X509_STORE_CTX_get_error_depth(x509_ctx);
  int err = X509_STORE_CTX_get_error(x509_ctx);

  X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
  X509_NAME* iname = cert ? X509_get_issuer_name(cert) : NULL;
  X509_NAME* sname = cert ? X509_get_subject_name(cert) : NULL;

  printf("Depth %d, Preverify: %d\n", depth, preverify);
  printf("Issuer CN : ");
  print_cn_name(iname);
  printf("Subject CN: ");
  print_cn_name(sname);

  if(depth == 0) {
    /* If depth is 0, its the server's certificate. Print the SANs too */
    printf("Subject ORG: ");
    print_org_name(sname);
  }

  return preverify;
}

// temporary hack till I fix client auth in ssl
bool client_auth_client(SSL* ssl) {
  bool ret = true;

  int size_nonce = 128;
  byte nonce[size_nonce];
  int size_sig = 256;
  byte sig[size_sig];
  RSA* r = nullptr;

  // send cert
  SSL_write(ssl, privateAppKey.certificate().data(),
      privateAppKey.certificate().size());
  size_nonce = SSL_read(ssl, nonce, size_nonce);

  r = RSA_new();
  if (!key_to_RSA(privateAppKey, r)) {
    ret = false;
    goto done;
  }

  if (!rsa_sha256_sign(r, size_nonce, nonce, &size_sig, sig)) {
    ret = false;
    goto done;
  }
  SSL_write(ssl, sig, size_sig);
  printf("client_auth_client succeeds\n");

done:
  if (r != nullptr)
    RSA_free(r);
  return ret;
}

bool client_auth_server(SSL*ssl) {
  bool ret = true;
  int res = 0;

  int size_cert = 8192;
  byte cert_buf[size_cert];
  int size_nonce = 64;
  byte nonce[size_nonce];
  int size_sig = 256;
  byte sig[size_sig];

  X509* x = nullptr;
  EVP_PKEY* client_auth_public_key = nullptr;
  EVP_PKEY* subject_pkey = nullptr;
  RSA* r = nullptr;
  X509_STORE_CTX* ctx = nullptr; 

  // prepare for verify 
  X509_STORE* cs = X509_STORE_new();
  X509_STORE_add_cert(cs, policy_cert);
  ctx = X509_STORE_CTX_new();

  // get cert
  // Todo: Replace with call to int sized_read(int fd, string* out)
  size_cert= SSL_read(ssl, cert_buf, size_cert);
  string asn_cert;
  asn_cert.assign((char*)cert_buf, size_cert);

  x = X509_new();
  if (!asn1_to_x509(asn_cert, x)) {
    ret = false;
    goto done;
  }

  subject_pkey = X509_get_pubkey(x);
  if (subject_pkey == nullptr) {
    ret = false;
    goto done;
  }
  r = EVP_PKEY_get1_RSA(subject_pkey);
  if (r == nullptr) {
    ret = false;
    goto done;
  }
  
  memset(nonce, 0, 64);
  if (!get_random(64 * 8, nonce)) {
    ret = false;
    goto done;
  }
  SSL_write(ssl, nonce, size_nonce);

  // get signature
  // Todo: Replace with call to int sized_read(int fd, string* out)
  size_sig = SSL_read(ssl, sig, size_sig);

  // verify chain

  res = X509_STORE_CTX_init(ctx, cs, x, nullptr);
  X509_STORE_CTX_set_cert(ctx, x);
  res = X509_verify_cert(ctx);
  if (res != 1) {
    ret = false;
    goto done;
  }

  // verify signature
  if (!rsa_sha256_verify(r, size_nonce, nonce, size_sig, sig)) {
    ret = false;
    goto done;
  }
  printf("client_auth_server succeeds\n");

done:
  if (x != nullptr)
    X509_free(x);
  if (r != nullptr)
    RSA_free(r);
  if (subject_pkey != nullptr)
    EVP_PKEY_free(subject_pkey);
  if (ctx != nullptr)
    X509_STORE_CTX_free(ctx);
  
  return ret;
}

void server_application(SSL* ssl) {
  int res = SSL_accept(ssl);
  if (res != 1) {
    printf("Server: Can't SSL_accept connection\n");
    unsigned long code = ERR_get_error();
    printf("Accept error: %s\n", ERR_lib_error_string(code));
    print_ssl_error(SSL_get_error(ssl, res));
    SSL_free(ssl);
    return;
  }
  int sd = SSL_get_fd(ssl);
  printf("Accepted ssl connection using %s \n", SSL_get_cipher(ssl));

#if 1
    // Verify a client certificate was presented during the negotiation
    X509* cert = SSL_get_peer_certificate(ssl);
    if(cert) {
      // X509_free(cert);
      printf("Server: Peer cert presented in nego\n");
    } else {
      printf("Server: No peer cert presented in nego\n");
      // return;
    }
#endif

  if (!client_auth_server(ssl)) {
    printf("Hokey client auth failed at server\n");
    return;
  }

  // Todo: use sized_read
  byte in[1024];
  memset(in, 0, 1024);

  // client starts, in a real application we would likely get a serialized protobuf
  // Todo: Replace with call to int sized_read(int fd, string* out)
  int n = SSL_read(ssl, in, 1024);
  printf("SSL server read: %s\n", (const char*) in);

  // says something back
  const char* msg = "Hi from your secret server\n";
  SSL_write(ssl, (byte*)msg, strlen(msg));
  close(sd);
  SSL_free(ssl);
}

bool load_server_certs_and_key(SSL_CTX* ctx) {
  // load auth key, policy_cert and certificate chain
  RSA* r = RSA_new();
  if (!key_to_RSA(privateAppKey, r)) {
    return false;
  }
  EVP_PKEY* auth_private_key = EVP_PKEY_new();
  EVP_PKEY_set1_RSA(auth_private_key, r);

  X509* x509_auth_key_cert= X509_new();
  string auth_cert_str;
  auth_cert_str.assign((char*)privateAppKey.certificate().data(),privateAppKey.certificate().size());
  if (!asn1_to_x509(auth_cert_str, x509_auth_key_cert)) {
      return false;
  }

  STACK_OF(X509)* stack = sk_X509_new_null();
  if (sk_X509_push(stack, policy_cert) == 0) {
    return false;
  }
#if 0
  // Don't need this
  if (sk_X509_push(stack, x509_auth_key_cert) == 0) {
      return false;
  }
#endif

  if (SSL_CTX_use_cert_and_key(ctx, x509_auth_key_cert, auth_private_key, stack, 1) <= 0 ) {
      return false;
  }
  if (!SSL_CTX_check_private_key(ctx) ) {
      return false;
  }
  SSL_CTX_add_client_CA(ctx, policy_cert);
  SSL_CTX_add1_to_CA_list(ctx, policy_cert);
  return true;
}

// Secure channel support

bool run_me_as_server(const string& host_address, int port) {
  SSL_load_error_strings();

  const char* hostname = FLAGS_server_app_host.c_str();
  int port= FLAGS_server_app_port;
  struct sockaddr_in addr;

  struct hostent *he = nullptr;
  if ((he = gethostbyname(hostname)) == NULL) {
    printf("gethostbyname failed\n");
    return false;
  }
  int sd = socket(AF_INET, SOCK_STREAM, 0);
  if (sd < 0) {
    printf("socket call failed\n");
    return false;
  }
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = *(long*)(he->h_addr);
  if (bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
    printf("bind failed\n");
    return false;
  }
  if (listen(sd, 10) != 0) {
    printf("listen failed\n");
    return false;
  }

  SSL_METHOD* method = (SSL_METHOD*) TLS_server_method();
  SSL_CTX* ctx = SSL_CTX_new(method);
  if (ctx == NULL) {
    printf("SSL_CTX_new failed\n");
    return false;
  }
  X509_STORE* cs = SSL_CTX_get_cert_store(ctx);
  X509_STORE_add_cert(cs, policy_cert);

  if (!load_server_certs_and_key(ctx)) {
    printf("SSL_CTX_new failed\n");
    return false;
  }

  const long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
  SSL_CTX_set_options(ctx, flags);

#if 0
  // This is unnecessary on my mac.
  if(!isRoot()) {
    printf("This program must be run as root/sudo user!!");
    return false;
  }
#endif

#if 0
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
    // IMPORTANT:
    // should be able to use: SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_callback);
#else
     SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
#endif
    unsigned int len = 0;
    while (1) {
      printf("example_app server at accept\n");
      struct sockaddr_in addr;
      int client = accept(sd, (struct sockaddr*)&addr, &len);
      SSL* ssl = SSL_new(ctx);
      SSL_set_fd(ssl, client);
      server_application(ssl);
  }
  close(sd);
  SSL_CTX_free(ctx);
  return true;
}

void client_application(SSL* ssl) {
  // client starts, in a real application we would likely send a serialized protobuf
  const char* msg = "Hi from your secret client\n";
  SSL_write(ssl, (byte*)msg, strlen(msg));
  byte buf[1024];
  memset(buf, 0, 1024);
  // Todo: Replace with call to int sized_read(int fd, string* out)
  int n = SSL_read(ssl, buf, 1024);
  printf("SSL client read: %s\n", (const char*)buf);
}

bool load_client_certs_and_key(SSL_CTX* ctx) {
  RSA* r = RSA_new();
  if (!key_to_RSA(privateAppKey, r)) {
    printf("load_client_certs_and_key, error 1\n");
    return false;
  }
  EVP_PKEY* auth_private_key = EVP_PKEY_new();
  EVP_PKEY_set1_RSA(auth_private_key, r);

  X509* x509_auth_key_cert= X509_new();
  string auth_cert_str;
  auth_cert_str.assign((char*)privateAppKey.certificate().data(), privateAppKey.certificate().size());
  if (!asn1_to_x509(auth_cert_str, x509_auth_key_cert)) {
    printf("load_client_certs_and_key, error 2\n");
      return false;
  }

  STACK_OF(X509)* stack = sk_X509_new_null();
  if (sk_X509_push(stack, policy_cert) == 0) {
    printf("load_client_certs_and_key, error 3\n");
    return false;
  }
#if 0
  // Don't need this
  if (sk_X509_push(stack, x509_auth_key_cert) == 0) {
    printf("load_client_certs_and_key, error 4\n");
      return false;
  }
#endif

  if (SSL_CTX_use_cert_and_key(ctx, x509_auth_key_cert, auth_private_key, stack, 1) <= 0 ) {
    printf("load_client_certs_and_key, error 5\n");
      return false;
  }
  if (!SSL_CTX_check_private_key(ctx) ) {
    printf("load_client_certs_and_key, error 6\n");
    return false;
  }
  SSL_CTX_add_client_CA(ctx, policy_cert);
  SSL_CTX_add1_to_CA_list(ctx, policy_cert);
  return true;
}

bool init_client_ssl(int* p_sd, SSL_CTX** p_ctx, SSL** p_ssl) {
  OPENSSL_init_ssl(0, NULL);;
  SSL_load_error_strings();

  const char* hostname = FLAGS_server_app_host.c_str();
  int port= FLAGS_server_app_port;
  struct sockaddr_in addr;

  int sd = socket(AF_INET, SOCK_STREAM, 0);
  if (sd <= 0) {
    printf("init_client_ssl, error 1.5\n");
    unsigned long code = ERR_get_error();
    const char* error_str = ERR_lib_error_string(code);
    printf("Error: %s\n", error_str);
  }

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);

  struct hostent *he = gethostbyname(hostname);
  if (he == nullptr) {
    printf("init_client_ssl, error 1\n");
    return false;
  }
  memcpy(&(addr.sin_addr.s_addr), he->h_addr, he->h_length);

  if (connect(sd, (struct sockaddr*)&addr, sizeof(addr)) !=  0) {
    printf("init_client_ssl, error 2, port: %d\n", port);
    close(sd);
    return false;
  }

  const SSL_METHOD* method = TLS_client_method();
  if(method == nullptr) {
    printf("Can't get method\n");
    return false;
  }
  SSL_CTX* ctx = SSL_CTX_new(method);
  if(ctx == nullptr) {
    printf("Can't get SSL_CTX\n");
    return false;
  }
  X509_STORE* cs = SSL_CTX_get_cert_store(ctx);
  X509_STORE_add_cert(cs, policy_cert);

#if 0
  // for debugging
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
#else
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
#endif

  SSL_CTX_set_verify_depth(ctx, 4);
  const long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
  SSL_CTX_set_options(ctx, flags);

  SSL* ssl = SSL_new(ctx);
  SSL_set_fd(ssl, sd);
  int res = SSL_set_cipher_list(ssl, "TLS_AES_256_GCM_SHA384");  // Change?

  if (!load_client_certs_and_key(ctx)) {
    printf("load_client_certs_and_key failed\n");
    return false;
  }

  // SSL_connect - initiate the TLS/SSL handshake with an TLS/SSL server
  if (SSL_connect(ssl) == 0) {
    printf("ssl_connect failed\n");
    return false;
  }

  // Verify a server certificate was presented during the negotiation
  X509* cert = SSL_get_peer_certificate(ssl);
  if(cert) {
    // X509_free(cert);
    printf("Client: Peer cert presented in nego\n");
  } else {
    printf("Client: No peer cert presented in nego\n");
  }

  *p_sd = sd;
  *p_ctx = ctx;
  *p_ssl = ssl;
  return true;
}

void close_client_ssl(int sd, SSL_CTX* ctx, SSL* ssl) {
  if (ssl != nullptr)
    SSL_free(ssl);
  if (sd > 0)
    close(sd);
  if (ctx !=nullptr)
    SSL_CTX_free(ctx);
}

bool run_me_as_client() {
  SSL_load_error_strings();
  int sd = 0;
  SSL_CTX* ctx = nullptr;
  SSL* ssl = nullptr;

  if (!init_client_ssl(&sd, &ctx, &ssl)) {
    printf("init_client_ssl failed\n");
    return false;
  }

  if (!client_auth_client(ssl)) {
    printf("Hokey client auth failed at client\n");
    return false;
  }
  client_application(ssl);
  close_client_ssl(sd, ctx, ssl);
  return true;
}

// --------------------------------------------------------------------------------------

bool construct_platform_evidence_package(signed_claim_message& platform_attest_claim,
    signed_claim_message& the_attestation, evidence_package* ep) {
    
  string pt("vse-verifier");
  string et("signed-claim");

  ep->set_prover_type(pt);
  evidence* ev1 = ep->add_fact_assertion();
  ev1->set_evidence_type(et);
  signed_claim_message sc1;
  sc1.CopyFrom(platform_attest_claim);
  string serialized_sc1;
  if (!sc1.SerializeToString(&serialized_sc1))
    return false;
  ev1->set_serialized_evidence((byte*)serialized_sc1.data(), serialized_sc1.size());

  evidence* ev2 = ep->add_fact_assertion();
  ev2->set_evidence_type(et);
  signed_claim_message sc2;
  sc2.CopyFrom(the_attestation);
  string serialized_sc2;
  if (!sc2.SerializeToString(&serialized_sc2))
    return false;
  ev2->set_serialized_evidence((byte*)serialized_sc2.data(), serialized_sc2.size());
  return true;
}

bool construct_attestation(entity_message& attest_key_entity, entity_message& auth_key_entity,
        entity_message& measurement_entity, vse_clause* vse_attest_clause) {
  string s1("says");
  string s2("speaks-for");

  vse_clause auth_key_speaks_for_measurement;
  if (!make_simple_vse_clause(auth_key_entity, s2, measurement_entity, &auth_key_speaks_for_measurement)) {
    printf("Construct attestation error 1\n");
    return false;
  }
  if (!make_indirect_vse_clause(attest_key_entity, s1, auth_key_speaks_for_measurement, vse_attest_clause)) {
    printf("Construct attestation error 1\n");
    return false;
  }
  return true;
}

void print_cn_name(X509_NAME* name) {
  char name_buf[1024];
  if (X509_NAME_get_text_by_NID(name, NID_commonName, name_buf, 1024) > 0) {
    printf(" %s", name_buf);
  }
  printf("\n");
}

void print_org_name(X509_NAME* name) {
  char name_buf[1024];
  if (X509_NAME_get_text_by_NID(name, NID_organizationName, name_buf, 1024) > 0) {
    printf(" %s", name_buf);
  }
  printf("\n");
}

void print_ssl_error(int code) {
  switch(code) {
  case SSL_ERROR_NONE:
    printf("No ssl error\n");
    break;
  case SSL_ERROR_WANT_READ:
    printf("want read ssl error\n");
    break;
  case SSL_ERROR_WANT_WRITE:
    printf("want write ssl error\n");
    break;
  case SSL_ERROR_WANT_CONNECT:
    printf("want connect ssl error\n");
    break;
  case SSL_ERROR_WANT_ACCEPT:
    printf("want accept ssl error\n");
    break;
  case SSL_ERROR_WANT_X509_LOOKUP:
    printf("want lookup ssl error\n");
    break;
  case SSL_ERROR_WANT_ASYNC:
    printf("want async ssl error\n");
    break;
  case SSL_ERROR_WANT_CLIENT_HELLO_CB:
    printf("wantclient hello  ssl error\n");
    break;
  case SSL_ERROR_SSL:
    printf("ssl error error\n");
    break;
  default:
    printf("Unknown ssl error, %d\n", code);
    break;
  }
}
