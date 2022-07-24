#include <gtest/gtest.h>
#include <gflags/gflags.h>

#include "support.h"
#include "certifier.h"
#include "simulated_enclave.h"
#include "application_enclave.h"
#include "certifier.pb.h"
#include <mutex>
#include <thread>

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

DEFINE_bool(help_me, false, "Want help?");
DEFINE_bool(cold_init_service, false, "Start over");

DEFINE_bool(print_all, false,  "verbose");
DEFINE_bool(print_log, false,  "print log");
DEFINE_string(log_file_name, "service.log", "service log file");

DEFINE_string(policy_cert_file, "policy_cert_file.bin", "policy_cert");
DEFINE_string(policy_host, "localhost", "address for policy server");
DEFINE_int32(policy_port, 8123, "port for policy server");

DEFINE_string(service_dir, "./service/", "directory for service data");
DEFINE_string(service_policy_store, "policy_store.bin", "policy store for service");

DEFINE_string(server_app_host, "localhost", "address for application requests");
DEFINE_int32(server_app_port, 8127, "port for application requests");

DEFINE_string(run_policy, "all", "what programs to run");  // "signed" is other possibility
DEFINE_string(host_enclave_type, "simulated-enclave", "Primary enclave");

// For simulated enclave only
DEFINE_string(platform_file_name, "platform_file.bin", "platform certificate");
DEFINE_string(platform_attest_endorsement, "platform_attest_endorsement.bin", "platform endorsement of attest key");
DEFINE_string(attest_key_file, "attest_key_file.bin", "attest key");
DEFINE_string(measurement_file, "app_service.measurement", "measurement");

bool service_trust_data_initialized = false;
key_message publicPolicyKey;

#include "policy_key.cc"

string serializedPolicyCert;
string serializedServiceCert;
policy_store pStore;
X509* policy_cert = nullptr;
X509* service_cert = nullptr;

// For attest
key_message privateServiceKey;
key_message publicServiceKey;

// This is the sealing key
const int service_symmetric_key_size = 64;
byte service_symmetric_key[service_symmetric_key_size];
key_message app_sealing_key;

// Protect Key
byte symmetric_key_for_protect[service_symmetric_key_size];
key_message protect_symmetric_key;

#define DEBUG

// --------------------------------------------------------------------------

void print_trust_data() {
  if (!service_trust_data_initialized)
    return;
  printf("\nTrust data:\n");
  printf("\nPolicy key\n");
  print_key(publicPolicyKey);
  printf("\nPolicy cert\n");
  print_bytes(serializedPolicyCert.size(), (byte*)serializedPolicyCert.data());
  printf("\n");
  printf("\nPrivate attest key\n");
  print_key(privateServiceKey);
  printf("\nPublic attestkey\n");
  print_key(publicServiceKey);
  printf("\nSeal key\n");
  print_bytes(service_symmetric_key_size, service_symmetric_key);
  printf("\n\n");
  printf("\nBlob key\n");
  print_bytes(service_trust_data_initialized, symmetric_key_for_protect);
  printf("\n\n");
}

bool save_store(const string& enclave_type) {
  string serialized_store;

  if (!pStore.Serialize(&serialized_store)) {
    printf("save_store() can't serialize store\n"); 
    return false;
  }
  int size_protected_store = serialized_store.size() + 4096;
  byte protected_store[size_protected_store];
  if (!Protect_Blob(enclave_type, protect_symmetric_key, serialized_store.size(),
          (byte*)serialized_store.data(), &size_protected_store, protected_store)) {
    printf("save_store can't protect blob\n");
    return false;
  }

  string store_file(FLAGS_service_dir);
  store_file.append(FLAGS_service_policy_store);
  if (!write_file(store_file, size_protected_store, protected_store)) {
    printf("save_store can't write %s\n", store_file.c_str());
    return false;
  }
  return true;
}

bool fetch_store(const string& enclave_type) {
  string store_file(FLAGS_service_dir);
  store_file.append(FLAGS_service_policy_store);

  int size_protected_blob = file_size(store_file) + 1;
  byte protected_blob[size_protected_blob];
  int size_unprotected_blob = size_protected_blob;
  byte unprotected_blob[size_unprotected_blob];

  if (!read_file(store_file, &size_protected_blob, protected_blob)) {
    printf("fetch_store can't read %s\n", store_file.c_str());
    return false;
  }
  
  if (!Unprotect_Blob(enclave_type, size_protected_blob, protected_blob,
        &protect_symmetric_key, &size_unprotected_blob, unprotected_blob)) {
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

void clear_sensitive_data() {
  // Todo: clear symmetric and private keys
}

bool cold_init(const string& enclave_type) {

  // Because of policy_key.cc include, the asn1 policy cert is in
  // initialized_cert it has size initialized_cert_size equal
  serializedPolicyCert.assign((char*)initialized_cert, initialized_cert_size);

  policy_cert = X509_new();
  if (!asn1_to_x509(serializedPolicyCert, policy_cert)) {
    printf("Can't translate cert\n");
    return false;
  }

  // make key message for public policy key from cert
  EVP_PKEY* epk = X509_get_pubkey(policy_cert);
  if (epk == nullptr) {
    printf("Can't get subject key\n");
    return false;
  }
  RSA* rk = EVP_PKEY_get1_RSA(epk);
  if (rk == nullptr) {
    printf("Can't get subject rsa key\n");
    return false;
  }

  X509_NAME* sn = X509_get_subject_name(policy_cert);
  if (sn == nullptr) {
    printf("Can't get subject name\n");
    return false;
  }

  string subject_name_str;
  char name_buf[1024];
  if (X509_NAME_get_text_by_NID(sn, NID_commonName, name_buf, 1024) < 0)
    return false;
  subject_name_str.assign((const char*) name_buf);

  const BIGNUM* N = BN_new();
  const BIGNUM* E = BN_new();
  const BIGNUM* D = BN_new();
  RSA_get0_key(rk, &N, &E, &D);

  rsa_message* rkm = new(rsa_message);
  if (rkm == nullptr)

  int size_n = BN_num_bytes(N);
  int size_e = BN_num_bytes(E);

  byte bn_buf[8192];
  int s = BN_bn2bin(N, bn_buf);
  if (s <= 0)
    return false;
  rkm->set_public_modulus(bn_buf, s);
  s = BN_bn2bin(E, bn_buf);
  if (s <= 0)
    return false;
  rkm->set_public_exponent(bn_buf, s);

  publicPolicyKey.set_key_name(subject_name_str);
        int size_n = 256;
  if (size_n == 128) {
    publicPolicyKey.set_key_type("rsa-1024-public");
  } else if (size_n == 256) {
    publicPolicyKey.set_key_type("rsa-2048-public");
  } else {
    return false;
  }
  publicPolicyKey.set_key_format("vse-key");
  publicPolicyKey.set_allocated_rsa_key(rkm);

  BN_free((BIGNUM*)N);
  BN_free((BIGNUM*)E);
  BN_free((BIGNUM*)D);

  EVP_PKEY_free(epk);
  RSA_free(rk);
  X509_NAME_free(sn);
  string* cert_str = new(string);
  cert_str->assign((char*)initialized_cert, initialized_cert_size);
  publicPolicyKey.set_allocated_certificate(cert_str);

  // make up some symmetric keys
  if (!get_random(8 * service_symmetric_key_size, service_symmetric_key))
    return false;
  if (!get_random(8 * service_symmetric_key_size, symmetric_key_for_protect))
    return false;

  // service_symmetric_key
  app_sealing_key.set_key_name("sealing-key");
  app_sealing_key.set_key_type("aes-256-cbc-hmac-sha256");
  app_sealing_key.set_key_format("vse-key");
  app_sealing_key.set_secret_key_bits(service_symmetric_key, service_symmetric_key_size);

  // fill symmetric_key_for_protect
  protect_symmetric_key.set_key_name("protect-key");
  protect_symmetric_key.set_key_type("aes-256-cbc-hmac-sha256");
  protect_symmetric_key.set_key_format("vse-key");
  protect_symmetric_key.set_secret_key_bits(symmetric_key_for_protect, service_symmetric_key_size);

  // Todo: Stick keys in store

  // make service attest private and public key
  if (!make_certifier_rsa_key(2048,  &privateServiceKey)) {
    return false;
  }
  privateServiceKey.set_key_name("service-key");
  if (!private_key_to_public_key(privateServiceKey, &publicServiceKey)) {
    printf("Can't make public Service key\n");
    return false;
  }

  // put symmetric keys, app private and public key and policy_cert in store
  if (!pStore.replace_policy_key(publicPolicyKey)) {
    printf("Can't store policy key\n");
    return false;
  }

  string auth_tag("attest-key");
  if (!pStore.add_authentication_key(auth_tag, privateServiceKey)) {
    printf("Can't store auth key\n");
    return false;
  }

  // protect_symmetric_key
  printf("enclave type: %s\n", enclave_type.c_str());
  if (!save_store(enclave_type)) {
    printf("Can't save store\n");
    return false;
  }

  if (FLAGS_print_all) {
    print_trust_data();
  }

  service_trust_data_initialized = true;
  return service_trust_data_initialized;
}

bool warm_restart(const string& enclave_type) {
  if (!fetch_store(enclave_type)) {
    printf("Can't fetch store\n");
    return false;
  }

  // initialize trust data from store
  const key_message* pk = pStore.get_policy_key();
  if (pk == nullptr) {
    printf("warm-restart error 1\n");
    return false;
  }

  string attest_tag("attest-key");
  const key_message* ak = pStore.get_authentication_key_by_tag(attest_tag);
  if (ak == nullptr) {
    printf("warm-restart error 2\n");
    return false;
  }

  publicPolicyKey.CopyFrom(*pk);
  privateServiceKey.CopyFrom(*ak);
  if (!private_key_to_public_key(privateServiceKey, &publicServiceKey)) {
    printf("Can't make public Service key\n");
    return false;
  }
  serializedPolicyCert = publicPolicyKey.certificate();
  policy_cert = X509_new();
  const byte* p = (const byte*) serializedPolicyCert.data();
  if (d2i_X509(&policy_cert, &p, (int)serializedPolicyCert.size()) == NULL) {
    printf("warm-restart error 5\n");
    return false;
  }

  // Todo: Get cert from store

  service_trust_data_initialized = true;

  if (FLAGS_print_all) {
    print_trust_data();
  }
  return service_trust_data_initialized;
}

// -----------------------------------------------------------------------------

bool certify_me(const string& enclave_type) {
#if 0
  if (!warm_restart(enclave_type)) {
    printf("warm restart failed\n");
    return false;
  }
#endif

  // This comes from the platform usually
  string platform_attest_file_name(FLAGS_service_dir);
  platform_attest_file_name.append(FLAGS_platform_attest_endorsement);
  int plat_attest_size = file_size(platform_attest_file_name)+1;
  byte plat_attest_claim[plat_attest_size];

  if (!read_file(platform_attest_file_name, &plat_attest_size, plat_attest_claim)) {
    printf("Can't read %s\n", platform_attest_file_name.c_str());
    return false;
  }
  string pl_str;
  pl_str.assign((char*)plat_attest_claim, plat_attest_size);
  signed_claim_message signed_platform_says_attest_key_is_trusted;
  if (!signed_platform_says_attest_key_is_trusted.ParseFromString(pl_str)) {
    printf("Can't parse platform attest claim\n");
    return false;
  }
  if (FLAGS_print_all) {
    printf("Got platform claims\n");
    print_signed_claim(signed_platform_says_attest_key_is_trusted);
  }

  string platform_statement_str;
  claim_message c;
  platform_statement_str.assign((char*)signed_platform_says_attest_key_is_trusted.serialized_claim_message().data(),
      signed_platform_says_attest_key_is_trusted.serialized_claim_message().size());
  if (!c.ParseFromString(platform_statement_str)) {
    printf("Bad platform claim\n");
    return false;
  }

  if (c.claim_format() != "vse-clause") {
    printf("Platform claim is not vse-clause\n");
    return false;
  }

  vse_clause vc;
  string vc_str;
  vc_str.assign((char*)c.serialized_claim().data(), c.serialized_claim().size());
  if (!vc.ParseFromString(vc_str)) {
    printf("Can't parse vse platform claim\n");
    return false;
  }

  //  The platform statement is "platform-key says attestation-key is-trusted-for-attestation"
  //  We retrieve the entity describing the attestation key from this.
  entity_message attest_key_entity = vc.clause().subject();

  // get attestation.  Here we generate a vse-attestation which is
  // a claim, signed by the attestation key that signed a statement
  // the user requests (Some people call this the "user data" in an
  // attestation.  Formats for an attestation will vary among platforms
  // but they must always convery the information we do here.

  string enclave_id("");
  string descript("service-attest");
  string at_format("vse-attestation");
  string s1("says");
  string s2("speaks-for");

  // now construct the vse clause "attest-key says authentication key speaks-for measurement"
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
  if (!make_key_entity(publicServiceKey, &auth_key_entity)) {
    printf("certify_me error 2\n");
    return false;
  }

  vse_clause auth_key_speaks_for_measurement;
  if (!make_simple_vse_clause(auth_key_entity, s2, measurement_entity, &auth_key_speaks_for_measurement)) {
    printf("certify_me error 3\n");
    return false;
  }

  vse_clause vse_attest_clause;
  if (!make_indirect_vse_clause(attest_key_entity, s1, auth_key_speaks_for_measurement, &vse_attest_clause)) {
    printf("certify_me error 4\n");
    return false;
  }

  string serialized_attestation;
  if (!vse_attestation(descript, enclave_type, enclave_id, vse_attest_clause, &serialized_attestation)) {
    printf("certify_me error 5\n");
    return false;
  }

  int size_out = 8192;
  byte out[size_out];
  if (!Attest(enclave_type, serialized_attestation.size(), (byte*) serialized_attestation.data(), &size_out, out)) {
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

  // Important Todo: trust_request_message should be signed by authkey
  //   to prevent MITM attacks.
  request.set_requesting_enclave_tag("requesting-enclave");
  request.set_providing_enclave_tag("providing-enclave");
  request.set_submitted_evidence_type("platform-attestation-only");
  request.set_purpose("attestation");

  // Put platform claim and attestation in support in the following order
  //    platform_says_attest_key_is_trusted
  //    the_attestation
  evidence_package* ep = new(evidence_package);
  string pt("vse-verifier");
  string et("signed-claim");

  ep->set_prover_type(pt);
  evidence* ev1 = ep->add_fact_assertion();
  ev1->set_evidence_type(et);
  signed_claim_message sc1;
  sc1.CopyFrom(signed_platform_says_attest_key_is_trusted);
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

  request.set_allocated_support(ep);

  key_message* ppk = new(key_message);
  ppk->CopyFrom((const key_message)publicPolicyKey);
  request.mutable_policy_key()->CopyFrom((const key_message)publicPolicyKey);
  request.set_allocated_policy_key(ppk);

  string serialized_pk;
  if (!publicPolicyKey.SerializeToString(&serialized_pk)) {
    printf("certify_me error 12\n");
    return false;
  }
  request.set_serialized_policy_key((byte*)serialized_pk.data(), serialized_pk.size());
  request.set_service_address(FLAGS_server_app_host);

  // privateServiceKey
  RSA* priRsaServiceKey = RSA_new();
  if (!key_to_RSA(privateServiceKey, priRsaServiceKey)) {
    printf("certify_me error 13\n");
    return false;
  }
  int signed_pk_size = RSA_size(priRsaServiceKey);
  byte signed_pk[signed_pk_size];
  memset(signed_pk, 0, signed_pk_size);
  if (!rsa_sha256_sign(priRsaServiceKey, serialized_pk.size(),
                      (byte*)serialized_pk.data(),
                      &signed_pk_size, signed_pk)) {
    printf("certify_me error 14\n");
    return false;
  }
  string* pk_str= new(string);
  pk_str->assign((char*)signed_pk, signed_pk_size);
  request.set_allocated_signed_policy_key(pk_str);

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
  publicServiceKey.set_certificate(response.artifact());
  privateServiceKey.set_certificate(response.artifact());

  X509* art_cert = X509_new();
  string d_str;
  d_str.assign((char*)response.artifact().data(),response.artifact().size());
  if (asn1_to_x509(d_str, art_cert)) {
     X509_print_fp(stdout, art_cert);
  }
  close(sock);

  // Update store and save it
  string auth_tag("attest-key");
  const key_message* km = pStore.get_authentication_key_by_tag(auth_tag);
  if (km == nullptr) {
    printf("Can't find authentication key in store\n");
    return false;
  }
  ((key_message*) km)->set_certificate((byte*)response.artifact().data(),
        response.artifact().size());

  return save_store(enclave_type);
}

// -------------------------------------------------------------------------------------

class spawned_children {
public:
  bool valid_;
  string app_name_;
  string location_;
  string measured;
  int pid_;
  int parent_read_fd_;
  int parent_write_fd_;
  spawned_children* next_;
};

std::mutex kid_mtx;
spawned_children* my_kids = nullptr;

spawned_children* new_kid() {
  spawned_children* nk = new(spawned_children);
  if (nk == nullptr)
    return nullptr;
  kid_mtx.lock();
  nk->valid_ = false;
  nk->next_ = my_kids;
  my_kids = nk;
  kid_mtx.unlock();
  return nk;
}

spawned_children* find_kid(int pid) {
  kid_mtx.lock();
  spawned_children* k = my_kids;
  while (k != nullptr) {
    if (k->pid_ == pid)
      break;
    k = k->next_;
  }
  kid_mtx.unlock();
  return k;
}

void remove_kid(int pid) {
  kid_mtx.lock();
  if (my_kids == nullptr) {
    kid_mtx.unlock();
    return;
  }
  if (my_kids->pid_ == pid) {
    delete my_kids;
    my_kids = nullptr;
  }
  spawned_children* k = my_kids;
  while (k != nullptr) {
    if (k->next_ == nullptr)
      break;
    if (k->next_->pid_ == pid) {
      spawned_children* to_remove = k->next_;
      k->next_ = to_remove->next_;
      delete to_remove;
      break;
    }
    k = k->next_;
  }
  kid_mtx.unlock();
}

bool measure_binary(const string& file, string* m) {
  int size = file_size(file.c_str());
  if (size <= 0) {
    printf("Can't get executable file\n");
    return false;
  }
  byte* file_contents = (byte*)malloc(size);
  int bytes_read = size;
  if (!read_file(file, &bytes_read, file_contents) || bytes_read < size) {
    printf("Executable read failed\n");
    free(file_contents);
    return false;
  }
  byte digest[32];
  unsigned int len = 32;
  if (!digest_message(file_contents, bytes_read,
          digest, len)) {
    printf("Digest failed\n");
    free(file_contents);
    return false;
  }
  m->assign((char*)digest, (int)len);
  free(file_contents);
  return true;
}

void delete_child(int signum) {
    int pid = wait(nullptr);
    // kill the thread
    remove_kid(pid);
}

bool impl_Seal(string in, string* out) {
  byte iv[16];
  int t_size = in.size() + 64;
  byte t_out[t_size];

  if (!get_random(8 * 16, iv))
    return false;
  if (!authenticated_encrypt((byte*)in.data(), in.size(), service_symmetric_key,
            iv, t_out, &t_size)) {
    printf("impl_Seal: authenticated encrypt failed\n");
    return false;
  }
  out->assign((char*)t_out, t_size);
  return true;
}

bool impl_Unseal(string in, string* out) {
  int t_size = in.size();
  byte t_out[t_size];
  if (!authenticated_decrypt((byte*)in.data(), in.size(), service_symmetric_key,
            t_out, &t_size)) {
    printf("impl_Unseal: authenticated decrypt failed\n");
    return false;
  }
  out->assign((char*)t_out, t_size);
  return true;
}

bool impl_Attest(string in, string* out) {
  // in is a serialized vse-attestation
  claim_message cm;
  string nb, na;
  time_point tn, tf;
  if (!time_now(&tn))
    return false;
  if (!add_interval_to_time_point(tn, 24.0 * 365.0, &tf))
    return false;
  if (!time_to_string(tn, &nb))
    return false;
  if (!time_to_string(tf, &na))
    return false;
  string cf("vse-attestation");
  string desc("");
  if (!make_claim(in.size(), (byte*)in.data(), cf, desc,
        nb, na, &cm))
    return false;
  string ser_cm;
  if (!cm.SerializeToString(&ser_cm))
    return false;

  signed_claim_message scm;
  if (!make_signed_claim(cm, privateServiceKey, &scm)) {
    printf("impl_Attest: Signing failed\n");
    return false;
  }
  if (!scm.SerializeToString(out))
    return false;

  return true;
}

bool impl_GetCerts(string* out) {
  return false;
}

void app_service_loop(int read_fd, int write_fd) {
  int r_size = 4096;
  byte* r_buf[r_size];
  bool continue_loop = true;

  sleep(10); // hack
  printf("application service loop: %d %d\n", read_fd, write_fd);
  while(continue_loop) {
    sleep(5); // hack
    bool succeeded = false;
    // continue_loop = false;
    string in;
    string out;
    int n = read(read_fd, r_buf, r_size);
    printf("app_service_loop, read: %d\n", n);
    if (n <= 0) {
      continue;
    }
    string str_app_req;
    str_app_req.assign((char*)r_buf, n);
    app_request req;
    if (!req.ParseFromString(str_app_req)) {
      goto finishreq;
    }

    printf("app_service_loop, service requested: %s\n", req.function().c_str());
    if (req.function() == "seal") {
        in = req.args(0);
        succeeded= impl_Seal(in, &out);
    } else if (req.function() == "unseal") {
        in = req.args(0);
        succeeded= impl_Unseal(in, &out);
    } else if (req.function() == "attest") {
        in = req.args(0);
        succeeded= impl_Attest(in, &out);
    } else if (req.function() == "getcerts") {
        succeeded= impl_GetCerts(&out);
    }
    if (succeeded) {
      printf("service succeeded\n");
    } else {
      printf("service failed\n");
    }

finishreq:
    app_response rsp;
    string str_app_rsp;
    rsp.set_function(req.function());

    if (succeeded) {
      rsp.set_status("succeeded");
      rsp.add_args(out);
    } else {
      rsp.set_status("failed");
    }
    if (!rsp.SerializeToString(&str_app_rsp)) {
      printf("Can't serialize response\n");
    }
    if (write(write_fd, (byte*)str_app_rsp.data(), str_app_rsp.size()) <
            (int)str_app_rsp.size()) {
      printf("Response write failed\n");
    }
  }
}

bool start_app_service_loop(int read_fd, int write_fd) {
  printf("start_app_service_loop\n");
#if 0
  std::thread service_loop(app_service_loop, read_fd, write_fd);
#else
  app_service_loop(read_fd, write_fd);
#endif
  printf("after thread\n");
  return true;
}

bool process_run_request(run_request& req) {
  // check this for thread safety

  // measure binary
  string m;
  // Change later to prevent TOCTOU attack
  if (!req.has_location() || !measure_binary(req.location(), &m)) {
    printf("Can't measure binary\n");
    return false;
  }

  int fd1[2];
  int fd2[2];
  if (pipe(fd1) < 0) {
    printf("Pipe 1 failed\n");
    return false;
  }
  if (pipe(fd2) < 0) {
    printf("Pipe 2 failed\n");
    return false;
  }
  printf("pipes made %d %d %d %d\n", fd1[0], fd1[1], fd2[0], fd2[1]);

  int parent_read_fd = fd2[0];
  int parent_write_fd = fd1[1];
  int child_read_fd = fd1[0];
  int child_write_fd = fd2[1];

  // fork and get pid
  pid_t pid = fork();
  if (pid < 0) {
    printf("Can't fork\n");
    close(fd1[0]);
    close(fd1[1]);
    close(fd2[0]);
    close(fd2[1]);
    return false;
  } else if (pid == 0) {  // child
    close(parent_read_fd);
    close(parent_write_fd);

    // Todo: change owner

    printf("Child about to exec %s, read: %d, write: %d\n",
        req.location().c_str(), child_read_fd, child_write_fd);
    string n1 = std::to_string(child_read_fd);
    string n2 = std::to_string(child_write_fd);
    char *argv[3]= {
      (char*)n1.c_str(),
      (char*)n2.c_str(),
      nullptr
    };
    char *envp[1]= {
      nullptr
    };
    if (execve(req.location().c_str(), argv, envp) < 0) {
      printf("Exec failed\n");
      return false;
    }
  } else {  // parent
    close(child_read_fd);
    close(child_write_fd);
    signal(SIGCHLD, delete_child);
    printf("parent returned, read: %d, write: %d\n", parent_read_fd, parent_write_fd);

    // add it to lists
    spawned_children* nk = new_kid();
    if (nk == nullptr) {
      printf("Can't add kid\n");
      return false;
    }
    nk->location_ = req.location();
    nk->measured.assign((char*)m.data(), m.size());;
    nk->pid_ = pid;
    nk->parent_read_fd_ = parent_read_fd;
    nk->parent_write_fd_ = parent_write_fd;
    nk->valid_ = true;
    if (!start_app_service_loop(parent_read_fd, parent_write_fd)) {
      printf("Couldn't start service loop\n");
      return false;
    }
  }
  return true;
}

const int max_req_size = 4096;
bool app_request_server() {
  // This is the TCP server that requests to start
  // protected programs.
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

  unsigned int len = 0;
  while (1) {
    printf("application_service server at accept\n");
    struct sockaddr_in addr;
    int client = accept(sd, (struct sockaddr*)&addr, &len);
    printf("client: %d\n", client);

    // read run request
    byte in[max_req_size];
    memset(in, 0, max_req_size);
    int n = read(client, in, max_req_size);
    if (n < 0) {
      printf("Read failed in application server\n");
    }

    // This should be a serialized run_request
    bool ret = false;
    run_request req;
    string str_req;
    str_req.assign((char*)in, n);
    if (!req.ParseFromString(str_req)) {
      goto done;
    }
    printf("at process_run_request: %s\n", req.location().c_str());
    ret = process_run_request(req);

done:
    run_response resp;
    if (ret) {
      resp.set_status("succeeded");
    } else {
      resp.set_status("failed");
    }
    string str_resp;
    if (resp.SerializeToString(&str_resp)) {
      if(write(client, (byte*)str_resp.data(), str_resp.size()) < 0) {
        printf("Write failed\n");
      }
    }
    close(client);
  }
  close(sd);
  return true;
}

// ------------------------------------------------------------------------------

int main(int an, char** av) {
  gflags::ParseCommandLineFlags(&an, &av, true);
  an = 1;
  ::testing::InitGoogleTest(&an, av);

  SSL_library_init();
  string store_file(FLAGS_service_dir);
  store_file.append(FLAGS_service_policy_store);

  if (FLAGS_help_me) {
    printf("app_service.exe --print_all=true|false --policy_host=policy-host-address --policy_port=policy-host-port\n");
    printf("\t --service_dir=-directory-for-service-data --server_service_host=my-server-host-address --server_service_port=server-host-port\n");
    printf("\t --policy_cert_file=self-signed-policy-cert-file-name --policy_store_file=policy-store-file-name\n");
    printf("\t --host_enclave_type=\"simulated-enclave\"");
    return 0;
  }

  if (FLAGS_host_enclave_type == "simulated-enclave") {
    string at_file(FLAGS_service_dir);
    at_file.append(FLAGS_attest_key_file);
    string measurement_file(FLAGS_service_dir);
    measurement_file.append(FLAGS_measurement_file);
    if (!simulator_init(at_file.c_str(), measurement_file.c_str())) {
      printf("Can't init from : %s, %s\n", at_file.c_str(), measurement_file.c_str());
      return 1;
    }
  } else if (FLAGS_host_enclave_type == "oe-enclave") {
    printf("Unsupported host enclave\n");
    return 1;
  } else if (FLAGS_host_enclave_type == "sev-snp") {
    printf("Unsupported host enclave\n");
    return 1;
  } else {
    printf("Unsupported host enclave\n");
    return 1;
  }

  // initialize and certify service data
  if (FLAGS_cold_init_service || file_size(store_file) <= 0) {
    if (!cold_init(FLAGS_host_enclave_type)) {
      printf("cold-init failed\n");
      return 1;
    }
  }

#if 0
  if (!warm_restart(FLAGS_host_enclave_type)) {
    printf("warm-restart failed\n");
    return 1;
  }
#endif

  if (!certify_me(FLAGS_host_enclave_type)) {
    printf("certification failed\n");
    return 1;
  }

  // run service response
  if (!app_request_server()) {
    printf("Can't run request server\n");
    return 1;
  }

  clear_sensitive_data();
  return 0;
}
