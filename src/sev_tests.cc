//  Copyright (c) 2021-22, VMware Inc, and the Certifier Authors.  All rights
//  reserved.
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

#include "certifier.h"
#include "support.h"

#ifdef SEV_SNP

#  include "attestation.h"

using namespace certifier::framework;
using namespace certifier::utilities;

extern bool      verify_sev_Attest(EVP_PKEY *key,
                                   int       size_sev_attestation,
                                   byte *    the_attestation,
                                   int *     size_measurement,
                                   byte *    measurement);
extern EVP_PKEY *get_simulated_vcek_key();
extern bool sev_verify_report(EVP_PKEY *key, struct attestation_report *report);


bool test_sev(bool print_all) {
  const int data_size = 64;
  string    enclave_type("sev-enclave");
  string    enclave_id("test-enclave");
  byte      data[data_size];
  for (int i = 0; i < data_size; i++)
    data[i] = i;

  byte sealed[512];
  int  sealed_size = 512;
  memset(sealed, 0, sealed_size);

  if (!Seal(enclave_type, enclave_id, data_size, data, &sealed_size, sealed)) {
    printf("test_sev, seal error\n");
    return false;
  }

  if (print_all) {
    printf("\n");
    printf("data   size : %d\n", data_size);
    print_bytes(data_size, data);
    printf("\n");
    printf("Sealed size : %d\n", sealed_size);
    print_bytes(sealed_size, sealed);
    printf("\n");
  }

  byte unsealed[512];
  int  unsealed_size = 512;
  memset(unsealed, 0, unsealed_size);

  if (!Unseal(enclave_type,
              enclave_id,
              sealed_size,
              sealed,
              &unsealed_size,
              unsealed)) {
    printf("test_sev, unseal error\n");
    return false;
  }

  if (print_all) {
    printf("\n");
    printf("unsealed size: %d\n", unsealed_size);
    print_bytes(unsealed_size, unsealed);
    printf("\n");
  }

  if (unsealed_size != data_size || memcmp(data, unsealed, data_size) != 0) {
    printf("test_sev, unsealed response wrong\n");
    return false;
  }

  int  size_measurement = 64;
  byte measurement[size_measurement];
  memset(measurement, 0, size_measurement);

  attestation_user_data ud;
  ud.set_enclave_type("sev-enclave");
  RSA *r = RSA_new();
  if (!generate_new_rsa_key(2048, r))
    return false;
  key_message private_auth_key;
  key_message public_auth_key;
  if (!RSA_to_key(r, &private_auth_key)) {
    return false;
  }
  private_auth_key.set_key_name("authKey");
  if (!private_key_to_public_key(private_auth_key, &public_auth_key)) {
    return false;
  }
  // time
  time_point t;
  time_now(&t);
  string str_now;
  time_to_string(t, &str_now);
  ud.set_time(str_now);
  ud.mutable_enclave_key()->CopyFrom(public_auth_key);

  int    size_out = 2048;
  byte   out[size_out];
  string serialized_user;
  if (!ud.SerializeToString(&serialized_user)) {
    return false;
  }
  if (!Attest(ud.enclave_type(),
              serialized_user.size(),
              (byte *)serialized_user.data(),
              &size_out,
              out)) {
    printf("Attest failed\n");
    return false;
  }

#  ifdef SEV_DUMMY_GUEST
  extern EVP_PKEY *get_simulated_vcek_key();
  EVP_PKEY *       verify_pkey = get_simulated_vcek_key();
#  else
  extern int sev_read_pem_into_x509(const char *file_name, X509 **x509_cert);
  extern EVP_PKEY *sev_get_vcek_pubkey(X509 * x509_vcek);
  X509 *           x509_vcek;
  if (sev_read_pem_into_x509("test_data/vcek.pem", &x509_vcek)
      != EXIT_SUCCESS) {
    printf("Failed to load VCEK Cert!\n");
    return false;
  }
  EVP_PKEY *verify_pkey = sev_get_vcek_pubkey(x509_vcek);
#  endif /* SEV_DUMMY_GUEST */

  if (verify_pkey == nullptr)
    return false;
  bool success = verify_sev_Attest(verify_pkey,
                                   size_out,
                                   out,
                                   &size_measurement,
                                   measurement);
  EVP_PKEY_free(verify_pkey);
  verify_pkey = nullptr;

  if (!success) {
    printf("verify_sev_Attest failed\n");
    return false;
  }

  sev_attestation_message sev_att;
  string                  at_str;
  at_str.assign((char *)out, size_out);
  if (!sev_att.ParseFromString(at_str)) {
    printf("Can't parse attestation\n");
    return false;
  }

  attestation_user_data ud_new;
  string                ud_str;
  ud_str.assign((char *)sev_att.what_was_said().data(),
                sev_att.what_was_said().size());
  if (!ud_new.ParseFromString(ud_str)) {
    printf("Can't parse user data\n");
    return false;
  }

  if (!same_key(ud_new.enclave_key(), ud.enclave_key())) {
    printf("not same key\n");
    return false;
  }

  if (print_all) {
    attestation_report r;
    printf("attestation struct size is %lx, reported attestation size is %lx\n",
           sizeof(attestation_report),
           sev_att.reported_attestation().size());
    printf("report starts at: %lx, signature starts at %lx\n",
           (long unsigned int)&r,
           (long unsigned int)&r.signature);
    printf("\nMeasurement size: %d, measurement: ", size_measurement);
    print_bytes(size_measurement, measurement);
    printf("\n");
  }

  return true;
}

// new platform test
// ---------------------------------------------------------------------------------

#  if 0
// This was scaffolding for an earlier version and is no longer needed
bool simulated_sev_Attest(const key_message& vcek, const string& enclave_type,
      int ud_size, byte* ud_data, int* size_out, byte* out) {

  attestation_report ar;
  memset(&ar, 0, sizeof(ar));

  if (!digest_message(Digest_method_sha_384, ud_data, ud_size, ar.report_data, 48)) {
    printf("simulated_sev_Attest: can't digest ud\n");
    return false;
  }
  memset(ar.measurement, 0, 48);
  ar.version = 1;
  ar.guest_svn = 1;
  ar.policy = 0xff;
  // ar.family_id[16];
  // ar.image_id[16];
  // ar.vmpl;
  ar.signature_algo= SIG_ALGO_ECDSA_P384_SHA384;
  // ar.tcb_version platform_version;
  // ar.platform_info;
  // ar.flags;
  // ar.reserved0;
  // ar.host_data[32];
  // ar.id_key_digest[48];
  // ar.author_key_digest[48];
  // ar.report_id[32];
  // ar.report_id_ma[32];
  // ar.tcb_version reported_tcb;
  // ar.reserved1[24];
  // ar.chip_id[64];
  // ar.reserved2[192];
  // ar.signature.r[72];
  // ar.signature.s[72];

  EC_KEY* eck = key_to_ECC(vcek);
  int blk_len = ECDSA_size(eck);
  int sig_size_out = 2 * blk_len;
  byte sig_out[sig_size_out];
  if (!ecc_sign(Digest_method_sha_384, eck, sizeof(ar) - sizeof(ar.signature), (byte*)&ar,
          &sig_size_out, sig_out)) {
    printf("simulated_sev_Attest: can't ec_sign\n");
    return false;
  }
  memcpy(ar.signature.r, sig_out, blk_len);
  memcpy(ar.signature.s, &sig_out[blk_len], blk_len);
  EC_KEY_free(eck);

  sev_attestation_message atm;
  string atm_str;

  atm.mutable_what_was_said()->assign((char*)ud_data, ud_size);
  atm.mutable_reported_attestation()->assign((char*)&ar, sizeof(ar));

  if (!atm.SerializeToString(&atm_str)) {
    printf("simulated_sev_Attest: can't sev attestation\n");
    return false;
  }
  if (*size_out < (int)atm_str.size()) {
    printf("simulated_sev_Attest: output buffer too small\n");
    return false;
  }
  *size_out = atm_str.size();
  memcpy(out, (byte*)atm_str.data(), *size_out);

  return true;
}
#  endif /* 0 dead-code scaffolding for an earlier version */

bool construct_sev_platform_evidence(const string &     purpose,
                                     const string &     serialized_ark_cert,
                                     const string &     serialized_ask_cert,
                                     const string &     serialized_vcek_cert,
                                     const key_message &vcek,
                                     evidence_package * evp) {

  evp->set_prover_type("vse-verifier");
  string enclave_type("sev-enclave");

  // certs
  evidence *ev = evp->add_fact_assertion();
  if (ev == nullptr) {
    printf("construct_sev_platform_evidence: Can't add to ark platform "
           "evidence\n");
    return false;
  }
  ev->set_evidence_type("cert");
  ev->set_serialized_evidence(serialized_ark_cert);
  ev = evp->add_fact_assertion();
  if (ev == nullptr) {
    printf("construct_sev_platform_evidence: Can't add to ask platform "
           "evidence\n");
    return false;
  }
  ev->set_evidence_type("cert");
  ev->set_serialized_evidence(serialized_ask_cert);
  ev = evp->add_fact_assertion();
  if (ev == nullptr) {
    printf("construct_sev_platform_evidence: Can't add to vcek platform "
           "evidence\n");
    return false;
  }
  ev->set_evidence_type("cert");
  ev->set_serialized_evidence(serialized_vcek_cert);

  key_message auth_key;
  RSA *       r = RSA_new();
  if (!generate_new_rsa_key(2048, r)) {
    printf("construct_sev_platform_evidence: Can't generate rsa key\n");
    return false;
  }
  if (!RSA_to_key(r, &auth_key)) {
    printf("construct_sev_platform_evidence: Can't convert rsa key to key\n");
    RSA_free(r);
    return false;
  }
  RSA_free(r);

  // replace this with real sev certs and attestation
  attestation_user_data ud;
  if (purpose == "authentication") {
    if (!make_attestation_user_data(enclave_type, auth_key, &ud)) {
      printf("construct_sev_platform_evidence: Can't make user data (1)\n");
      return false;
    }
  } else if (purpose == "attestation") {
    if (!make_attestation_user_data(enclave_type, auth_key, &ud)) {
      printf("construct_sev_platform_evidence: Can't make user data (1)\n");
      return false;
    }
  } else {
    printf("construct_sev_platform_evidence: neither attestation or "
           "authorization\n");
    return false;
  }
  string serialized_ud;
  if (!ud.SerializeToString(&serialized_ud)) {
    printf("construct_sev_platform_evidence: Can't serialize user data\n");
    return false;
  }

  int  size_out = 16000;
  byte out[size_out];
#  if 1
  if (!Attest(enclave_type,
              serialized_ud.size(),
              (byte *)serialized_ud.data(),
              &size_out,
              out)) {
#  else
  if (!simulated_sev_Attest(vcek,
                            enclave_type,
                            serialized_ud.size(),
                            (byte *)serialized_ud.data(),
                            &size_out,
                            out)) {
#  endif /* 1 */

    printf("construct_sev_platform_evidence: Attest failed\n");
    return false;
  }
  string the_attestation_str;
  the_attestation_str.assign((char *)out, size_out);

  ev = evp->add_fact_assertion();
  if (ev == nullptr) {
    printf("construct_sev_platform_evidence: Can't add to attest platform "
           "evidence\n");
    return false;
  }
  ev->set_evidence_type("sev-attestation");
  ev->set_serialized_evidence(the_attestation_str);

  return true;
}

bool test_sev_platform_certify(const bool    debug_print,
                               const string &policy_file_name,
                               const string &policy_key_file,
                               const string &ark_key_file_name,
                               const string &ask_key_file_name,
                               const string &vcek_key_file_name,
                               const string &ark_cert_file_name,
                               const string &ask_cert_file_name,
                               const string &vcek_cert_file_name) {


  string           enclave_type("sev-enclave");
  string           evidence_descriptor("sev-full-platform");
  string           enclave_id("test-enclave");
  evidence_package evp;

  // This has no effect for now
  extern bool sev_Init(const string &, const string &, const string &);
  string      ark_cert;
  string      ask_cert;
  string      vcek_cert;
  if (!read_file_into_string(ark_cert_file_name, &ark_cert)) {
    printf("%s() error, line: %d, Can't read ark cert %s\n",
           __func__,
           __LINE__,
           ark_cert_file_name.c_str());
    return false;
  }
  if (!read_file_into_string(ask_cert_file_name, &ask_cert)) {
    printf("%s() error, line: %d, Can't read ask cert %s\n",
           __func__,
           __LINE__,
           ask_cert_file_name.c_str());
    return false;
  }
  if (!read_file_into_string(vcek_cert_file_name, &vcek_cert)) {
    printf("%s() error, line: %d, Can't read vcek cert %s\n",
           __func__,
           __LINE__,
           vcek_cert_file_name.c_str());
    return false;
  }

  if (!sev_Init(ark_cert, ask_cert, vcek_cert)) {
    printf("%s() error, line: %d, can't sev_Init\n", __func__, __LINE__);
    return false;
  }

  // get policy
  signed_claim_sequence signed_statements;
  if (!read_signed_vse_statements(policy_file_name, &signed_statements)) {
    printf("%s() error, line: %d, Can't read policy %s\n",
           __func__,
           __LINE__,
           policy_file_name.c_str());
    return false;
  }

  key_message policy_key;
  key_message policy_pk;
  string      policy_key_str;
  if (!read_file_into_string(policy_key_file, &policy_key_str)) {
    printf("%s() error, line: %d, Can't read policy key %s\n",
           __func__,
           __LINE__,
           policy_key_file.c_str());
    return false;
  }
  if (!policy_key.ParseFromString(policy_key_str)) {
    printf("test_sev_platform_certify: Can't parse policy key\n");
    return false;
  }
  if (!private_key_to_public_key(policy_key, &policy_pk)) {
    printf("test_sev_platform_certify: Can't convert policy key\n");
    return false;
  }

#  if 1
  //  For simulated SNP, we don't have real certs so we make some up.

  // Make ark, ask, vcek certs
  key_message ark_key;
  key_message ark_pk;
  string      ark_key_str;
  if (!read_file_into_string(ark_key_file_name, &ark_key_str)) {
    printf("test_sev_platform_certify: Can't read ark key\n");
    return false;
  }
  if (!ark_key.ParseFromString(ark_key_str)) {
    printf("test_sev_platform_certify: Can't parse ark key\n");
    return false;
  }
  ark_key.set_key_name("ARKKey");
  ark_key.set_key_type(Enc_method_rsa_2048_private);
  ark_key.set_key_format("vse-key");
  if (!private_key_to_public_key(ark_key, &ark_pk)) {
    printf("test_sev_platform_certify: Can't convert ark key\n");
    return false;
  }

  key_message ask_key;
  key_message ask_pk;
  string      ask_key_str;
  if (!read_file_into_string(ask_key_file_name, &ask_key_str)) {
    printf("test_sev_platform_certify: Can't read ask  key\n");
    return false;
  }
  if (!ask_key.ParseFromString(ask_key_str)) {
    printf("test_sev_platform_certify: Can't parse ask key\n");
    return false;
  }
  ask_key.set_key_name("ASKKey");
  ask_key.set_key_type(Enc_method_rsa_2048_private);
  ask_key.set_key_format("vse-key");
  if (!private_key_to_public_key(ask_key, &ask_pk)) {
    printf("test_sev_platform_certify: Can't convert ask key\n");
    return false;
  }

  key_message vcek_key;
  key_message vcek_pk;
  string      vcek_key_str;
  if (!read_file_into_string(vcek_key_file_name, &vcek_key_str)) {
    printf("test_sev_platform_certify: Can't read vcek key\n");
    return false;
  }
  if (!vcek_key.ParseFromString(vcek_key_str)) {
    printf("test_sev_platform_certify: Can't parse vcek key\n");
    return false;
  }
  vcek_key.set_key_name("VCEKKey");
  vcek_key.set_key_type(Enc_method_ecc_384_private);
  vcek_key.set_key_format("vse-key");
  if (!private_key_to_public_key(vcek_key, &vcek_pk)) {
    printf("test_sev_platform_certify: Can't convert vcek key\n");
    return false;
  }

  string ark_issuer_desc("platform-provider");
  string ark_issuer_name(ark_key.key_name());
  string ark_subject_desc("platform-provider");
  string ark_subject_name(ark_key.key_name());
  X509 * x_ark = X509_new();
  if (!produce_artifact(ark_key,
                        ark_issuer_name,
                        ark_issuer_desc,
                        ark_pk,
                        ark_subject_name,
                        ark_subject_desc,
                        1ULL,
                        365.26 * 86400,
                        x_ark,
                        true)) {
    printf("test_sev_platform_certify: Can't produce ark artifact\n");
    return false;
  }
  string serialized_ark_cert;
  if (!x509_to_asn1(x_ark, &serialized_ark_cert)) {
    return false;
  }

  string ask_subject_desc("platform-provider");
  string ask_subject_name(ask_key.key_name());
  X509 * x_ask = X509_new();
  if (!produce_artifact(ark_key,
                        ark_issuer_name,
                        ark_issuer_desc,
                        ask_pk,
                        ask_subject_name,
                        ask_subject_desc,
                        2ULL,
                        365.26 * 86400,
                        x_ask,
                        false)) {
    printf("test_sev_platform_certify: Can't produce ask artifact\n");
    return false;
  }
  string serialized_ask_cert;
  if (!x509_to_asn1(x_ask, &serialized_ask_cert)) {
    return false;
  }

  string vcek_issuer_desc("platform-provider");
  string vcek_issuer_name(ask_key.key_name());
  string vcek_subject_desc("platform-provider");
  string vcek_subject_name(vcek_key.key_name());
  X509 * x_vcek = X509_new();
  if (!produce_artifact(ask_key,
                        vcek_issuer_name,
                        vcek_issuer_desc,
                        vcek_pk,
                        vcek_subject_name,
                        vcek_subject_desc,
                        3ULL,
                        365.26 * 86400,
                        x_vcek,
                        false)) {
    printf("test_sev_platform_certify: Can't produce vcek artifact\n");
    return false;
  }
  string serialized_vcek_cert;
  if (!x509_to_asn1(x_vcek, &serialized_vcek_cert)) {
    return false;
  }
#  endif /* 1 */

  // construct evidence package
  string purpose("authentication");
  if (!construct_sev_platform_evidence(purpose,
                                       serialized_ark_cert,
                                       serialized_ask_cert,
                                       serialized_vcek_cert,
                                       vcek_key,
                                       &evp)) {
    printf("construct_sev_platform_evidence failed\n");
    return false;
  }

  if (debug_print) {
    printf("\nPolicy key:\n");
    print_key(policy_pk);
    printf("\nPolicy and evidence:\n");
    for (int i = 0; i < signed_statements.claims_size(); i++) {
      print_signed_claim(signed_statements.claims(i));
      printf("\n");
    }
  }

  if (debug_print) {
    printf("test_platform_certify, evidence descriptor: %s, enclave type: %s, "
           "evidence:\n",
           evidence_descriptor.c_str(),
           enclave_type.c_str());
    for (int i = 0; i < evp.fact_assertion_size(); i++) {
      print_evidence(evp.fact_assertion(i));
      printf("\n");
    }
  }

  // Fix this
  return true;
  if (!validate_evidence_from_policy(evidence_descriptor,
                                     signed_statements,
                                     purpose,
                                     evp,
                                     policy_pk)) {
    printf("validate_evidence failed\n");
    return false;
  }

  return true;
}

// -----------------------------------------------------------------------------

#endif  // SEV_SNP
