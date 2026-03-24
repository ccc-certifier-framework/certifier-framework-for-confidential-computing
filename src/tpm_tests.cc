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
#include "tpm2_support.h"
#include "tpm2_lib.h"
#include "attestation.h"

using namespace certifier::framework;
using namespace certifier::utilities;

// -----------------------------------------------------------------------------

#ifdef TPM

bool test_tpm(bool print_all) {
  const int data_size = 64;
  string    enclave_type("tpm-enclave");
  string    enclave_id("test-enclave");
  byte      data[data_size];

  for (int i = 0; i < data_size; i++)
    data[i] = i;

  string device_name("/dev/tpm1");
  string endorsement_cert_file_name("jlm_cert.crt");
  string seal_hierarchy_file_name("seal_hierarchy.bin");
  string quote_hierarchy_file_name("quote_hierarchy.bin");
  int    num_pcrs = 1;
  byte   pcrs[1];

  // Init
  if (!tpm_Init(device_name,
                endorsement_cert_file_name,
                seal_hierarchy_file_name,
                quote_hierarchy_file_name,
                num_pcrs,
                pcrs)) {
    printf("%s() error, line %d, Can't init TPM\n", __func__, __LINE__);
    return false;
  }

  byte sealed[512];
  int  sealed_size = 512;
  memset(sealed, 0, sealed_size);

  if (!Seal(enclave_type, enclave_id, data_size, data, &sealed_size, sealed)) {
    printf("test_sev, %s, seal error, %d\n", __func__, __LINE__);
    tpm_close();
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
    printf("test_sev, %s, unseal error, %d\n", __func__, __LINE__);
    tpm_close();
    return false;
  }

  if (print_all) {
    printf("\n");
    printf("unsealed size: %d\n", unsealed_size);
    print_bytes(unsealed_size, unsealed);
    printf("\n");
  }

  if (unsealed_size != data_size || memcmp(data, unsealed, data_size) != 0) {
    printf("test_sev, unsealed response wrong, %s, %d\n", __func__, __LINE__);
    tpm_close();
    return false;
  }

  extern TPM2B_PUBLIC g_public_quote_key;
  extern TPM2B_PUBLIC g_public_endorsement_key;

  string      fake_quote_cert;
  key_message policy_key;
  key_message quote_public_key;

  RSA *policy_r = RSA_new();
  if (!generate_new_rsa_key(2048, policy_r)) {
    printf("%s, %d, generate_new_rsa_key error\n", __func__, __LINE__);
    tpm_close();
    return false;
  }
  if (!RSA_to_key(policy_r, &policy_key)) {
    printf("%s, %d, RSA_to_key error\n", __func__, __LINE__);
    tpm_close();
    return false;
  }

  string name("test-quote-key");
  if (!tpm_public_key_to_key(g_public_quote_key, name, &quote_public_key)) {
    printf("Error %s, line: %d, tpm_public_key_to_key error\n",
           __func__,
           __LINE__);
    tpm_close();
    return false;
  }
  RSA_free(policy_r);

  if (print_all) {
    printf("\nQuote key:\n");
    print_key(quote_public_key);
    printf("\n");
  }

  if (!construct_quote_key_cert(policy_key,
                                quote_public_key,
                                &fake_quote_cert)) {
    printf("Error:  %s, line %d, cant construct quote key\n",
           __func__,
           __LINE__);
    tpm_close();
    return false;
  }
  int  size_measurement = 64;
  byte measurement[size_measurement];
  memset(measurement, 0, size_measurement);

  attestation_user_data ud;
  ud.set_enclave_type("tpm-enclave");
  RSA *auth_r = RSA_new();
  if (!generate_new_rsa_key(2048, auth_r)) {
    printf("%s, %d, generate_new_rsa_key error\n", __func__, __LINE__);
    tpm_close();
    return false;
  }
  key_message private_auth_key;
  key_message public_auth_key;
  if (!RSA_to_key(auth_r, &private_auth_key)) {
    printf("%s, %d, RSA_to_key error\n", __func__, __LINE__);
    tpm_close();
    return false;
  }
  private_auth_key.set_key_name("authKey");
  if (!private_key_to_public_key(private_auth_key, &public_auth_key)) {
    printf("%s, %d, private_key_to_public_key error\n", __func__, __LINE__);
    return false;
  }
  RSA_free(auth_r);

  // time
  time_point t;
  time_now(&t);
  string str_now;
  time_to_string(t, &str_now);
  ud.set_time(str_now);

  // key
  ud.mutable_enclave_key()->CopyFrom(public_auth_key);
  ud.mutable_policy_key()->CopyFrom(policy_key);

  int    size_out = 2048;
  byte   out[size_out];
  string serialized_user;
  if (!ud.SerializeToString(&serialized_user)) {
    printf("%s, %d, SerializeToString error\n", __func__, __LINE__);
    tpm_close();
    return false;
  }

#  ifdef DEBUG3
  printf("Serialized to attest (%d): ", (int)serialized_user.size());
  print_bytes((int)serialized_user.size(), (byte_t *)serialized_user.data());
  printf("\n");
#  endif

  if (!Attest(ud.enclave_type(),
              serialized_user.size(),
              (byte *)serialized_user.data(),
              &size_out,
              out)) {
    printf("%s, %d Attest failed\n", __func__, __LINE__);
    tpm_close();
    return false;
  }

#  ifdef DEBUG3
  tpm_close();
  return true;
#  endif

  string serialized_tpm_msg;
  serialized_tpm_msg.assign((char *)out, size_out);

  bool success = tpm_verify_attest(quote_public_key, serialized_tpm_msg);
  if (!success) {
    printf("%s, %d: tpm_verify_attest failed\n", __func__, __LINE__);
    tpm_close();
    return false;
  }

  tpm_attestation_message att;
  if (!att.ParseFromString(serialized_tpm_msg)) {
    printf("%s, %d: Can't parse attestation\n", __func__, __LINE__);
    tpm_close();
    return false;
  }

  if (print_all) {
    printf("\ntmp attestation:\n");
    printf("    what was said: ");
    print_bytes(att.what_was_said().size(), (byte *)att.what_was_said().data());
    printf("\n");
    printf("    The quote    : ");
    print_bytes(att.the_quote().size(), (byte *)att.the_quote().data());
    printf("\n");
    printf("    Signing alg  : %s\n", att.signing_algorithm().c_str());
    printf("    Signature    : ");
    print_bytes(att.signature().size(), (byte *)att.signature().data());
    printf("\n");
  }
  tpm_close();

  return true;
}

#  if 0
bool construct_tpm_platform_evidence(const string      &purpose,
                                     const string      &serialized_ark_cert,
                                     const string      &serialized_ask_cert,
                                     const string      &serialized_vcek_cert,
                                     const key_message &vcek,
                                     evidence_package  *evp) {

  evp->set_prover_type("vse-verifier");
  string enclave_type("tpm-enclave");

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
  RSA        *r = RSA_new();
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
#    if 1
  if (!Attest(enclave_type,
              serialized_ud.size(),
              (byte *)serialized_ud.data(),
              &size_out,
              out)) {
#    endif /* 1 */

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

bool test_tpm_platform_certify(const bool    debug_print,
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
    printf("%s(), error, line: %d, can't parse policy key\n",
           __func__,
           __LINE__);
    return false;
  }
  if (!private_key_to_public_key(policy_key, &policy_pk)) {
    printf("%s(), error, line: %d, can't convert policy key\n",
           __func__,
           __LINE__);
    return false;
  }

#    if 1
  //  For simulated SNP, we don't have real certs so we make some up.

  // Make ark, ask, vcek certs
  key_message ark_key;
  key_message ark_pk;
  string      ark_key_str;
  if (!read_file_into_string(ark_key_file_name, &ark_key_str)) {
    printf("%s(), error, line: %d, can't read ark key\n", __func__, __LINE__);
    return false;
  }
  if (!ark_key.ParseFromString(ark_key_str)) {
    printf("%s(), error, line: %d, can't parse ark key\n", __func__, __LINE__);
    return false;
  }
  ark_key.set_key_name("ARKKey");
  ark_key.set_key_type(Enc_method_rsa_2048_private);
  ark_key.set_key_format("vse-key");
  if (!private_key_to_public_key(ark_key, &ark_pk)) {
    printf("%s(), error, line: %d, can't convert ark key\n",
           __func__,
           __LINE__);
    return false;
  }

  key_message ask_key;
  key_message ask_pk;
  string      ask_key_str;
  if (!read_file_into_string(ask_key_file_name, &ask_key_str)) {
    printf("%s(), error, line: %d, can't read ask  key\n", __func__, __LINE__);
    return false;
  }
  if (!ask_key.ParseFromString(ask_key_str)) {
    printf("%s(), error, line: %d, can't parse ask key\n", __func__, __LINE__);
    return false;
  }
  ask_key.set_key_name("ASKKey");
  ask_key.set_key_type(Enc_method_rsa_2048_private);
  ask_key.set_key_format("vse-key");
  if (!private_key_to_public_key(ask_key, &ask_pk)) {
    printf("%s(), error, line: %d, can't convert ask key\n",
           __func__,
           __LINE__);
    return false;
  }

  key_message vcek_key;
  key_message vcek_pk;
  string      vcek_key_str;
  if (!read_file_into_string(vcek_key_file_name, &vcek_key_str)) {
    printf("%s(), error, line: %d, can't read vcek key\n", __func__, __LINE__);
    return false;
  }
  if (!vcek_key.ParseFromString(vcek_key_str)) {
    printf("%s(), error, line: %d, can't parse vcek key\n", __func__, __LINE__);
    return false;
  }
  vcek_key.set_key_name("VCEKKey");
  vcek_key.set_key_type(Enc_method_ecc_384_private);
  vcek_key.set_key_format("vse-key");
  if (!private_key_to_public_key(vcek_key, &vcek_pk)) {
    printf("%s(), error, line: %d, can't convert vcek key\n",
           __func__,
           __LINE__);
    return false;
  }

  string ark_issuer_desc("platform-provider");
  string ark_issuer_name(ark_key.key_name());
  string ark_subject_desc("platform-provider");
  string ark_subject_name(ark_key.key_name());
  X509  *x_ark = X509_new();
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
    printf("%s(), error, line: %d, can't produce ark artifact\n",
           __func__,
           __LINE__);
    return false;
  }
  string serialized_ark_cert;
  if (!x509_to_asn1(x_ark, &serialized_ark_cert)) {
    return false;
  }

  string ask_subject_desc("platform-provider");
  string ask_subject_name(ask_key.key_name());
  X509  *x_ask = X509_new();
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
    printf("%s(), error, line: %d, can't produce ask artifact\n",
           __func__,
           __LINE__);
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
  X509  *x_vcek = X509_new();
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
    printf("%s(), error, line: %d, can't produce vcek artifact\n",
           __func__,
           __LINE__);
    return false;
  }
  string serialized_vcek_cert;
  if (!x509_to_asn1(x_vcek, &serialized_vcek_cert)) {
    return false;
  }
#    endif /* 1 */

  // construct evidence package
  string purpose("authentication");
  if (!construct_sev_platform_evidence(purpose,
                                       serialized_ark_cert,
                                       serialized_ask_cert,
                                       serialized_vcek_cert,
                                       vcek_key,
                                       &evp)) {
    printf("%s(), error, line: %d, construct_sev_platform_evidence failed\n",
           __func__,
           __LINE__);
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
    printf("%s(), line: %d, , evidence descriptor: %s, enclave type: %s, "
           "evidence:\n",
           __func__,
           __LINE__,
           evidence_descriptor.c_str(),
           enclave_type.c_str());
    for (int i = 0; i < evp.fact_assertion_size(); i++) {
      print_evidence(evp.fact_assertion(i));
      printf("\n");
    }
  }

  // FIX!
  return true;
  if (!validate_evidence_from_policy(evidence_descriptor,
                                     signed_statements,
                                     purpose,
                                     evp,
                                     policy_pk)) {
    printf("%s(), error, line: %d, validate_evidence failed\n",
           __func__,
           __LINE__);
    return false;
  }

  return true;
}
#  endif

#endif  // TPM

// -----------------------------------------------------------------------------
