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

  int  num_pcrs = 1;
  byte pcrs[1] = {7};

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
    printf("test_tpm, %s, seal error, %d\n", __func__, __LINE__);
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
    printf("test_tpm, %s, unseal error, %d\n", __func__, __LINE__);
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
    printf("test_tpm, unsealed response wrong, %s, %d\n", __func__, __LINE__);
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

// Final evidence should be:
//    policy_key says quote-key is-trusted-for-attestation
//    policy_key says measurement is-trusted
//    quote-key says authKey speaks-for measurement
bool construct_tpm_platform_evidence(const string      &purpose,
                                     const key_message &policy_key,
                                     const string      &measurement_str,
                                     const string      &serialized_quote_cert,
                                     evidence_package  *evp) {

  evp->set_prover_type("vse-verifier");
  string enclave_type("tpm-enclave");

  // policy-key says quote-key is-trusted-for-atteststion
  evidence *ev = evp->add_fact_assertion();
  if (ev == nullptr) {
    printf("construct_tpm_platform_evidence: Can't add evidence\n");
    return false;
  }
  ev->set_evidence_type("cert");
  ev->set_serialized_evidence(serialized_quote_cert);
  ev = evp->add_fact_assertion();
  if (ev == nullptr) {
    printf("construct_tpm_platform_evidence: Can't add evidence\n");
    return false;
  }

  // Auth key
  key_message auth_key;
  RSA        *r = RSA_new();
  if (!generate_new_rsa_key(2048, r)) {
    printf("construct_tpm_platform_evidence: Can't generate rsa key\n");
    return false;
  }
  if (!RSA_to_key(r, &auth_key)) {
    printf("construct_tpm_platform_evidence: Can't convert rsa key to key\n");
    RSA_free(r);
    return false;
  }
  RSA_free(r);

  attestation_user_data ud;
  if (purpose == "authentication") {
    if (!make_attestation_user_data(enclave_type, auth_key, &ud)) {
      printf("construct_tpm_platform_evidence: Can't make user data (1)\n");
      return false;
    }
  } else if (purpose == "attestation") {
    if (!make_attestation_user_data(enclave_type, auth_key, &ud)) {
      printf("construct_tpm_platform_evidence: Can't make user data (1)\n");
      return false;
    }
  } else {
    printf("construct_tpm_platform_evidence: neither attestation or "
           "authorization\n");
    return false;
  }
  string serialized_ud;
  if (!ud.SerializeToString(&serialized_ud)) {
    printf("construct_tpm_platform_evidence: Can't serialize user data\n");
    return false;
  }

  // quote-key says auth-key speaks-for measurement
  int  size_out = 16000;
  byte out[size_out];
  if (!Attest(enclave_type,
              serialized_ud.size(),
              (byte *)serialized_ud.data(),
              &size_out,
              out)) {

    printf("construct_tpm_platform_evidence: Attest failed\n");
    return false;
  }
  string the_attestation_str;
  the_attestation_str.assign((char *)out, size_out);

  ev = evp->add_fact_assertion();
  if (ev == nullptr) {
    printf("construct_tpm_platform_evidence: Can't add to attest platform "
           "evidence\n");
    return false;
  }
  ev->set_evidence_type("tpm-attestation");
  ev->set_serialized_evidence(the_attestation_str);

  return true;
}

bool test_tpm_platform_certify(const bool    debug_print,
                               const string &policy_file_name,
                               const string &policy_key_file,
                               const string &device_name,
                               const string &endorsement_cert_file_name,
                               const string &seal_hierarchy_file_name,
                               const string &quote_hierarchy_file_name,
                               int           num_pcrs,
                               byte_t       *pcrs) {


  string           enclave_type("tpm-enclave");
  string           evidence_descriptor("tpm-evidence");
  string           enclave_id("test-enclave");
  evidence_package evp;

  if (!tpm_Init(device_name,
                endorsement_cert_file_name,
                seal_hierarchy_file_name,
                quote_hierarchy_file_name,
                num_pcrs,
                pcrs)) {
    printf("%s() error, line: %d, can't tpm_Init\n", __func__, __LINE__);
    return false;
  }

  // get policy
  signed_claim_sequence signed_statements;
  if (!read_signed_vse_statements(policy_file_name, &signed_statements)) {
    printf("%s() error, line: %d, Can't read policy %s\n",
           __func__,
           __LINE__,
           policy_file_name.c_str());
    tpm_close();
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
    tpm_close();
    return false;
  }
  if (!policy_key.ParseFromString(policy_key_str)) {
    printf("%s(), error, line: %d, can't parse policy key\n",
           __func__,
           __LINE__);
    tpm_close();
    return false;
  }
  if (!private_key_to_public_key(policy_key, &policy_pk)) {
    printf("%s(), error, line: %d, can't convert policy key\n",
           __func__,
           __LINE__);
    tpm_close();
    return false;
  }

  // Make quote cert
  key_message quote_key;
  string      quote_key_str;

  // make quote key message
  extern TPM2B_PUBLIC g_public_quote_key;
  string              name("quote-key");
  if (!tpm_public_key_to_key(g_public_quote_key, name, &quote_key)) {
    printf("%s(), error, line: %d, can't translate quote key\n",
           __func__,
           __LINE__);
    tpm_close();
    return false;
  }

  if (debug_print) {
    printf("\nPolicy key:\n");
    print_key(policy_key);
    printf("\n");
    printf("\nPolicy key:\n");
    print_key(policy_pk);
    printf("\n");
    printf("\nQuote key :\n");
    print_key(quote_key);
    printf("\n");
  }

  string quote_issuer_desc("policy-key");
  string quote_issuer_name(policy_key.key_name());
  string quote_subject_desc("quote-key");
  string quote_subject_name(quote_key.key_name());
  X509  *x_quote = X509_new();
  if (!produce_artifact(policy_key,
                        quote_issuer_name,
                        quote_issuer_desc,
                        quote_key,
                        quote_subject_name,
                        quote_subject_desc,
                        1ULL,
                        365.26 * 86400,
                        x_quote,
                        true)) {
    printf("%s(), error, line: %d, can't produce quote artifact\n",
           __func__,
           __LINE__);
    tpm_close();
    return false;
  }

  string serialized_quote_cert;
  if (!x509_to_asn1(x_quote, &serialized_quote_cert)) {
    printf("%s(), error, line: %d, can't translate quote cert\n",
           __func__,
           __LINE__);
    tpm_close();
    return false;
  }

  if (debug_print) {
    printf("\nQuote cert:\n");
    X509_print_fp(stdout, x_quote);
    printf("\n");
  }

  // make measurement statement
  int  size_measurement = 32;
  byte measurement[size_measurement] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
      0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
      0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
  };
  string measurement_str;
  measurement_str.assign((char *)measurement, size_measurement);

  X509_free(x_quote);

  // construct evidence package
  string purpose("authentication");
  if (!construct_tpm_platform_evidence(purpose,
                                       policy_pk,
                                       measurement_str,
                                       serialized_quote_cert,
                                       &evp)) {
    printf("%s(), error, line: %d, construct_tpm_platform_evidence failed\n",
           __func__,
           __LINE__);
    tpm_close();
    return false;
  }

  if (debug_print) {
    printf("\nPolicy and evidence:\n");
    for (int i = 0; i < signed_statements.claims_size(); i++) {
      print_signed_claim(signed_statements.claims(i));
      printf("\n");
    }
  }

  if (debug_print) {
    printf("tpm evidence package, evidence descriptor: %s, enclave type: %s, "
           "evidence:\n\n",
           evidence_descriptor.c_str(),
           enclave_type.c_str());
    for (int i = 0; i < evp.fact_assertion_size(); i++) {
      print_evidence(evp.fact_assertion(i));
      printf("\n");
    }
  }

  proved_statements are_proved;
  if (!init_axiom(policy_pk, &are_proved)) {
    printf("%s(), error, line: %d,  init_axiom failed\n", __func__, __LINE__);
  }

  // measurement is trusted
  entity_message m_ent;
  if (!make_measurement_entity(measurement_str, &m_ent)) {
    printf("init_proved_statements: Can't make measurement entity\n");
    return false;
  }

#  if 0
  vse_clause c1;
  if (!make_simple_vse_clause(auth_ent, speaks_verb, m_ent, &c1)) {
    printf("init_proved_statements: Can't make simple vse clause\n");
    return false;
  }

   entity_message auth_ent;
   if (!make_key_entity(ud.enclave_key(), &auth_ent)) {
     printf("init_proved_statements: Can't make key entity\n");
      return false;
   }
         entity_message auth_ent;
      if (!make_key_entity(ud.enclave_key(), &auth_ent)) {
        printf("init_proved_statements: Can't make key entity\n");
        return false;
      }

      // vcekKey says authKey speaks-for measurement
      entity_message vcek_ent;
      if (!make_key_entity(vcek_key, &vcek_ent)) {
        printf("init_proved_statements: Can't make key entity\n");
        return false;
      }
      vse_clause *cl = already_proved->add_proved();
      if (!make_indirect_vse_clause(vcek_ent, says_verb, c1, cl)) {
        printf("init_proved_statements: Can't make indirect vse clause\n");
        return false;
      }
#  endif

#  if 0
  if (debug_print) {
  printf("Proved:");
  print_vse_clause(to_prove);
  printf("\n");
  printf("final proved statements:\n");
  for (int i = 0; i < already_proved.proved_size(); i++) {
    print_vse_clause(already_proved.proved(i));
    printf("\n");
  }
  printf("\n");
#  endif

  // construct proof
#  if 0
  bool construct_proof_from_tpm_evidence(key_message       &policy_pk,
                                       const string      &purpose,
                                       proved_statements *already_proved,
                                       vse_clause        *to_prove,
                                       proof             *pf)

  if (debug_print) {
  printf("to prove : ");
  print_vse_clause(to_prove);
  printf("\n\n");
  printf("proposed proof:\n");
  print_proof(pf);
  printf("\n");
#  endif

  // FIX!
  tpm_close();
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

  tpm_close();
  return true;
}

bool test_tpm_proof(bool print_all) {

  string policy_file_name("policy.bin");
  string policy_key_file("policy_key_file.dom0");
  string device_name("/dev/tpm1");
  string endorsement_cert_file_name("jlm_cert.crt");
  string seal_hierarchy_file_name("seal_hierarchy.bin");
  string quote_hierarchy_file_name("quote_hierarchy.bin");
  int    num_pcrs = 1;
  byte_t pcrs[num_pcrs] = {7};

  if (!test_tpm_platform_certify(true,
                                 policy_file_name,
                                 policy_key_file,
                                 device_name,
                                 endorsement_cert_file_name,
                                 seal_hierarchy_file_name,
                                 quote_hierarchy_file_name,
                                 num_pcrs,
                                 pcrs)) {
    printf("%s(), error, line: %d, test_tpm_platform_certify failed\n",
           __func__,
           __LINE__);
    return false;
  }
  return true;
}

#else

bool test_tpm(bool print_all) {
  return true;
}

bool test_tpm_proof(bool print_all) {
  return true;
}

#endif  // TPM

// -----------------------------------------------------------------------------
