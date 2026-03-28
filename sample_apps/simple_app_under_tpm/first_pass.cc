//  Copyright (c) 2026, John L Manferdelli.  All rights
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
#include "simulated_enclave.h"
#include "tpm2_support.h"

using namespace certifier::framework;
using namespace certifier::utilities;

#define DEBUG

// -----------------------------------------------------------------------

bool first_pass(const string &policy_key_file_name,
                const string &tpm_device,
                const string &seal_hierarchy_file_name,
                const string &quote_hierarchy_file_name,
                int           num_pcrs,
                byte         *pcrs) {

  string endorsement_cert_file_name;
  if (!tpm_Init(tpm_device,
                endorsement_cert_file_name,
                seal_hierarchy_file_name,
                quote_hierarchy_file_name,
                num_pcrs,
                pcrs)) {
    printf("%s() error, line %d, can'r tpm_Init\n", __func__, __LINE__);
    return false;
  }

  // get policy key
  key_message policy_key;
  key_message policy_pk;
  string      policy_key_str;
  if (!read_file_into_string(policy_key_file_name, &policy_key_str)) {
    printf("%s() error, line: %d, Can't read policy key %s\n",
           __func__,
           __LINE__,
           policy_key_file_name.c_str());
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

  // get quote key
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

#ifdef DEBUG
  printf("quote cert: ");
  X509_print_fp(stdout, x_quote);
  printf("\n");
#endif

  X509_free(x_quote);

  string quote_file_name("quote_cert.crt");
  if (!write_file_from_string(quote_file_name, serialized_quote_cert)) {
    printf("%s(), error, line: %d, can't write quote cert\n",
           __func__,
           __LINE__);
    tpm_close();
    return false;
  }

  // get measurement
  // save it
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
  private_auth_key.set_key_name("enclave-key");
  if (!private_key_to_public_key(private_auth_key, &public_auth_key)) {
    printf("%s, %d, private_key_to_public_key error\n", __func__, __LINE__);
    return false;
  }
  RSA_free(auth_r);

  printf("tpm_test: generated enclave key:\n");
  print_key(public_auth_key);
  printf("\n");

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

  if (!Attest(ud.enclave_type(),
              serialized_user.size(),
              (byte *)serialized_user.data(),
              &size_out,
              out)) {
    printf("%s, %d Attest failed\n", __func__, __LINE__);
    tpm_close();
    return false;
  }

  string serialized_tpm_msg;
  serialized_tpm_msg.assign((char *)out, size_out);

  tpm_attestation_message att;
  if (!att.ParseFromString(serialized_tpm_msg)) {
    printf("%s, %d, can't parse attestation\n", __func__, __LINE__);
    tpm_close();
    return false;
  }

  // extract measurement
  string             extra_data;
  uint32_t           magic;
  uint16_t           type;
  string             signer;
  TPML_PCR_SELECTION pcrSelect;
  string             pcr_digest;
  int                new_num_pcrs = 10;
  byte_t             new_pcrs[num_pcrs];

  if (!decode_quoted((int)att.the_quote().size(),
                     (byte_t *)att.the_quote().data(),
                     &magic,
                     &type,
                     &signer,
                     &extra_data,
                     &pcrSelect,
                     &pcr_digest)) {
    printf("%s, %d, decode_quoted failed\n", __func__, __LINE__);
    tpm_close();
    return false;
  }

  if (!get_pcr_from_select(&pcrSelect, &new_num_pcrs, new_pcrs)) {
    printf("%s, %d, get_pcr_from_select failed\n", __func__, __LINE__);
    tpm_close();
    return false;
  }

  measurement_value mv;
  string            conf;
  conf.assign((char *)new_pcrs, new_num_pcrs);
  mv.set_registers(conf);
  mv.set_the_measurement(pcr_digest);
  string mv_str;
  if (!mv.SerializeToString(&mv_str)) {
    printf("%s(), error, line: %d, can't serialize measurement\n",
           __func__,
           __LINE__);
    tpm_close();
    return false;
  }

#ifdef DEBUG
  printf("PCR's: ");
  for (int i = 0; i < num_pcrs; i++)
    printf("%d ", pcrs[i]);
  printf("\n");
  printf("Digest: ");
  print_bytes(mv.the_measurement().size(),
              (byte_t *)mv.the_measurement().data());
  printf("\n");
#endif

  string measurement_file_name("measurement");
  if (!write_file_from_string(measurement_file_name, mv_str)) {
    printf("%s(), error, line: %d, can't write measurement\n",
           __func__,
           __LINE__);
    tpm_close();
    return false;
  }

  tpm_close();
  return true;
}

// -----------------------------------------------------------------------
