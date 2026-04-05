//
// Copyright 2026, John L Manferdelli, All Rights Reserved.
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
// File: tpm2_support.h

#ifndef _TPM2_SUPPORT_H__
#define _TPM2_SUPPORT_H__
#include <tpm2_lib.h>
#include "certifier.h"
#include "support.h"
#include "tpm2_lib.h"
#include "certifier.pb.h"
#include <string>
using std::string;
using namespace certifier::framework;
using namespace certifier::utilities;

bool print_pcrs(local_tpm &tpm, int num_pcrs, byte *pcrs);
bool extend_pcrs(local_tpm &tpm, int pcr_num);

bool create_seal_session(local_tpm          &tpm,
                         TPML_PCR_SELECTION &pcrSelect,
                         TPM_HANDLE         *session_handle);
bool create_seal_hierarchy_and_secret(local_tpm    &tpm,
                                      int           num_pcrs,
                                      byte_t       *pcrs,
                                      const string &seal_file);
bool recover_sealing_secret(local_tpm    &tpm,
                            int           num_pcrs,
                            byte_t       *pcrs,
                            const string &file_name,
                            string       *seal_secret);
bool recover_and_load_quote_hierarchy(local_tpm    &tpm,
                                      int           num_pcrs,
                                      byte_t       *pcrs,
                                      const string &file_name,
                                      TPM_HANDLE   *srk_handle,
                                      TPM_HANDLE   *quote_handle);
bool create_quote_session(local_tpm          &tpm,
                          TPML_PCR_SELECTION &pcrSelect,
                          string             *nonce,
                          TPM_HANDLE         *session_handle);
bool create_quote_hierarchy(local_tpm    &tpm,
                            int           num_pcrs,
                            byte_t       *pcrs,
                            const string &file_name);
bool create_endorsement_session(local_tpm  &tpm,
                                string     &authString,
                                string     *nonce,
                                TPM_HANDLE *session_handle);

bool get_endorsement_key(local_tpm  &tpm,
                         string     &authString,
                         string     &policyString,
                         TPM_HANDLE *ek_handle);
bool save_context(local_tpm &tpm, TPM_HANDLE &handle, string *out);
bool load_context(local_tpm &tpm, TPM_HANDLE &handle, string &in);
bool nv_increment_counter(local_tpm &tpm, int slot);
bool read_nv_slot(local_tpm &tpm, int slot, string *out);
bool write_nv_slot(local_tpm &tpm, int slot, string &in);
bool read_nv_handle(local_tpm &tpm,
                    TPM_HANDLE handle,
                    string    &authString,
                    int        size,
                    string    *out);
bool write_nv_handle(local_tpm &tpm,
                     TPM_HANDLE handle,
                     string    &authString,
                     string    &in);

// ---------------------------------------------------------------

bool init_quote_cert_from_file(const string &quote_cert_file_name);

bool init_tpm(const string &device_name);
bool close_tpm();

bool get_srk_auth(string *srkAuth);
bool get_quote_auth(string *quoteAuth);
bool get_endorsement_auth(string* endorsementAuth);

bool create_pcr_policy(local_tpm    &tpm,
                       int           num_pcrs,
                       byte_t       *pcrs,
                       TPM2B_DIGEST *policy_out);
bool get_endorsement_cert(local_tpm &tpm, string *out);
bool get_endorsement_cert(const string &file_name, string *out);
bool recover_endorsement_cert(const string &file_name);
bool save_endorsement_cert(const string &file_name);
bool create_quote_hierarchy(local_tpm    &tpm,
                            int           num_pcrs,
                            byte_t       *pcrs,
                            const string &file_name);
bool recover_and_load_quote_hierarchy(local_tpm    &tpm,
                                      int           num_pcrs,
                                      byte_t       *pcrs,
                                      const string &file_name,
                                      TPM_HANDLE   *srk_handle,
                                      TPM_HANDLE   *quote_handle);

void print_mask(int n, byte_t *m);
bool decode_quoted(int                 size_buf,
                   byte_t             *buf,
                   uint32_t           *magic,
                   uint16_t           *type,
                   string             *signer,
                   string             *extra_data,
                   TPML_PCR_SELECTION *pcrSelect,
                   string             *pcr_digest);
void pcrs_from_select(int size, byte_t *buf, int *index, byte_t *pcrs);
bool get_pcr_from_select(TPML_PCR_SELECTION *p, int *num_pcrs, byte_t *pcrs);
bool get_data_from_attest(int       size,
                          byte_t   *buf,
                          uint32_t *magic,
                          uint16_t *type,
                          string   *signer,
                          string   *extra_data,
                          int      *num_pcrs,
                          byte_t   *pcrs,
                          string   *digest);

bool do_quote(local_tpm    &tpm,
              TPM_HANDLE   &srk_handle,
              int           num_pcrs,
              byte_t       *pcrs,
              TPM_HANDLE   &quote_handle,
              const string &to_quote,
              string       *quoted,
              string       *signature);
bool tpm_Init(const string &device_name,
              const string &endorsement_cert_file_name,
              const string &endorsement_cert_chain_file_name,
              const string &seal_hierarchy_file_name,
              const string &quote_hierarchy_file_name,
              int           num_pcrs,
              byte_t       *pcrs);
bool tpm_close();

bool tpm_Seal(string &unsealed, string *sealed);
bool tpm_Seal(int in_size, byte_t *in, int *size_out, byte_t *out);
bool tpm_Unseal(string &sealed, string *unsealed);
bool tpm_Unseal(int in_size, byte_t *in, int *size_out, byte_t *out);
bool local_tpm_attest(TPM_HANDLE   &quote_handle,
                      TPM_ALG_ID    hash_alg,
                      TPM_HANDLE   &srk_handle,
                      int           num_pcrs,
                      byte_t       *pcrs,
                      const string &to_quote,
                      string       *quoted,
                      string       *signature);
bool tpm_Attest(const string &to_quote,
                string       *quoted,
                string       *alg,
                string       *signature);
bool tpm_Attest(int   what_to_say_size,
                byte *what_to_say,
                int  *size_out,
                byte *out);
bool tpm_Verify(const string &cert,
                const string &to_quote,
                const string &quoted,
                const string &signature);
bool tpm_Verify(const key_message &quote_key,
                const string      &to_quote,
                const string      &quoted,
                const string      &hash_name,
                const string      &sig_scheme,
                const string      &signature);
bool tpm_verify_attest(const key_message &quote_key,
                       const string      &serialized_tpm_msg);
bool tpm_verify_attest(const string &quote_cert,
                       const string &serialized_tpm_msg);
bool tpm_verify_attest_with_measurement(int     cert_size,
                                        byte_t *cert,
                                        int     tpm_msg_size,
                                        byte_t *tpm_msg,
                                        int    *m_size,
                                        byte_t *m,
                                        int    *pcr_size,
                                        byte_t *pcrs);
bool make_credential(const string &quote_hash_alg,
                     string       &quote_key_name,
                     const string &endorsement_cert_in,
                     string       &credential,
                     string       *cred_blob,
                     string       *encrypted_secret);

bool tpm_public_key_to_key(const TPM2B_PUBLIC &in_public,
                           const string       &name,
                           key_message        *out_key);
bool make_credential_from_certifier(const char *quote_hash_alg,
                                    int         quote_key_name_size,
                                    byte_t     *quote_key_name_buf,
                                    int         endoresment_cert_size,
                                    byte_t     *endoresment_cert_buf,
                                    int         credential_size,
                                    byte_t     *credential_buf,
                                    int        *cred_blob_size,
                                    byte_t     *cred_blob_buf,
                                    int        *encrypted_secret_size,
                                    byte_t     *encrypted_secret_buf);

bool construct_activate_request(const string      &endorsement_cert,
                                const string      &endorsement_cert_chain,
                                const key_message &quote_key,
                                const string      &quote_key_name,
                                const string      &quote_hash_alg,
                                string            *serialized_request);

bool process_activate_response(const string &serialized_response,
                               string       *quote_cert);

// ---------------------------------------------------------------
#endif
