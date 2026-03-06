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
                                      const string &file);
bool recover_sealing_secret(local_tpm    &tpm,
                            int           num_pcrs,
                            byte_t       *pcrs,
                            const string &file_name,
                            string       *seal_secret);
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
bool do_quote(local_tpm  &tpm,
              TPM_HANDLE &srk_handle,
              int         num_pcrs,
              byte_t     *pcrs,
              TPM_HANDLE &quote_handle,
              string     &to_quote,
              string     *quoted,
              string     *signature);
bool tpm_init(const string &device_name,
              const string &endorsement_cert_file_name,
              const string &seal_hierarchy_file_name,
              const string &quote_hierarchy_file_name,
              int           num_pcrs,
              byte_t       *pcrs);
bool tpm_close();

bool tpm_seal(string &unsealed, string *sealed);
bool tpm_unseal(string &sealed, string *unsealed);
bool local_tpm_attest(TPM_HANDLE &quote_handle,
                      TPM_ALG_ID  hash_alg,
                      TPM_HANDLE &srk_handle,
                      int         num_pcrs,
                      byte_t     *pcrs,
                      string     &to_quote,
                      string     *quoted,
                      string     *signature);
bool tpm_attest(string &to_quote, string *quoted, string *signature);
bool tpm_verify_attest(string &cert,
                       string &to_quote,
                       string &quoted,
                       string &signature);
bool tpm_verify_attest(key_message  &quote_key,
                       string       &to_quote,
                       string       &quoted,
                       const string &hash_name,
                       const string &sig_scheme,
                       string       &signature);

bool make_credential(const TPM2B_PUBLIC &quoting_key,
                     const string       &cert_in,
                     string             *cred_blob,
                     string             *encrypted_secret);

bool credential_test(local_tpm          &tpm,
                     TPML_PCR_SELECTION &pcrSelect,
                     TPM_HANDLE         &srk_handle,
                     TPM_HANDLE         &quote_handle);

// ---------------------------------------------------------------
#endif
