#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl_helpers.h>

#include <tpm20.h>
#include <tpm2_lib.h>
#include <gflags/gflags.h>

//
// Copyright 2015 Google Corporation, All Rights Reserved.
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
//
// Portions of this code were derived TPM2.0-TSS published
// by Intel under the license set forth in intel_license.txt
// and downloaded on or about August 6, 2015.
// Portions of this code were derived tboot published
// by Intel under the license set forth in intel_license.txt
// and downloaded on or about August 6, 2015.
// Portions of this code were derived from the crypto utility
// published by John Manferdelli under the Apache 2.0 license.
// See github.com/jlmucb/crypto.
// File: ClientGetProgramKeyCert.cc


//  This program decrypts the program  key certificate using ActivateCredential
//  and stores the resulting decrypted cert.

// Calling sequence: ClientGetProgramKeyCert.exe
//    --slot_primary=slot-number
//    --slot_seal= slot-number
//    --program_key_response_file=input-file-name
//    --program_key_cert_file=output-file-name


using std::string;


#define CALLING_SEQUENCE "ClientGetProgramKeyCert.exe " \
"--slot_primary=slot-number " \
"--slot_seal= slot-number " \
"--slot_quote= slot-number " \
"--program_key_response_file=input-file-name " \
"--program_key_cert_file=output-file-name\n"

void PrintOptions() {
  printf("Calling sequence: %s", CALLING_SEQUENCE);
}

DEFINE_string(program_key_response_file, "", "input-file-name");
DEFINE_int32(slot_primary, 1, "slot-number");
DEFINE_int32(slot_seal, 2, "slot-number");
DEFINE_int32(slot_quote, 3, "slot-number");
DEFINE_string(program_key_type, "RSA", "alg name");
DEFINE_string(program_key_cert_file, "", "output-file-name");
DEFINE_string(hash_alg, "sha1", "hash algorithm");

#ifndef GFLAGS_NS
#define GFLAGS_NS google
#endif

#define MAX_SIZE_PARAMS 4096
#define DEBUG

int main(int an, char** av) {
  LocalTpm tpm;
  int ret_val = 0;

  printf("\nClientGetProgramKeyCert\n\n");

  GFLAGS_NS::ParseCommandLineFlags(&an, &av, true);
  if (!tpm.OpenTpm("/dev/tpm0")) {
    printf("Can't open tpm\n");
    return 1;
  }

  OpenSSL_add_all_algorithms();

  TPM_HANDLE nv_handle = 0;

  string authString("01020304");
  string parentAuth("01020304");
  string emptyAuth;

  TPML_PCR_SELECTION pcrSelect;

  TPM_HANDLE ekHandle = 0;
  TPM_HANDLE root_handle = 0;
  TPM_HANDLE seal_handle = 0;
  TPM_HANDLE quote_handle = 0;

  TPM2B_ID_OBJECT credentialBlob;
  TPM2B_ENCRYPTED_SECRET unmarshaled_secret;

  TPM2B_DIGEST recovered_credential;

  TPMA_OBJECT primary_flags;
  TPM2B_PUBLIC ek_pub_out;

  int current_size = 0;
  uint16_t context_data_size = 924;
  byte context_save_area[MAX_SIZE_PARAMS];

  string cert_key_seed;
  string label;
  string contextV;
  int size_derived_keys;
  byte derived_keys[128];
  int encrypted_cert_hmac_size;
  byte encrypted_cert_hmac[256];
  HMAC_CTX hctx;

  int size_response = MAX_SIZE_PARAMS;
  byte response_buf[MAX_SIZE_PARAMS];
  program_cert_response_message response;
  int size_cert_out = MAX_SIZE_PARAMS;
  byte cert_out_buf[MAX_SIZE_PARAMS];

  TPM_ALG_ID hash_alg_id;
  if (FLAGS_hash_alg == "sha1") {
    hash_alg_id = TPM_ALG_SHA1;
  } else if (FLAGS_hash_alg == "sha256") {
    hash_alg_id = TPM_ALG_SHA256;
  } else {
    printf("Unknown hash algorithm\n");
    return 1;
  }

  string input;
  string output;

  if (FLAGS_program_key_type != "RSA") {
    printf("Only RSA supported\n");
    ret_val = 1;
    goto done;
  }
  if (FLAGS_program_key_response_file == "") {
    printf("No key name\n");
    ret_val = 1;
    goto done;
  }
  if (FLAGS_program_key_cert_file == "") {
    printf("No key name\n");
    ret_val = 1;
    goto done;
  }

  // Create endorsement key
  *(uint32_t*)(&primary_flags) = 0;

  primary_flags.fixedTPM = 1;
  primary_flags.fixedParent = 1;
  primary_flags.sensitiveDataOrigin = 1;
  primary_flags.userWithAuth = 1;
  primary_flags.decrypt = 1;
  primary_flags.restricted = 1;

  if (Tpm2_CreatePrimary(tpm, TPM_RH_ENDORSEMENT, emptyAuth, pcrSelect,
                         TPM_ALG_RSA, hash_alg_id, primary_flags,
                         TPM_ALG_AES, 128, TPM_ALG_CFB, TPM_ALG_NULL,
                         2048, 0x010001, &ekHandle, &ek_pub_out)) {
    printf("CreatePrimary succeeded parent: %08x\n", ekHandle);
  } else {
    printf("CreatePrimary failed\n");
    ret_val = 1;
    goto done;
  }

  // restore context
  // TODO(jlm): should get pcr list from parameters
  InitSinglePcrSelection(7, hash_alg_id, &pcrSelect);

  // root handle
  memset(context_save_area, 0, MAX_SIZE_PARAMS);
  nv_handle = GetNvHandle(FLAGS_slot_primary);
  if (!Tpm2_ReadNv(tpm, nv_handle, authString, &context_data_size,
                   context_save_area)) {
    printf("Root ReadNv failed\n");
    ret_val = 1;
    goto done;
  }

#ifdef DEBUG_EXTRA
  printf("\ncontext_save_area: ");
  PrintBytes(context_data_size, context_save_area);
  printf("\n\n");
#endif

  if (!Tpm2_LoadContext(tpm, context_data_size, context_save_area,
                        &root_handle)) {
    printf("Root LoadContext failed\n");
    ret_val = 1;
    goto done;
  }

  // quote handle
  memset(context_save_area, 0, MAX_SIZE_PARAMS);
  nv_handle = GetNvHandle(FLAGS_slot_quote);
  if (!Tpm2_ReadNv(tpm, nv_handle, authString, &context_data_size,
                   context_save_area)) {
    printf("Quote ReadNv failed\n");
    ret_val = 1;
    goto done;
  }
  if (!Tpm2_LoadContext(tpm, context_data_size, context_save_area,
                        &quote_handle)) {
    printf("Quote LoadContext failed\n");
    ret_val = 1;
    goto done;
  }

#ifdef DEBUG_EXTRA
  printf("\ncontext_save_area: ");
  PrintBytes(context_data_size, context_save_area);
  printf("\n\n");
#endif

  // Get response
  if (!ReadFileIntoBlock(FLAGS_program_key_response_file, &size_response,
                         response_buf)) {
    printf("Can't read response\n");
    ret_val = 1;
    goto done;
  }
  input.assign((const char*)response_buf, size_response);
  if (!response.ParseFromString(input)) {
    printf("Can't parse response\n");
    ret_val = 1;
    goto done;
  }

#ifdef DEBUG
  printf("\nintegrity (%d): ", (int)response.integrityhmac().size());
  PrintBytes(response.integrityhmac().size(),
             (byte*)response.integrityhmac().data());
  printf("\n");
  printf("encidentity(%d): ", (int)response.encidentity().size());
  PrintBytes(response.encidentity().size(),
             (byte*)response.encidentity().data());
  printf("\n");
  printf("secret(%d): ", (int)response.secret().size());
  PrintBytes(response.secret().size(),
             (byte*)response.secret().data());
  printf("\n");
#endif

  // Fill credential blob and secret
  credentialBlob.size = (int)response.integrityhmac().size() + (int)response.encidentity().size();
  current_size = 0;
  memcpy(&credentialBlob.credential[current_size],
         (byte*) response.integrityhmac().data(),
         response.integrityhmac().size());
  current_size += response.integrityhmac().size();
  memcpy(&credentialBlob.credential[current_size],
         (byte*) response.encidentity().data(),
         response.encidentity().size());
  current_size += response.encidentity().size();

  // secret 
  unmarshaled_secret.size = response.secret().size();
  memcpy(unmarshaled_secret.secret, response.secret().data(),
         unmarshaled_secret.size);

#ifdef DEBUG
  printf("\nunmarshaled secret: %d\n",
         (int) (unmarshaled_secret.size + sizeof(uint16_t)));
  PrintBytes(unmarshaled_secret.size, 
             (byte*)&unmarshaled_secret.secret);
  printf("\n");
  printf("\nConstructed credBlob (%d): ", credentialBlob.size);
  PrintBytes(credentialBlob.size, credentialBlob.credential);
  printf("\n");
#endif

  if (!Tpm2_ActivateCredential(tpm, quote_handle, ekHandle, parentAuth,
                               emptyAuth, credentialBlob, unmarshaled_secret,
                               &recovered_credential)) {
    printf("ActivateCredential failed\n");
    ret_val = 1;
    goto done;
  }

#ifdef DEBUG
  printf("\nActivateCredential succeeded\n");
  printf("\nRecovered credential (%d): ", recovered_credential.size);
  PrintBytes(recovered_credential.size, recovered_credential.buffer);
  printf("\n");
#endif

  // Decrypt cert, credential is key
  if (response.encrypted_cert().size() > MAX_SIZE_PARAMS) {
    printf("encrypted cert too large\n");
    ret_val = 1;
    goto done;
  }
  size_cert_out = response.encrypted_cert().size();

  size_derived_keys = 128;
  label = "PROTECT";
  cert_key_seed.assign((const char*)recovered_credential.buffer,
                       recovered_credential.size);
  if (!KDFa(hash_alg_id, cert_key_seed, label, contextV, contextV, 256,
            size_derived_keys, derived_keys)) {
    printf("Can't derive cert protection keys\n");
    ret_val = 1;
    goto done;
  }
  // Check Hmac first
  if (hash_alg_id == TPM_ALG_SHA1) {
    HMAC_Init_ex(&hctx, &derived_keys[16], 16, EVP_sha1(), nullptr);
    encrypted_cert_hmac_size = 20;
  } else {
    HMAC_Init_ex(&hctx, &derived_keys[16], 16, EVP_sha256(), nullptr);
    encrypted_cert_hmac_size = 32;
  }
  HMAC_Update(&hctx, (byte*)response.encrypted_cert().data(),
              response.encrypted_cert().size());
  HMAC_Final(&hctx, encrypted_cert_hmac, (uint32_t*)&encrypted_cert_hmac_size);
  HMAC_CTX_cleanup(&hctx);
  if (memcmp(encrypted_cert_hmac, response.encrypted_cert_hmac().data(),
             encrypted_cert_hmac_size) !=0) {
    printf("Hmac compare failed\n");
    ret_val = 1;
    goto done;
  }
  // decrypt
  if (!AesCtrCrypt(128, derived_keys, response.encrypted_cert().size(),
                   (byte*)response.encrypted_cert().data(),
                   cert_out_buf)) {
    printf("Can't parse response\n");
    ret_val = 1;
    goto done;
  }
  size_cert_out = response.encrypted_cert().size();

#ifdef DEBUG
  printf("\nhmac (%d): ", encrypted_cert_hmac_size);
  PrintBytes(encrypted_cert_hmac_size, encrypted_cert_hmac);
  printf("\n");
  printf("decrypted cert (%d): ", size_cert_out);
  PrintBytes(size_cert_out, cert_out_buf);
  printf("\n\n");
#endif
  
 // Write output cert
 if (!WriteFileFromBlock(FLAGS_program_key_cert_file,
                          size_cert_out,
                          cert_out_buf)) {
    printf("Can't write out program cert\n");
    ret_val = 1;
    goto done;
  }

done:
 if (root_handle != 0) {
    Tpm2_FlushContext(tpm, root_handle);
  }
  if (seal_handle != 0) {
    Tpm2_FlushContext(tpm, seal_handle);
  }
  if (quote_handle != 0) {
    Tpm2_FlushContext(tpm, quote_handle);
  }
  if (ekHandle != 0) {
    Tpm2_FlushContext(tpm, ekHandle);
  }
  tpm.CloseTpm();
  return ret_val;
}

