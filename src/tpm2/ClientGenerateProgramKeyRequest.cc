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

#include <quote_protocol.h>

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
// File: ClientGenerateProgramKeyRequest.cc


// This program creates a program key and produces a
// program_cert_request_message which contains a protobuf
// consisting of the endorsement key certificate, and
// a request to sign the program key and encrypt the result
// with a credential that can be unlocked with the endorsement
// key referencing the Quote key properties..

// Calling sequence: ClientGenerateProgramKeyRequest.exe
//    --signed_endorsement_cert=input-file-name
//    --signing_key_type=RSA
//    --signing_key_size=2048
//    --program_key_request_file=output-file-name


using std::string;


#define CALLING_SEQUENCE "ClientCreateSigningKey.exe " \
"--signed_endorsement_cert_file=input-file-name " \
"--slot_primary=1" \
"--slot_seal=2" \
"--slot_quote=3" \
"--program_key_name=name " \
"--program_key_type=RSA " \
"--program_key_size=2048 " \
"--program_key_exponent=0x10001" \
"--hash_alg=sha1 " \
"--program_key_file=output-file-name" \
"--program_cert_request_file=output-file-name\n"

void PrintOptions() {
  printf("Calling sequence: %s", CALLING_SEQUENCE);
}


DEFINE_string(signed_endorsement_cert_file, "", "input-file-name");
DEFINE_string(program_key_name, "NAME", "program name");
DEFINE_string(program_key_type, "RSA", "program key type");
DEFINE_int32(program_key_size, 2048, "program key type");
DEFINE_int64(program_key_exponent, 0x010001ULL, "program key exponent");
DEFINE_int32(slot_primary, 1, "slot number");
DEFINE_int32(slot_seal, 2, "seal slot number");
DEFINE_int32(slot_quote, 3, "quote slot number");
DEFINE_string(hash_alg, "sha1", "sha1|sha256");
DEFINE_string(program_key_file, "", "output-file-name");
DEFINE_string(program_cert_request_file, "", "output-file-name");

#ifndef GFLAGS_NS
#define GFLAGS_NS google
#endif

#define MAX_SIZE_PARAMS 4096
#define DEBUG

int main(int an, char** av) {
  LocalTpm tpm;
  int ret_val = 0;

  printf("\nClientGenerateProgramKeyRequest\n\n");

  GFLAGS_NS::ParseCommandLineFlags(&an, &av, true);
  if (!tpm.OpenTpm("/dev/tpm0")) {
    printf("Can't open tpm\n");
    return 1;
  }

  OpenSSL_add_all_algorithms();

  TPM_HANDLE ekHandle = 0;
  TPMA_OBJECT primary_flags;
  TPM2B_PUBLIC ek_pub_out;
  TPM2B_NAME ek_pub_name;
  TPM2B_NAME ek_qualified_pub_name;
  uint16_t ek_pub_blob_size = MAX_SIZE_PARAMS;
  byte ek_pub_blob[MAX_SIZE_PARAMS];

  int ek_cert_blob_size = MAX_SIZE_PARAMS;
  byte ek_cert_blob[MAX_SIZE_PARAMS];

  TPM_HANDLE nv_handle = 0;

  string authString("01020304");
  string parentAuth("01020304");
  string emptyAuth;

  TPML_PCR_SELECTION pcrSelect;

  TPM_HANDLE root_handle = 0; 
  TPM_HANDLE seal_handle = 0;
  TPM_HANDLE quote_handle = 0;

  TPM2B_PUBLIC quote_pub_out;
  TPM2B_NAME quote_pub_name;
  TPM2B_NAME quote_qualified_pub_name;
  uint16_t quote_pub_blob_size = MAX_SIZE_PARAMS;
  byte quote_pub_blob[MAX_SIZE_PARAMS];

  string endorsement_key_blob;
  byte context_save_area[MAX_SIZE_PARAMS];
  uint16_t context_data_size = 924;

  RSA* program_rsa_key = nullptr;
  byte program_der_array_private[MAX_SIZE_PARAMS];
  byte* program_start_private = nullptr;
  byte* program_next_private = nullptr;
  int program_len_private;

  string* mod = nullptr;
  uint64_t expIn;
  uint64_t expOut;
  SHA_CTX sha1;
  SHA256_CTX sha256;
  string x509_request_key_blob;

  private_key_blob_message program_key_out;
  program_cert_request_message request;

  int quote_size = MAX_SIZE_PARAMS;
  byte quoted[MAX_SIZE_PARAMS];
  byte quoted_hash[256];
  string quote_key_info;
  string quote_sig;
  string quote_info;
  quote_key_info_message quote_key_info_message;
  TPM2B_DATA to_quote;
  TPMT_SIG_SCHEME scheme;
  int sig_size = MAX_SIZE_PARAMS;
  byte sig[MAX_SIZE_PARAMS];

  TPM_ALG_ID hash_alg_id;
  if (FLAGS_hash_alg == "sha1") {
    hash_alg_id = TPM_ALG_SHA1;
  } else if (FLAGS_hash_alg == "sha256") {
    hash_alg_id = TPM_ALG_SHA256;
  } else {
    printf("Unknown hash algorithm\n");
    return 1;
  }

  string output;

  // Create endorsement key
  *(uint32_t*)(&primary_flags) = 0;

  primary_flags.fixedTPM = 1;
  primary_flags.fixedParent = 1;
  primary_flags.sensitiveDataOrigin = 1;
  primary_flags.userWithAuth = 1;
  primary_flags.decrypt = 1;
  primary_flags.restricted = 1;

  InitSinglePcrSelection(7, hash_alg_id, &pcrSelect);
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
  if (Tpm2_ReadPublic(tpm, ekHandle, &ek_pub_blob_size, ek_pub_blob,
                      &ek_pub_out, &ek_pub_name, &ek_qualified_pub_name)) {
    printf("ek ReadPublic succeeded\n");
  } else {
    printf("ek ReadPublic failed\n");
    ret_val = 1;
    goto done;
  }

#ifdef DEBUG_EXTRA
  printf("\nek Public blob: ");
  PrintBytes(ek_pub_blob_size, ek_pub_blob);
  printf("\n");
  printf("ek Name: ");
  PrintBytes(ek_pub_name.size, ek_pub_name.name);
  printf("\n");
  printf("ek Qualified name: ");
  PrintBytes(ek_qualified_pub_name.size, ek_qualified_pub_name.name);
  printf("\n");
#endif

  Tpm2_FlushContext(tpm, ekHandle);
  ekHandle = 0;

  // Get endorsement cert
  if (!ReadFileIntoBlock(FLAGS_signed_endorsement_cert_file, 
                         &ek_cert_blob_size, ek_cert_blob)) {
    printf("Can't read endorsement info\n");
    ret_val = 1;
    goto done;
  }
  endorsement_key_blob.assign((const char*)ek_cert_blob, ek_cert_blob_size);

  // restore hierarchy
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

  // seal handle
  memset(context_save_area, 0, MAX_SIZE_PARAMS);
  nv_handle = GetNvHandle(FLAGS_slot_seal);
  if (!Tpm2_ReadNv(tpm, nv_handle, authString, &context_data_size,
                   context_save_area)) {
    printf("Root ReadNv failed\n");
    ret_val = 1;
    goto done;
  }

#ifdef DEBUG_EXTRA
  printf("context_save_area: ");
  PrintBytes(context_data_size, context_save_area);
  printf("\n");
#endif

  if (!Tpm2_LoadContext(tpm, context_data_size, context_save_area,
                        &seal_handle)) {
    printf("Seal LoadContext failed\n");
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

#ifdef DEBUG_EXTRA
  printf("context_save_area: ");
  PrintBytes(context_data_size, context_save_area);
  printf("\n");
#endif

  if (!Tpm2_LoadContext(tpm, context_data_size, context_save_area,
                        &quote_handle)) {
    printf("Quote LoadContext failed\n");
    ret_val = 1;
    goto done;
  }

  // Generate program key
  if (FLAGS_program_key_type != "RSA") {
    printf("Only RSA supported\n");
    ret_val = 1;
    goto done;
  }
  if (FLAGS_program_key_name == "") {
    printf("No key name\n");
    ret_val = 1;
    goto done;
  }
  if (FLAGS_program_key_file == "") {
    printf("No key file\n");
    ret_val = 1;
    goto done;
  }

  program_rsa_key = RSA_generate_key(FLAGS_program_key_size, 
                                     FLAGS_program_key_exponent,
                                     nullptr, nullptr);
  if (program_rsa_key == nullptr) {
    printf("Can't generate RSA key\n");
    ret_val = 1;
    goto done;
  }
  program_len_private = i2d_RSAPrivateKey(program_rsa_key, nullptr);
  program_start_private = program_der_array_private;
  program_next_private = program_der_array_private;
  i2d_RSAPrivateKey(program_rsa_key, (byte**)&program_next_private);
  printf("\nder encoded private key (%d): ", program_len_private);
  PrintBytes(program_len_private, program_start_private);
  printf("\n\n");

  program_key_out.set_key_type("RSA");
  program_key_out.set_key_name(FLAGS_program_key_name);
  program_key_out.set_blob((const char*)program_start_private,
                           program_len_private);
  if (!program_key_out.SerializeToString(&output)) {
    printf("Can't serialize output\n");
    ret_val = 1;
    goto done;
  }
  if (!WriteFileFromBlock(FLAGS_program_key_file, output.size(),
                          (byte*)output.data())) {
    printf("Can't write output file\n");
    ret_val = 1;
    goto done;
  }

  // Fill program key parameters
  request.set_endorsement_cert_blob(endorsement_key_blob);
  request.set_quote_sign_alg("RSA");
  request.set_quote_sign_hash_alg(FLAGS_hash_alg);
  request.mutable_program_key()->set_program_name(FLAGS_program_key_name);
  request.mutable_program_key()->set_program_key_type("RSA");
  request.mutable_program_key()->set_program_bit_modulus_size(
      FLAGS_program_key_size);
  expIn = (uint64_t) FLAGS_program_key_exponent;
  ChangeEndian64((uint64_t*)&expIn, (uint64_t*)(&expOut));
  request.mutable_program_key()->set_program_key_exponent(
      (const char*)&expOut, sizeof(uint64_t));
  mod = BN_to_bin(*program_rsa_key->n);
  if (mod == nullptr) {
    printf("Can't get program key modulus\n");
    ret_val = 1;
    goto done;
  }
  request.mutable_program_key()->set_program_key_modulus(
      (byte*)mod->data(), mod->size());

  // get quote key info
  if (Tpm2_ReadPublic(tpm, quote_handle, &quote_pub_blob_size,
                      quote_pub_blob, &quote_pub_out, &quote_pub_name,
                      &quote_qualified_pub_name)) {
    printf("Quote ReadPublic succeeded\n");
  } else {
    printf("Quote ReadPublic failed\n");
    ret_val = 1;
    goto done;
  }

#ifdef DEBUG_EXTRA
  printf("\nQuote Public blob: ");
  PrintBytes(quote_pub_blob_size, quote_pub_blob);
  printf("\n");
  printf("Quote Name: ");
  PrintBytes(quote_pub_name.size, quote_pub_name.name);
  printf("\n");
  printf("Quote Qualified name: ");
  PrintBytes(quote_qualified_pub_name.size, quote_qualified_pub_name.name);
  printf("\n");
#endif

  // hash program key request
  {
    string serialized_key = request.mutable_program_key()->DebugString();
    if (hash_alg_id == TPM_ALG_SHA1) {
      SHA1_Init(&sha1);
      SHA1_Update(&sha1, (byte*)serialized_key.data(), serialized_key.size());
      SHA1_Final(quoted_hash, &sha1);
    } else {
      SHA256_Init(&sha256);
      SHA256_Update(&sha256, (byte*)serialized_key.data(),
                    serialized_key.size());
      SHA256_Final(quoted_hash, &sha256);
    }
    to_quote.size = SizeHash(hash_alg_id);
    memset(to_quote.buffer, 0, to_quote.size);
    memcpy(to_quote.buffer, quoted_hash, to_quote.size);
  }

#ifdef DEBUG
  printf("\nquoted_hash: "); PrintBytes(to_quote.size, to_quote.buffer);
  printf("\n");
#endif

  if (!Tpm2_Quote(tpm, quote_handle, parentAuth, to_quote.size,
                  to_quote.buffer, scheme, pcrSelect, TPM_ALG_RSA,
                  hash_alg_id, &quote_size, quoted, &sig_size, sig)) {
    printf("Quote failed\n");
    ret_val = 1;
    goto done;
  }

#ifdef DEBUG
  {
    printf("\nQuote succeeded\n");
    printf("Quoted (%d): ", to_quote.size);
    PrintBytes(to_quote.size, to_quote.buffer);
    printf("\n");
    printf("TPM computed quote (%d): ", quote_size);
    PrintBytes(quote_size, quoted);
    printf("\n");
    printf("Sig (%d): ", sig_size);
    PrintBytes(sig_size, sig);
    printf("\n");
    TPMS_ATTEST t;
    if (UnmarshalCertifyInfo(quote_size, quoted, &t)) {
      print_quote_certifyinfo(t);
    }
    printf("\n");
  }
#endif

  // Quote key information
  // quote_pub_out.publicArea contains quote key info.  Namely,
  // TPMI_ALG_PUBLIC   type;
  // TPMI_ALG_HASH     nameAlg;
  // TPMA_OBJECT       objectAttributes;
  // TPM2B_DIGEST      authPolicy;
  // TPMU_PUBLIC_PARMS parameters;
  //   TPMI_ALG_PUBLIC   type;
  //   TPMU_PUBLIC_PARMS parameters;
  //     TPMS_RSA_PARMS rsaDetails
  //        TPMT_SYM_DEF_OBJECT symmetric;
  //        TPMT_RSA_SCHEME     scheme;
  //        TPMI_RSA_KEY_BITS   keyBits;
  //        uint32_t            exponent;
  // TPMU_PUBLIC_ID    unique;
  //   TPM2B_PUBLIC_KEY_RSA rsa
  //      size
  //      buffer
  request.set_quoted_blob(quoted, quote_size);
  quote_sig.assign((const char*)sig, sig_size);
  request.set_quote_signature(quote_sig);
  request.mutable_quote_key_info()->mutable_public_key()->set_key_type("RSA");
  request.mutable_quote_key_info()->mutable_public_key()->mutable_rsa_key()
      ->set_key_name("Quote_key");
  request.mutable_quote_key_info()->mutable_public_key()->mutable_rsa_key()
      ->set_bit_modulus_size(
         quote_pub_out.publicArea.parameters.rsaDetail.keyBits);
  expIn = quote_pub_out.publicArea.parameters.rsaDetail.exponent;
  expOut = 0ULL;
  ChangeEndian64((uint64_t*)&expIn, (uint64_t*)&expOut);
  request.mutable_quote_key_info()->mutable_public_key()->mutable_rsa_key()
     ->set_exponent((const char*)&expOut, sizeof(uint64_t));
  request.mutable_quote_key_info()->mutable_public_key()->mutable_rsa_key()
    ->set_modulus((const char*)quote_pub_out.publicArea.unique.rsa.buffer,
                  quote_pub_out.publicArea.unique.rsa.size);
  request.mutable_quote_key_info()->set_name(
      (const char*)quote_pub_name.name, quote_pub_name.size);
  request.mutable_quote_key_info()->set_properties(
      *(uint32_t*)&quote_pub_out.publicArea.objectAttributes);
  if (quote_pub_out.publicArea.nameAlg == TPM_ALG_SHA1) {
    request.set_quote_sign_hash_alg("sha1");
  } else if (quote_pub_out.publicArea.nameAlg == TPM_ALG_SHA256) {
    request.set_quote_sign_hash_alg("sha256");
  } else {
    printf("Unsupported hash alg\n");
    ret_val = 1;
    goto done;
  }

  output.clear();
  if (!request.SerializeToString(&output)) {
    printf("Can't serialize string\n");
    ret_val = 1;
    goto done;
  }
  if (!WriteFileFromBlock(FLAGS_program_cert_request_file,
                          output.size(),
                          (byte*)output.data())) {
    printf("Can't write endorsement cert\n");
    goto done;
  }

#ifdef DEBUG_EXTRA
  printf("\nrequest:\n%s\n", request.DebugString().c_str());
#endif

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
