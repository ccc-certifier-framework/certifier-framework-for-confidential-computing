#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include <tpm20.h>
#include <tpm2_lib.h>
#include <gflags/gflags.h>

#include "certifier.h"
#include "support.h"
#include "tpm2_support.h"
#include "tpm2_lib.h"

#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <openssl_help.h>

//
// Copyright 2026 John L Manferdelli, All Rights Reserved.
// Portions, Copyright 2015 Google Corporation (see "License__notices.txt)
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
// File: tpm2_test.cc


// Calling sequence
// tpm2_test.exe

using std::string;
using namespace certifier::framework;
using namespace certifier::utilities;

DEFINE_string(operation, "", "operation");
DEFINE_string(password, "password", "password");
DEFINE_int32(pcr_num, -1, "integer parameter");
DEFINE_int32(index, -1, "nv index");
DEFINE_int32(nv_slot, 1000, "nv slot");
DEFINE_int32(nv_size, -1, "nv size");
DEFINE_string(tpm_device, "/dev/tpm0", "tpm device");
DEFINE_string(seal_hierearchy_name,
              "seal_hierarchy.bin",
              "seal hierarch save file name");
DEFINE_string(quote_hierearchy_name,
              "quote_hierarchy.bin",
              "quote hierarch save file name");
DEFINE_string(ek_cert_file_name, "ek-rsa2048.crt", "tpm cert file name");

#ifndef GFLAGS_NS
#  define GFLAGS_NS google
#endif

#define DEBUG

// ----------------------------------------------------------

byte_t g_policy_rsa_2048[32] = {0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8,
                                0x1a, 0x90, 0xcc, 0x8d, 0x46, 0xa5, 0xd7, 0x24,
                                0xfd, 0x52, 0xd7, 0x6e, 0x06, 0x52, 0x0b, 0x64,
                                0xf2, 0xa1, 0xda, 0x1b, 0x33, 0x14, 0x69, 0xaa};
byte_t g_policy_rsa_3072[48] = {
    0xB2, 0x6E, 0x7D, 0x28, 0xD1, 0x1A, 0x50, 0xBC, 0x53, 0xD8, 0x82, 0xBC,
    0xF5, 0xFD, 0x3A, 0x1A, 0x07, 0x41, 0x48, 0xBB, 0x35, 0xD3, 0xB4, 0xE4,
    0xCB, 0x1C, 0x0A, 0xD9, 0xBD, 0xE4, 0x19, 0xCA, 0xCB, 0x47, 0xBA, 0x09,
    0x69, 0x96, 0x46, 0x15, 0x0F, 0x9F, 0xC0, 0x00, 0xF3, 0xF8, 0x0E, 0x12};

/*
 * Flags (L-1)
 *
 *   Type:    tpm2.AlgRSA,
 *   NameAlg: tpm2.AlgSHA256,
 *   objectAttributes
 *     fixedTPM = 1
 *     stClear = 0
 *     fixedParent = 1
 *     sensitiveDataOrigin = 1
 *     userWithAuth = 0
 *     adminWithPolicy = 1
 *     noDA = 0
 *     encryptedDuplication = 0
 *     restricted = 1
 *     decrypt = 1
 *     sign = 0
 *   authPolicy
 *     0x83, 0x71, 0x97, 0x67, 0x44, 0x84,
 *     0xB3, 0xF8, 0x1A, 0x90, 0xCC, 0x8D,
 *     0x46, 0xA5, 0xD7, 0x24, 0xFD, 0x52,
 *     0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64,
 *     0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14,
 *     0x69, 0xAA
 *   parameters TPMS_RSA_PARMS
 *   symmetric->algorithm TPM_ALG_AES
 *   symmetric->keyBits 128
 *   symmetric->mode TPM_ALG_CFB
 *   symmetric->details NULL
 *   scheme->scheme TPM_ALG_NULL
 *   scheme->details NULL
 *   keyBits TPMI_RSA_KEY_BITS 2048
 *   exponent UINT32 0
 *   unique TPM2B_PUBLIC_KEY_RSA
 *   size UINT16 256
 */


bool endorsement_test(local_tpm &tpm, string authString) {
  TPM_HANDLE ek_handle;

  string policyString;
  string emptyAuth;
  int    size_buf = 128;
  byte_t buf[size_buf];

  int m = CreatePasswordAuthArea(emptyAuth, size_buf, buf);
  if (m < 0) {
    printf("%s() error, line %d, CreatePasswordAuthArea failed\n",
           __func__,
           __LINE__);
    return false;
  }
  authString.assign((char *)(buf + 2), m - 2);
  policyString.assign((char *)g_policy_rsa_2048, sizeof(g_policy_rsa_2048));

  if (!get_endorsement_key(tpm, authString, policyString, &ek_handle)) {
    printf("%s() error, line %d, get_endorsement_key failed\n",
           __func__,
           __LINE__);
    return false;
  }

  TPM2B_PUBLIC pub_out;
  TPM2B_NAME   pub_name;
  TPM2B_NAME   qualified_pub_name;
  uint16_t     pub_blob_size = 4096;
  byte_t       pub_blob[pub_blob_size];
  if (!Tpm2_ReadPublic(tpm,
                       ek_handle,
                       &pub_blob_size,
                       pub_blob,
                       &pub_out,
                       &pub_name,
                       &qualified_pub_name)) {
    printf("%s() error, line %d, ReadPublic failed\n", __func__, __LINE__);
    Tpm2_FlushContext(tpm, ek_handle);
    return false;
  }
  printf("Endorsement Key\n");
  printf("Public blob: ");
  print_bytes(pub_blob_size, pub_blob);
  printf("\n");
  printf("Name: ");
  print_bytes(pub_name.size, pub_name.name);
  printf("\n");
  printf("Qualified name: ");
  print_bytes(qualified_pub_name.size, qualified_pub_name.name);
  printf("\n");
  printf("Pubout size: %d\n", pub_out.size);
  printf("Type: %d\n", pub_out.publicArea.type);
  printf("Name: %d\n", pub_out.publicArea.nameAlg);
  printf("Scheme: %d\n", pub_out.publicArea.parameters.rsaDetail.scheme.scheme);
  printf("Bytes (%d):\n", (int)pub_out.publicArea.unique.rsa.size);
  print_bytes((int)pub_out.publicArea.unique.rsa.size,
              (byte_t *)pub_out.publicArea.unique.rsa.buffer);
  printf("\n");
  printf("Exponent: %d\n", pub_out.publicArea.parameters.rsaDetail.exponent);
  printf("\n");
#if 0
  byte_t reversed[256];
  reverse_byte_copy((int)pub_out.publicArea.unique.rsa.size,
                    (byte_t *)pub_out.publicArea.unique.rsa.buffer,
                    reversed);
  printf("Bytes reversed (%d):\n", (int)pub_out.publicArea.unique.rsa.size);
  print_bytes((int)pub_out.publicArea.unique.rsa.size, reversed);
  printf("\n");
#endif

  Tpm2_FlushContext(tpm, ek_handle);

  string cert_out;
  if (!get_endorsement_cert(FLAGS_ek_cert_file_name, &cert_out)) {
    printf("%s() error, line %d, get_endorsement_cert failed\n",
           __func__,
           __LINE__);
    return false;
  }
  string tmp_cert_name("jlm_cert.crt");
  if (!write_file_from_string(tmp_cert_name, cert_out)) {
    printf("%s() error, line %d, get_endorsement_cert failed\n",
           __func__,
           __LINE__);
    return false;
  }

  return true;
}

bool seal_test(local_tpm &tpm, int pcr_num, const string &seal_file) {

  int    num_pcrs = 1;
  byte_t pcrs[1] = {7};

  if (!extend_pcrs(tpm, 7)) {
    printf("%s() error, line %d, extend_pcrs failed\n", __func__, __LINE__);
    return false;
  }

  if (!create_seal_hierarchy_and_secret(tpm, num_pcrs, pcrs, seal_file)) {
    printf("%s() error, line %d, create_seal_hierarchy_and_secret failed\n",
           __func__,
           __LINE__);
    return false;
  }

  printf("\n");
  string seal_secret;
  if (!recover_sealing_secret(tpm,
                              num_pcrs,
                              pcrs,
                              FLAGS_seal_hierearchy_name,
                              &seal_secret)) {
    printf("%s() error, line %d, recover_sealing_secret failed\n",
           __func__,
           __LINE__);
    return false;
  }

  printf("Recovered seal secret: ");
  print_bytes(seal_secret.size(), (byte_t *)seal_secret.data());
  printf("\n");

  return true;
}

bool quote_test(local_tpm &tpm, const string &quote_file) {
  int    num_pcrs = 1;
  byte_t pcrs[1] = {7};

  TPM_HANDLE srk_handle;
  TPM_HANDLE quote_handle;

  if (!extend_pcrs(tpm, 7)) {
    printf("%s() error, line %d, extend_pcrs failed\n", __func__, __LINE__);
    return false;
  }

  if (!create_quote_hierarchy(tpm, num_pcrs, pcrs, quote_file)) {
    printf("%s() error, line %d, create_quote_hierarchy failed\n",
           __func__,
           __LINE__);
    return false;
  }

  if (!recover_and_load_quote_hierarchy(tpm,
                                        num_pcrs,
                                        pcrs,
                                        quote_file,
                                        &srk_handle,
                                        &quote_handle)) {
    printf("%s() error, line %d, recover_and_load_quote_hierarchy failed\n",
           __func__,
           __LINE__);
    return false;
  }

  string to_quote("I am being quoted");
  string quoted;
  string signature;

  if (!do_quote(tpm,
                srk_handle,
                num_pcrs,
                pcrs,
                quote_handle,
                to_quote,
                &quoted,
                &signature)) {
    printf("%s() error, line %d, recover_sealing_secret failed\n",
           __func__,
           __LINE__);
    Tpm2_FlushContext(tpm, quote_handle);
    Tpm2_FlushContext(tpm, srk_handle);
    return false;
  }
  printf("do_quote succeeded\n");

  TPM2B_PUBLIC pub_out;
  TPM2B_NAME   pub_name;
  TPM2B_NAME   qualified_pub_name;
  uint16_t     pub_blob_size = 4096;
  byte_t       pub_blob[pub_blob_size];
  if (!Tpm2_ReadPublic(tpm,
                       quote_handle,
                       &pub_blob_size,
                       pub_blob,
                       &pub_out,
                       &pub_name,
                       &qualified_pub_name)) {
    printf("%s() error, line %d, ReadPublic failed\n", __func__, __LINE__);
    Tpm2_FlushContext(tpm, quote_handle);
    Tpm2_FlushContext(tpm, srk_handle);
    return false;
  } else {
    printf("ReadPublic quote key succeeded\n");
  }
#if 0
  printf("\nQuote Key\n");
  printf("  Pubout size: %d\n", pub_out.size);
  printf("  Type: %d\n", pub_out.publicArea.type);
  printf("  Alg name: %x\n", pub_out.publicArea.nameAlg);
  printf("  Scheme: %d\n", pub_out.publicArea.parameters.rsaDetail.scheme.scheme);
  printf("  Modulus (%d):\n", (int)pub_out.publicArea.unique.rsa.size);
  print_bytes((int)pub_out.publicArea.unique.rsa.size,
              (byte_t *)pub_out.publicArea.unique.rsa.buffer);
  printf("\n");
  printf("  Exponent: %d\n", pub_out.publicArea.parameters.rsaDetail.exponent);
  printf("\n");
#endif

  key_message quote_key;

  int n = (int)pub_out.publicArea.unique.rsa.size;
  if (n == 256) {
    quote_key.set_key_type(Enc_method_rsa_2048_public);
  } else if (n == 128) {
    quote_key.set_key_type(Enc_method_rsa_1024_public);
  } else if (n == 512) {
    quote_key.set_key_type(Enc_method_rsa_4096_public);
  } else if (n == 384) {
    quote_key.set_key_type(Enc_method_rsa_3072_public);
  } else {
    printf("%s() error, line: %d, bad modulus size failed\n",
           __func__,
           __LINE__);
    Tpm2_FlushContext(tpm, quote_handle);
    Tpm2_FlushContext(tpm, srk_handle);
    return false;
  }
  rsa_message *rsa = new (rsa_message);
  quote_key.set_allocated_rsa_key(rsa);
  uint32_t le_exp;

  change_endian32((uint32_t *)&pub_out.publicArea.parameters.rsaDetail.exponent,
                  (uint32_t *)&le_exp);

  quote_key.set_key_name("quote-key-tpm");
  quote_key.set_key_format("vse-key");

  byte_t le_modulus[256];
  reverse_byte_copy(256,
                    (byte_t *)pub_out.publicArea.unique.rsa.buffer,
                    le_modulus);
  rsa->set_public_modulus(le_modulus, n);
  rsa->set_public_exponent((byte_t *)&le_exp, sizeof(uint32_t));
  print_key(quote_key);
  printf("\n");

  if (!tpm_verify_attest(quote_key, to_quote, quoted, signature)) {
    printf("%s() error, line: %d, Cant verify quote\n", __func__, __LINE__);
    Tpm2_FlushContext(tpm, quote_handle);
    Tpm2_FlushContext(tpm, srk_handle);
    return true;
  }

#if 0
  if (!verify_credential(tpm, to_quote, quote_sig)) {
    printf("%s() error, line %d, verify_credential failed\n",
           __func__,
           __LINE__);
    Tpm2_FlushContext(tpm, quote_handle);
    Tpm2_FlushContext(tpm, srk_handle);
    return false;
  }
#endif

  // Make/Activate Credential
  TPM_HANDLE ek_handle;
  string     emptyAuth;

  if (!get_endorsement_key(tpm, emptyAuth, emptyAuth, &ek_handle)) {
    printf("%s() error, line %d, get_endorsement_key failed\n",
           __func__,
           __LINE__);
    return false;
  }

  // Credential test
  TPM2B_DIGEST           credential;
  TPM2B_ID_OBJECT        credentialBlob;
  TPM2B_ENCRYPTED_SECRET secret;
  TPM2B_DIGEST           recovered_credential;

  memset((void *)&credential, 0, sizeof(TPM2B_DIGEST));
  memset((void *)&secret, 0, sizeof(TPM2B_ENCRYPTED_SECRET));
  memset((void *)&credentialBlob, 0, sizeof(TPM2B_ID_OBJECT));

  // TODO: Make a real secret here for MakeCredential with
  // size 32 bits.
  credential.size = 32;
  for (int i = 0; i < credential.size; i++)
    credential.buffer[i] = i + 1;

  TPM2B_PUBLIC quoting_pub_out;
  TPM2B_NAME   quoting_pub_name;
  TPM2B_NAME   quoting_qualified_pub_name;
  uint16_t     quoting_pub_blob_size = 1024;
  byte_t       quoting_pub_blob[quoting_pub_blob_size];

  memset((void *)&quoting_pub_out, 0, sizeof(TPM2B_PUBLIC));

  if (!Tpm2_ReadPublic(tpm,
                       quote_handle,
                       &quoting_pub_blob_size,
                       quoting_pub_blob,
                       &quoting_pub_out,
                       &quoting_pub_name,
                       &quoting_qualified_pub_name)) {
    printf("%s() error, line: %d, Cant read quote public\n",
           __func__,
           __LINE__);
    Tpm2_FlushContext(tpm, quote_handle);
    Tpm2_FlushContext(tpm, srk_handle);
    Tpm2_FlushContext(tpm, ek_handle);
    return false;
  }
  printf("Active Name (%d): ", quoting_pub_name.size);
  print_bytes(quoting_pub_name.size, quoting_pub_name.name);
  printf("\n");

  if (!Tpm2_MakeCredential(tpm,
                           ek_handle,
                           credential,
                           quoting_pub_name,
                           &credentialBlob,
                           &secret)) {
    printf("%s() error, line: %d, Cant MakeCredential failed\n",
           __func__,
           __LINE__);
    Tpm2_FlushContext(tpm, quote_handle);
    Tpm2_FlushContext(tpm, srk_handle);
    Tpm2_FlushContext(tpm, ek_handle);
  }

  printf("MakeCredential succeeded\n");
  printf("credBlob size: %d\n", credentialBlob.size);
  printf("secret size: %d\n", secret.size);
  if (!Tpm2_ActivateCredential(tpm,
                               quote_handle,
                               ek_handle,
                               emptyAuth,
                               emptyAuth,
                               credentialBlob,
                               secret,
                               &recovered_credential)) {
    printf("%s() error, line: %d, ActivateCredential failed\n",
           __func__,
           __LINE__);
    Tpm2_FlushContext(tpm, quote_handle);
    Tpm2_FlushContext(tpm, srk_handle);
    Tpm2_FlushContext(tpm, ek_handle);
    return false;
  }
  printf("ActivateCredential succeeded\n");
  printf("Recovered credential (%d): ", recovered_credential.size);
  print_bytes(recovered_credential.size, recovered_credential.buffer);
  printf("\n");

  Tpm2_FlushContext(tpm, ek_handle);
  Tpm2_FlushContext(tpm, quote_handle);
  Tpm2_FlushContext(tpm, srk_handle);
  return true;
}

bool context_test(local_tpm &tpm) {
  TPM_HANDLE handle;
  uint16_t   size = 4096;
  byte_t     saveArea[4096];
  string     authString;
  string     sensitiveData;
  string     outsideInfo;
  string     policyString;

  TPM2B_PUBLIC       pub_out;
  TPML_PCR_SELECTION pcrSelect;
  init_single_pcr_selection(7, TPM_ALG_SHA1, &pcrSelect);

  TPMA_OBJECT primary_flags;
  *(uint32_t *)(&primary_flags) = 0;
  primary_flags.fixedTPM = 1;
  primary_flags.fixedParent = 1;
  primary_flags.sensitiveDataOrigin = 1;
  primary_flags.userWithAuth = 1;
  primary_flags.sign = 1;

  if (Tpm2_CreatePrimary(tpm,
                         TPM_RH_OWNER,
                         authString,
                         sensitiveData,
                         outsideInfo,
                         pcrSelect,
                         TPM_ALG_RSA,
                         TPM_ALG_SHA256,
                         primary_flags,
                         policyString,
                         TPM_ALG_NULL,
                         (TPMI_AES_KEY_BITS)0,
                         TPM_ALG_ECB,
                         TPM_ALG_RSASSA,
                         1024,
                         0x010001,
                         &handle,
                         &pub_out)) {
    printf("%s() error, line %d, CreatePrimary failed\n", __func__, __LINE__);
    return false;
  }
#ifdef DEBUG
  printf("CreatePrimary succeeded\n");
#endif

  string in;
  string out;

  if (!save_context(tpm, handle, &out)) {
    printf("%s() error, line %d, save_context failed\n", __func__, __LINE__);
    Tpm2_FlushContext(tpm, handle);
    return false;
  }
  if (!load_context(tpm, handle, in)) {
    printf("%s() error, line %d, load_context failed\n", __func__, __LINE__);
    Tpm2_FlushContext(tpm, handle);
    return false;
  }

  Tpm2_FlushContext(tpm, handle);
  return true;
}

bool nv_test(local_tpm &tpm) {
  int slot = 1000;

  uint16_t size_data = 16;
  byte_t   data_in[512] = {0x9,
                           0x8,
                           0x7,
                           0x6,
                           0x9,
                           0x8,
                           0x7,
                           0x6,
                           0x9,
                           0x8,
                           0x7,
                           0x6,
                           0x9,
                           0x8,
                           0x7,
                           0x6};
  uint16_t size_out = 512;
  byte_t   data_out[512];

  string in;
  string out;
  in.assign((char *)data_in, size_data);

  if (!write_nv_slot(tpm, slot, in)) {
    printf("%s() error, line %d, write_nv_slot failed\n", __func__, __LINE__);
    return false;
  }
  if (!read_nv_slot(tpm, slot, &out)) {
    printf("%s() error, line %d, read_nv_slot failed\n", __func__, __LINE__);
    return false;
  }

  if (memcmp(in.data(), out.data(), out.size()) != 0) {
    printf("%s() error, line %d, written and read values don't match\n",
           __func__,
           __LINE__);
    return false;
  }
  return true;
}

bool define_write_read_test(local_tpm &tpm) {
#if 0
  TPM_HANDLE handle = 0x1000;

  if (!read_file_into_string(file_name, &cert)) {
    printf("%s() error, line %d, can't read cert file\n",
           __func__, __LINE__);
    return false;
  }

  // define a policy here using StartAuthSession
  int num_pcrs = 1;
  byte_t pcrs[1] = {7};
  if (!extend_pcrs(tpm, 7)) {
    printf("%s() error, line %d, extend_pcrs failed\n",
                    __func__, __LINE__);
    return false;
  }

#  ifdef DEBUG
  print_pcrs(tpm, num_pcrs, pcrs);
#  endif

  TPM2B_AUTH auth;
  string     authString;
  if (!create_pcr_policy(tpm, num_pcrs, pcrs, &auth)) {
    printf("%s() error, line %d, create_pcr_policy failed\n",
                   __func__, __LINE__);
    return false;
  }
#  ifdef DEBUG
  printf("Tpm2_DefineSpace create_pcr_policy succeeds\n");
#  endif

  if (!Tpm2_UndefineSpace(tpm, TPM_RH_OWNER, handle)) {
#  ifdef DEBUG
    printf("Tpm2_UndefineSpace fails (but that's OK usually)\n");
#  endif
  } else {
#  ifdef DEBUG
  printf("Tpm2_UndefineSpace %x succeeds\n", handle);
#  endif
  }

#  ifdef DEBUG
  printf("authstring size: %d\n", (int)authString.size());
  print_pcrs(tpm, num_pcrs, pcrs);
#  endif
  if (!Tpm2_DefineSpace(tpm,
                        TPM_RH_OWNER,
                        authString,
                        handle,
                        TPM_ALG_SHA256,
                        NV_AUTHWRITE | NV_AUTHREAD,
                        auth,
                        (uint16_t)cert.size())) {
    printf("%s() error, line %d, DefineSpace failed\n",
                    __func__, __LINE__);
    return false;
  }
#  ifdef DEBUG
  printf("Tpm2_DefineSpace %x succeeds\n", handle);
#  endif

  if (!write_nv_handle(tpm, handle, authString, cert)) {
    printf("%s() error, line %d, write nvram\n", __func__, __LINE__);
    return false;
  }
#endif
  return false;
}

bool get_cert(local_tpm &tpm, const string &file_name, string *out) {
  string     cert;
  TPM_HANDLE handle = 0x1c00002;

  if (!get_endorsement_cert(tpm, out)) {
    printf("%s() error, line %d, can't get endorsement cert\n",
           __func__,
           __LINE__);
    return false;
  }
  printf("Cert:\n");
  print_bytes(out->size(), (byte_t *)out->data());
  printf("\n");
  return true;
}

// ------------------------------------------------------------------------

int main(int an, char **av) {
  local_tpm tpm;

#if 0
  if (!tpm_init(const string &device_name,
              const string &endorsement_cert_file_name,
              const string &seal_hierarchy_file_name,
              const string &quote_hierarchy_file_name)) {
    printf("%s() error, line %d, tpm_init failed\n", __func__, __LINE__);
    return false;
  }
#endif

  GFLAGS_NS::ParseCommandLineFlags(&an, &av, true);

  if (FLAGS_operation == "") {
    printf("operations:\n");
    printf("  EndorsementTest\n");
    printf("  SealTest\n");
    printf("  QuoteTest\n");
    printf("  ContextTest\n");
    printf("  NvTest\n");
    printf("  GetCert\n");
    return 1;
  }

  if (!tpm.open_tpm(FLAGS_tpm_device.c_str())) {
    printf("Can't open tpm: %s\n", FLAGS_tpm_device.c_str());
    return 1;
  }
#ifdef DEBUG
  printf("Opened tpm: %s %d\n", FLAGS_tpm_device.c_str(), tpm.tpm_fd_);
#endif

  string authString;
  if (FLAGS_operation == "EndorsementTest") {
    printf("\n");
    if (endorsement_test(tpm, authString)) {
      printf("endorsement test succeeded\n");
    } else {
      printf("endorsement test failed\n");
    }
  } else if (FLAGS_operation == "SealTest") {
    printf("\n");
    if (seal_test(tpm, 7, FLAGS_seal_hierearchy_name)) {
      printf("seal test succeeded\n");
    } else {
      printf("seal test failed\n");
    }
  } else if (FLAGS_operation == "QuoteTest") {
    printf("\n");
    if (quote_test(tpm, FLAGS_quote_hierearchy_name)) {
      printf("quote test succeeded\n");
    } else {
      printf("quote test failed\n");
    }
  } else if (FLAGS_operation == "ContextTest") {
    printf("\n");
    if (context_test(tpm)) {
      printf("context test succeeded\n");
    } else {
      printf("context test failed\n");
    }
  } else if (FLAGS_operation == "NvTest") {
    printf("\n");
    if (nv_test(tpm)) {
      printf("nv test succeeded\n");
    } else {
      printf("nv test failed\n");
    }
  } else if (FLAGS_operation == "GetCert") {
    string cert;
    if (get_cert(tpm, FLAGS_ek_cert_file_name, &cert)) {
      printf("get cert test succeeded\n");
    } else {
      printf("get cert test failed\n");
    }
  } else {
    printf("\n");
    printf("No such operation (%s)\n", FLAGS_operation.c_str());
  }

  tpm.close_tpm();
}
