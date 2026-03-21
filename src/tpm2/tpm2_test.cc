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
DEFINE_int32(num_pcrs, 1, "number of pcrs");

#ifndef GFLAGS_NS
#  define GFLAGS_NS google
#endif

#define DEBUG

// ----------------------------------------------------------

#define INTERNALTPMMAKECRED

bool credential_test(local_tpm          &tpm,
                     TPML_PCR_SELECTION &pcrSelect,
                     TPM_HANDLE         &srk_handle,
                     TPM_HANDLE         &quote_handle) {

  TPM_HANDLE ek_handle = 0;
  string     policyString;
  string     authString;
  string     emptyAuth;
  int        size_buf = 128;
  byte_t     buf[size_buf];

  int m = CreatePasswordAuthArea(emptyAuth, size_buf, buf);
  if (m < 0) {
    printf("%s() error, line %d, CreatePasswordAuthArea failed\n",
           __func__,
           __LINE__);
    return false;
  }

  extern byte_t g_policy_rsa_2048[32];
  authString.assign((char *)(buf + 2), m - 2);
  policyString.assign((char *)g_policy_rsa_2048, sizeof(g_policy_rsa_2048));

  if (!get_endorsement_key(tpm, authString, policyString, &ek_handle)) {
    printf("%s() error, line %d, get_endorsement_key failed\n",
           __func__,
           __LINE__);
    return false;
  }
#ifdef DEBUG1
  printf("\nGot endorsement key %08x\n", ek_handle);
#endif

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
    printf("%s() error, line %d, ReadPublic failed\n", __func__, __LINE__);
    Tpm2_FlushContext(tpm, ek_handle);
    return false;
  }
#ifdef DEBUG1
  printf("Credential tests, ReadPublic succeeded\n");
  printf("Active Name (%d): ", quoting_pub_name.size);
  print_bytes(quoting_pub_name.size, quoting_pub_name.name);
  printf("\n");
#endif

  if (!Tpm2_MakeCredential(tpm,
                           ek_handle,
                           credential,
                           quoting_pub_name,
                           &credentialBlob,
                           &secret)) {
    printf("%s() error, line %d, Tpm2_MakeCredential failed\n",
           __func__,
           __LINE__);
    Tpm2_FlushContext(tpm, ek_handle);
    return false;
  }

#ifdef DEBUG2
  printf("TPM MakeCredential succeeded\n");
  printf("credBlob size: %d\n", credentialBlob.size);
  print_bytes(credentialBlob.size, credentialBlob.credential);
  printf("\n");
  printf("secret size: %d\n", secret.size);
  print_bytes(secret.size, secret.secret);
  printf("\n");
  printf("\ncredentialBlob: ");
  print_bytes(sizeof(credentialBlob), (byte_t *)&credentialBlob);
  printf("\n");
#endif

  // Activate
  string nonce;
  string policyDigest;
  policyDigest.assign((char *)quoting_pub_out.publicArea.authPolicy.buffer,
                      quoting_pub_out.publicArea.authPolicy.size);

  byte_t auth_buf[256];
  int    n = 0;

  string quoteAuth = authString;

#ifdef DEBUG1
  print_bytes(quoteAuth.size(), (byte_t *)quoteAuth.data());
  printf("\n");
  printf("Nonce (%d): ", (int)nonce.size());
  print_bytes(nonce.size(), (byte_t *)nonce.data());
  printf("\n");
#endif

  // endorsement auth session
  TPM_HANDLE endorsement_session_handle = 0;
  string     endorsementAuth;
#ifdef DEBUG1
  printf("\nCalling create_endorsement_session\n");
#endif
  nonce.clear();
  if (!create_endorsement_session(tpm,
                                  authString,
                                  &nonce,
                                  &endorsement_session_handle)) {
    printf("%s() error, line %d, create_endorsement _session failed\n",
           __func__,
           __LINE__);
    Tpm2_FlushContext(tpm, ek_handle);
    Tpm2_FlushContext(tpm, quote_handle);
    return false;
  }

  // endorsement auth
  n = 0;
  byte_t *cur = auth_buf;
  change_endian32((uint32_t *)&endorsement_session_handle, (uint32_t *)cur);
  cur += sizeof(uint32_t);
  n += sizeof(uint32_t);
  n += 1;
  uint16_t t = nonce.size();
  change_endian16(&t, (uint16_t *)cur);
  cur += sizeof(uint16_t);
  n += sizeof(uint16_t);
  memcpy(cur, (byte_t *)nonce.data(), t);
  cur += t;
  n += t;
  *cur = 1;
  cur += 1;
  *((uint16_t *)cur) = 0;
  cur += sizeof(uint16_t);
  n += sizeof(uint16_t);
  endorsementAuth.assign((char *)auth_buf, n);

#ifdef DEBUG2
  printf("Endorsement session handle: %08x\n", endorsement_session_handle);
  printf("Endorsement auth: ");
  print_bytes(endorsementAuth.size(), (byte_t *)endorsementAuth.data());
  printf("\n");
  printf("Nonce (%d): ", (int)nonce.size());
  print_bytes(nonce.size(), (byte_t *)nonce.data());
  printf("\n");
  int    num_pcrs = 1;
  byte_t pcrs[1] = {7};
  printf("PCRs at activate:\n");
  print_pcrs(tpm, num_pcrs, pcrs);
  printf("\n");
#endif

#ifndef INTERNALTPMMAKECRED

  if (!Tpm2_ActivateCredential(tpm,
                               quote_handle,
                               ek_handle,
                               quoteAuth,
                               endorsementAuth,
                               credentialBlob,
                               secret,
                               &recovered_credential)) {
    printf("%s() error, line %d, Tpm2_ActivateCredential failed\n",
           __func__,
           __LINE__);
    Tpm2_FlushContext(tpm, ek_handle);
    Tpm2_FlushContext(tpm, endorsement_session_handle);
    return false;
  }

#  ifdef DEBUG
  printf("ActivateCredential succeeded\n");
  printf("Recovered credential (%d): ", recovered_credential.size);
  print_bytes(recovered_credential.size, recovered_credential.buffer);
  printf("\n");
#  endif
#endif  // INTERNALTPMMAKECRED

  // Standalone makecredential
  string endorsement_cert;
  if (!get_endorsement_cert(tpm, &endorsement_cert)) {
    printf("%s() error, line %d, create_endorsement _session failed\n",
           __func__,
           __LINE__);
    return false;
  }
#ifdef DEBUG
  printf("get_endorsement_cert succeeded\n");
#endif

  // make_credential
  string quote_key_name;
  quote_key_name.assign((char *)quoting_pub_name.name, quoting_pub_name.size);
  string cred;
  string cred_blob_out;
  string encrypted_secret_out;
  cred.assign((char *)credential.buffer, credential.size);
  if (!make_credential(quoting_pub_out,
                       quote_key_name,
                       endorsement_cert,
                       cred,
                       &cred_blob_out,
                       &encrypted_secret_out)) {
    printf("make_credential failed\n");
    return false;
  }

  TPM2B_ID_OBJECT        cred_blob;
  TPM2B_ENCRYPTED_SECRET cred_secret;
  TPM2B_DIGEST           recovered_cred;

  memset((void *)&cred_secret, 0, sizeof(TPM2B_ENCRYPTED_SECRET));
  memset((void *)&cred_blob, 0, sizeof(TPM2B_ID_OBJECT));
  memset((void *)&recovered_cred, 0, sizeof(TPM2B_DIGEST));

  cred_blob.size = cred_blob_out.size();
  memcpy(cred_blob.credential, (byte_t *)cred_blob_out.data(), cred_blob.size);
  cred_secret.size = encrypted_secret_out.size();
  memcpy(cred_secret.secret,
         (byte_t *)encrypted_secret_out.data(),
         encrypted_secret_out.size());

#ifdef DEBUG2
  printf("\nStandalone MakeCredential succeeded\n");
  printf("\ncred_secret size: %d\n", cred_secret.size);
  print_bytes(cred_secret.size, cred_secret.secret);
  printf("\n");
  printf("\ncredBlob size: %d\n", (int)cred_blob.size);
  print_bytes(cred_blob.size, (byte_t *)cred_blob.credential);
  printf("\n");
#endif

#ifdef INTERNALTPMMAKECRED
  if (!Tpm2_ActivateCredential(tpm,
                               quote_handle,
                               ek_handle,
                               quoteAuth,
                               endorsementAuth,
                               cred_blob,
                               cred_secret,
                               &recovered_cred)) {
    printf("%s() error, line %d, Tpm2_ActivateCredential failed\n",
           __func__,
           __LINE__);
    Tpm2_FlushContext(tpm, ek_handle);
    Tpm2_FlushContext(tpm, endorsement_session_handle);
    return false;
  }

#  ifdef DEBUG
  printf("\nActivateCredential succeeded with internal MakeCredential\n");
  printf("Recovered credential (%d): ", recovered_cred.size);
  print_bytes(recovered_cred.size, recovered_cred.buffer);
  printf("\n");
#  endif
#endif


  Tpm2_FlushContext(tpm, ek_handle);
  Tpm2_FlushContext(tpm, endorsement_session_handle);
  return true;
}

// ------------------------------------------------------------------------

extern byte_t g_policy_rsa_2048[32];
extern byte_t g_policy_rsa_3072[48];

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
  printf("\n");
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

  if (!local_tpm_attest(quote_handle,
                        TPM_ALG_SHA256,
                        srk_handle,
                        num_pcrs,
                        pcrs,
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
#ifdef DEBUG
  printf("\ndo_quote succeeded\n");
#endif

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
  }

#ifdef DEBUG
  printf("\nQuote Key\n");
  printf("  Pubout size: %d\n", pub_out.size);
  printf("  Type: %d\n", pub_out.publicArea.type);
  printf("  Hash Alg name: %x\n", pub_out.publicArea.nameAlg);
  printf("  Scheme: %02x\n",
         pub_out.publicArea.parameters.rsaDetail.scheme.scheme);
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
  rsa->set_public_modulus(pub_out.publicArea.unique.rsa.buffer, n);
  rsa->set_public_exponent((byte_t *)&le_exp, sizeof(uint32_t));

  string hash_alg_name;
  string sig_scheme_name;

  switch (pub_out.publicArea.nameAlg) {
    default:
      printf("%s() error, line: %d, bad modulus size failed\n",
             __func__,
             __LINE__);
      Tpm2_FlushContext(tpm, quote_handle);
      Tpm2_FlushContext(tpm, srk_handle);
      return false;
    case TPM_ALG_SHA256:
      hash_alg_name.assign(Digest_method_sha_256);
      break;
    case TPM_ALG_SHA384:
      hash_alg_name.assign(Digest_method_sha_384);
      break;
    case TPM_ALG_SHA512:
      hash_alg_name.assign(Digest_method_sha_512);
      break;
  }

  switch (pub_out.publicArea.parameters.rsaDetail.scheme.scheme) {
    default:
      printf("%s() error, line: %d, bad modulus size failed\n",
             __func__,
             __LINE__);
      Tpm2_FlushContext(tpm, quote_handle);
      Tpm2_FlushContext(tpm, srk_handle);
      return false;
    case TPM_ALG_RSASSA:
      sig_scheme_name.assign("ssa");
      break;
    case TPM_ALG_RSAPSS:
      sig_scheme_name.assign("pss");
      break;
    case TPM_ALG_OAEP:
      sig_scheme_name.assign("oaep");
      break;
  }

  if (!tpm_Verify(quote_key,
                  to_quote,
                  quoted,
                  hash_alg_name,
                  sig_scheme_name,
                  signature)) {
    printf("%s() error, line: %d, Cant verify quote\n", __func__, __LINE__);
    Tpm2_FlushContext(tpm, quote_handle);
    Tpm2_FlushContext(tpm, srk_handle);
    return true;
  }
#ifdef DEBUG
  printf("\ntpm_verify_attest suceeded\n");
#endif

  // Make/Activate Credential test
  TPML_PCR_SELECTION pcrSelect;
  memset((void *)&pcrSelect, 0, sizeof(TPML_PCR_SELECTION));
  string policyString;

  if (num_pcrs < 1) {
    printf("%s() error, line %d: No pcrs\n", __func__, __LINE__);
    return false;
  }
  init_single_pcr_selection(pcrs[0], TPM_ALG_SHA256, &pcrSelect);
  for (int i = 1; i < num_pcrs; i++) {
    add_pcr_selection(pcrs[i], TPM_ALG_SHA256, &pcrSelect);
  }

#ifdef DEBUG
  printf("PCRs: \n");
  print_pcrs(tpm, num_pcrs, pcrs);
#endif

  if (!credential_test(tpm, pcrSelect, srk_handle, quote_handle)) {
    printf("%s() error, line %d, credential_test failed\n", __func__, __LINE__);
    return false;
  }

  Tpm2_FlushContext(tpm, quote_handle);
  Tpm2_FlushContext(tpm, srk_handle);

  return true;
}

bool misc_test() {

  TPM_ALG_ID hash_alg_id = TPM_ALG_SHA256;
  string     label;
  string     key;
  string     contextU;
  string     contextV;
  string     name;
  int        num_key_bits = 256;
  label = "INTEGRITY";
  string out_key;
  string reverse_key;

  /*
   * Alg: Sha256
   * Seed: 74f00e256647f2320c9d12738a5105461bd1fa1478f125380133adcb5d2b683b
   * Label: 494e54454752495459
   * ContextU: <EMPTY>
   * ContextV: <EMPTY>
   * NumBits: 256
   * KDFa: 9ccdf13dae82d3f8ea435d89e1ea34ad33875be71016d21078579f9a6bf99507
   */
  int    size_seed = 32;
  byte_t seed[size_seed] = {0x74, 0xf0, 0x0e, 0x25, 0x66, 0x47, 0xf2, 0x32,
                            0x0c, 0x9d, 0x12, 0x73, 0x8a, 0x51, 0x05, 0x46,
                            0x1b, 0xd1, 0xfa, 0x14, 0x78, 0xf1, 0x25, 0x38,
                            0x01, 0x33, 0xad, 0xcb, 0x5d, 0x2b, 0x68, 0x3b};
  key.assign((char *)seed, size_seed);
  contextU.clear();
  contextV.clear();
  int    size_real_kdfa = 32;
  byte_t real_kdfa[size_real_kdfa] = {
      0x9c, 0xcd, 0xf1, 0x3d, 0xae, 0x82, 0xd3, 0xf8, 0xea, 0x43, 0x5d,
      0x89, 0xe1, 0xea, 0x34, 0xad, 0x33, 0x87, 0x5b, 0xe7, 0x10, 0x16,
      0xd2, 0x10, 0x78, 0x57, 0x9f, 0x9a, 0x6b, 0xf9, 0x95, 0x07};

  int    size_rev_key = 32;
  byte_t rev_key[size_rev_key];
  reverse_byte_copy(key.size(), (byte_t *)key.data(), rev_key);
  reverse_key.assign((char *)rev_key, size_rev_key);

  if (!kdfa(hash_alg_id,
            key,
            label,
            contextU,
            contextV,
            num_key_bits,
            &out_key)) {
    printf("%s() error, line %d, Can't calculate kdfa\n", __func__, __LINE__);
    return false;
  }

  printf("Alg          : %02x\n", hash_alg_id);
  printf("Label        : %s\n", label.c_str());
  printf("Num bits     : %08x\n", num_key_bits);
  printf("key          : ");
  print_bytes(key.size(), (byte_t *)key.data());
  printf("\n");
  printf("contextU     : ");
  print_bytes(contextU.size(), (byte_t *)contextU.data());
  printf("\n");
  printf("contextV     : ");
  print_bytes(contextV.size(), (byte_t *)contextV.data());
  printf("\n");
  printf("kdfa         : ");
  print_bytes(out_key.size(), (byte_t *)out_key.data());
  printf("\n");
  printf("correct      : ");
  print_bytes(size_real_kdfa, real_kdfa);
  printf("\n");

  return memcmp(real_kdfa, (byte_t *)out_key.data(), size_real_kdfa) == 0;
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
                         policyString,
                         pcrSelect,
                         TPM_ALG_RSA,
                         TPM_ALG_SHA256,
                         primary_flags,
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

/*
 * TPM_HANDLE g_ek_handle = 0;
 * TPM_HANDLE g_srk_handle = 0;
 * TPM_HANDLE g_quote_handle = 0;
 * int          g_seal_key_type;
 * string       g_seal_key;
 * string       g_endorsement_cert;
 * string       g_endorsement_cert_file_name;
 * string       g_seal_hierarchy_file_name;
 * string       g_quote_hierarchy_file_name;
 * string       g_seal_thing;
 * int          g_num_pcrs;
 * byte_t       g_pcrs[32];
 * TPM2B_PUBLIC g_public_quote_key;
 * TPM2B_PUBLIC g_public_endorsement_key;
 */
bool certifier_test() {
  int           num_pcrs = 1;
  byte_t        pcrs[1] = {7};
  extern string g_seal_thing;
  extern string g_endorsement_cert;

  if (!tpm_Init(FLAGS_tpm_device,
                FLAGS_ek_cert_file_name,
                FLAGS_seal_hierearchy_name,
                FLAGS_quote_hierearchy_name,
                num_pcrs,
                pcrs)) {
    printf("%s() error, line %d, tpm_init failed\n", __func__, __LINE__);
    tpm_close();
    return false;
  }

#ifdef DEBUG
  X509 *cert = X509_new();
  asn1_to_x509(g_endorsement_cert, cert);
  printf("\nEndorsement Cert\n");
  X509_print_fp(stdout, cert);
  printf("\n");
  printf("\nSeal key: ");
  print_bytes((int)g_seal_thing.size(), (byte_t *)g_seal_thing.data());
  printf("\n");
  printf("\n");
  X509_free(cert);
#endif

  int    to_seal_size = 16;
  byte_t b_to_seal[to_seal_size] = {
      0xff,
      0xfe,
      0xfd,
      0xfc,
      0xfb,
      0xfa,
      0xf0,
      0xef,
      0x00,
      0x01,
      0x02,
      0x03,
      0x13,
      0x12,
      0x11,
      0x10,
  };
  string to_seal;
  string sealed;
  string unsealed;

  to_seal.assign((char *)b_to_seal, to_seal_size);

  if (!tpm_Seal(to_seal, &sealed)) {
    printf("%s() error, line %d, seal failed\n", __func__, __LINE__);
    tpm_close();
    return false;
  }
  if (!tpm_Unseal(sealed, &unsealed)) {
    printf("%s() error, line %d, unseal failed\n", __func__, __LINE__);
    tpm_close();
    return false;
  }

#ifdef DEBUG
  printf("\n");
  printf("to_seal  : ");
  print_bytes(to_seal.size(), (byte_t *)to_seal.data());
  printf("\n");
  printf("sealed   : ");
  print_bytes(sealed.size(), (byte_t *)sealed.data());
  printf("\n");
  printf("unsealed : ");
  print_bytes(unsealed.size(), (byte_t *)unsealed.data());
  printf("\n");
  printf("\n");
#endif

  if (memcmp((byte_t *)to_seal.data(),
             (byte_t *)unsealed.data(),
             to_seal.size())
      != 0) {
    printf("%s() error, line %d, to_seal and unsealed not equal\n",
           __func__,
           __LINE__);
    tpm_close();
    return false;
  }

  string to_quote("I am a quote");
  string quoted;
  string signature;

  if (!tpm_Attest(to_quote, &quoted, &signature)) {
    printf("%s() error, line %d, tpm_attest failed\n", __func__, __LINE__);
    tpm_close();
    return false;
  }

  string              hash_alg_name(Digest_method_sha_256);
  string              sig_scheme_name;
  extern TPM2B_PUBLIC g_public_quote_key;
  switch (g_public_quote_key.publicArea.parameters.rsaDetail.scheme.scheme) {
    default:
      printf("%s() error, line: %d, bad scheme\n", __func__, __LINE__);
      tpm_close();
      return false;
    case TPM_ALG_RSASSA:
      sig_scheme_name.assign("ssa");
      break;
    case TPM_ALG_RSAPSS:
      sig_scheme_name.assign("pss");
      break;
    case TPM_ALG_OAEP:
      sig_scheme_name.assign("oaep");
      break;
  }

  key_message quote_key;

  int n = (int)g_public_quote_key.publicArea.unique.rsa.size;
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
    tpm_close();
    return false;
  }
  rsa_message *rsa = new (rsa_message);
  quote_key.set_allocated_rsa_key(rsa);
  uint32_t le_exp;

  change_endian32(
      (uint32_t *)&g_public_quote_key.publicArea.parameters.rsaDetail.exponent,
      (uint32_t *)&le_exp);

  quote_key.set_key_name("quote-key-tpm");
  quote_key.set_key_format("vse-key");
  rsa->set_public_modulus(g_public_quote_key.publicArea.unique.rsa.buffer, n);
  rsa->set_public_exponent((byte_t *)&le_exp, sizeof(uint32_t));

  if (!tpm_Verify(quote_key,
                  to_quote,
                  quoted,
                  hash_alg_name,
                  sig_scheme_name,
                  signature)) {
    printf("%s() error, line: %d, Cant verify quote\n", __func__, __LINE__);
    tpm_close();
    return false;
  }
#ifdef DEBUG
  printf("Quote verified\n");
#endif

  if (!tpm_close()) {
    printf("%s() error, line %d, tpm_close failed\n", __func__, __LINE__);
    return false;
  }
  return true;
}

// ------------------------------------------------------------------------

int main(int an, char **av) {

  GFLAGS_NS::ParseCommandLineFlags(&an, &av, true);

  if (!init_tpm(FLAGS_tpm_device)) {
    printf("%s() error, line %d, tpm_init failed\n", __func__, __LINE__);
    return false;
  }

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

  extern local_tpm g_tpm;
  string           authString;
  if (FLAGS_operation == "EndorsementTest") {
    printf("\n");
    if (endorsement_test(g_tpm, authString)) {
      printf("endorsement test succeeded\n");
    } else {
      printf("endorsement test failed\n");
    }
  } else if (FLAGS_operation == "SealTest") {
    printf("\n");
    if (seal_test(g_tpm, 7, FLAGS_seal_hierearchy_name)) {
      printf("seal test succeeded\n");
    } else {
      printf("seal test failed\n");
    }
  } else if (FLAGS_operation == "QuoteTest") {
    printf("\n");
    if (quote_test(g_tpm, FLAGS_quote_hierearchy_name)) {
      printf("quote test succeeded\n");
    } else {
      printf("quote test failed\n");
    }
  } else if (FLAGS_operation == "ContextTest") {
    printf("\n");
    if (context_test(g_tpm)) {
      printf("context test succeeded\n");
    } else {
      printf("context test failed\n");
    }
  } else if (FLAGS_operation == "NvTest") {
    printf("\n");
    if (nv_test(g_tpm)) {
      printf("nv test succeeded\n");
    } else {
      printf("nv test failed\n");
    }
  } else if (FLAGS_operation == "GetCert") {
    string cert;
    if (get_cert(g_tpm, FLAGS_ek_cert_file_name, &cert)) {
      printf("get cert test succeeded\n");
    } else {
      printf("get cert test failed\n");
    }
  } else if (FLAGS_operation == "MiscTest") {
    printf("\n");
    if (misc_test()) {
      printf("misc test succeeded\n");
    } else {
      printf("misc test failed\n");
    }
  } else if (FLAGS_operation == "CertifierTest") {
    printf("\n");
    if (certifier_test()) {
      printf("certifier test succeeded\n");
    } else {
      printf("certifier test failed\n");
    }
  } else {
    printf("\n");
    printf("No such operation (%s)\n", FLAGS_operation.c_str());
  }

  close_tpm();
  return 0;
}
