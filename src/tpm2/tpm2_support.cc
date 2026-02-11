#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include <tpm2_support.h>
#include <gflags/gflags.h>

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
// File: tpm2_support.cc

#define MAX_SIZE_PARAMS 16384
#define DEBUG

void print_mask(int n, byte *m) {
  byte *p = m + n - 1;
  while (n-- > 0)
    printf("%02x", *(p--));
}

bool print_pcrs(local_tpm &tpm, int num_pcrs, byte *pcrs) {
  TPML_PCR_SELECTION pcrSelect;
  memset((void *)&pcrSelect, 0, sizeof(TPML_PCR_SELECTION));

  if (num_pcrs < 1) {
    printf("%s() error, line %d: No pcrs\n", __func__, __LINE__);
    return false;
  }
  init_single_pcr_selection(pcrs[0], TPM_ALG_SHA256, &pcrSelect);
  for (int i = 1; i < num_pcrs; i++) {
    add_pcr_selection(pcrs[i], TPM_ALG_SHA256, &pcrSelect);
  }

  uint32_t           upCounters = 0;
  TPML_PCR_SELECTION pcrSelectOut;
  memset((void *)&pcrSelectOut, 0, sizeof(TPML_PCR_SELECTION));
  TPML_DIGEST the_digests;

  if (!Tpm2_ReadPcrs(tpm,
                     pcrSelect,
                     &upCounters,
                     &pcrSelectOut,
                     &the_digests)) {
    printf("%s() error, line %d, Tpm2_ReadPcrs failed\n", __func__, __LINE__);
    return false;
  }
  printf("Tpm2_ReadPcrs succeeded %d entries\n", pcrSelectOut.count);
  for (int i = 0; i < (int)pcrSelectOut.count; i++) {
    printf("  hash: %04x, size: %d, ",
           pcrSelectOut.pcrSelections[i].hash,
           pcrSelectOut.pcrSelections[i].sizeofSelect);
    printf("mask: ");
    print_mask(5, pcrSelectOut.pcrSelections[i].pcrSelect);
    printf(", value: ");
    print_bytes(the_digests.digests[i].size, the_digests.digests[i].buffer);
    printf("\n");
  }
  printf("\n");
  return true;
}

bool create_pcr_policy(local_tpm    &tpm,
                       int           num_pcrs,
                       byte_t       *pcrs,
                       TPM2B_DIGEST *policy_out) {

  TPM_HANDLE         session_handle;
  TPML_PCR_SELECTION pcrSelect;
  memset((void *)&pcrSelect, 0, sizeof(TPML_PCR_SELECTION));

  TPM2B_NONCE            initial_nonce;
  TPM2B_ENCRYPTED_SECRET salt;
  TPMT_SYM_DEF           symmetric;
  TPM2B_NONCE            nonce_obj;

  if (num_pcrs < 1) {
    printf("%s() error, line %d: No pcrs\n", __func__, __LINE__);
    return false;
  }
  init_single_pcr_selection(pcrs[0], TPM_ALG_SHA256, &pcrSelect);
  for (int i = 1; i < num_pcrs; i++) {
    add_pcr_selection(pcrs[i], TPM_ALG_SHA256, &pcrSelect);
  }

  initial_nonce.size = 32;
  memset(initial_nonce.buffer, 0, initial_nonce.size);
  salt.size = 0;
  symmetric.algorithm = TPM_ALG_NULL;

  // Start auth session
  if (!Tpm2_StartAuthSession(tpm,
                             TPM_RH_NULL,
                             TPM_RH_NULL,
                             initial_nonce,
                             salt,
                             TPM_SE_POLICY,
                             symmetric,
                             TPM_ALG_SHA256,
                             &session_handle,
                             &nonce_obj)) {
    printf("\n");
    printf("%s() error, line %d, Tpm2_StartAuthSession fails\n",
           __func__,
           __LINE__);
    return false;
  }
#ifdef DEBUG
  printf("Tpm2_StartAuthSession succeeded\n");
#endif

  TPM2B_DIGEST expected_digest;
  expected_digest.size = 0;
  if (!Tpm2_PolicyPcr(tpm, session_handle, expected_digest, pcrSelect)) {
    printf("%s() error, line %d, Tpm2_StartAuthSession fails\n",
           __func__,
           __LINE__);
    Tpm2_FlushContext(tpm, session_handle);
    return false;
  }
#ifdef DEBUG
  printf("%s(), line %d, Tpm2_PolicyPcr succeeded\n", __func__, __LINE__);
#endif

  TPM2B_DIGEST policy_digest;
  if (!Tpm2_PolicyGetDigest(tpm, session_handle, policy_out)) {
    printf("%s() error, line %d, PolicyGetDigest failed\n", __func__, __LINE__);
    Tpm2_FlushContext(tpm, session_handle);
    return false;
  }
#ifdef DEBUG
  printf("%s() line %d, PolicyGetDigest before Pcr succeeded: \n",
         __func__,
         __LINE__);
  print_bytes(policy_out->size, policy_out->buffer);
  printf("\n");
#endif

  Tpm2_FlushContext(tpm, session_handle);
  return true;
}

bool create_seal_session(local_tpm          &tpm,
                         TPML_PCR_SELECTION &pcrSelect,
                         TPM_HANDLE         *session_handle) {

  TPM2B_DIGEST           digest_out;
  TPM2B_NONCE            initial_nonce;
  TPM2B_ENCRYPTED_SECRET salt;
  TPMT_SYM_DEF           symmetric;
  TPM2B_NONCE            nonce_obj;

  initial_nonce.size = 32;
  memset(initial_nonce.buffer, 0, initial_nonce.size);
  salt.size = 0;
  symmetric.algorithm = TPM_ALG_NULL;

  // Start auth session
  if (!Tpm2_StartAuthSession(tpm,
                             TPM_RH_NULL,
                             TPM_RH_NULL,
                             initial_nonce,
                             salt,
                             TPM_SE_POLICY,
                             symmetric,
                             TPM_ALG_SHA256,
                             session_handle,
                             &nonce_obj)) {
    printf("\n");
    printf("%s() error, line %d, Tpm2_StartAuthSession fails\n",
           __func__,
           __LINE__);
    return false;
  }
#ifdef DEBUG2
  printf("\n");
  printf("Tpm2_StartAuthSession succeeds handle: %08x\n", *session_handle);
  printf("initial nonce (%d): ", initial_nonce.size);
  print_bytes(initial_nonce.size, initial_nonce.buffer);
  printf("\n");
  printf("nonce (%d): ", nonce_obj.size);
  print_bytes(nonce_obj.size, nonce_obj.buffer);
  printf("\n");
#endif

  TPM2B_DIGEST policy_digest;
  if (!Tpm2_PolicyGetDigest(tpm, *session_handle, &policy_digest)) {
    printf("%s() error, line %d, PolicyGetDigest failed\n", __func__, __LINE__);
    Tpm2_FlushContext(tpm, *session_handle);
    return false;
  }
#ifdef DEBUG2
  printf("\n");
  printf("%s() line %d, PolicyGetDigest before Pcr succeeded: \n",
         __func__,
         __LINE__);
  print_bytes(policy_digest.size, policy_digest.buffer);
  printf("\n");
#endif

  if (!Tpm2_PolicyPassword(tpm, *session_handle)) {
    printf("%s() error, line %d, Tpm2_PolicyPassword fails\n",
           __func__,
           __LINE__);
    Tpm2_FlushContext(tpm, *session_handle);
    return false;
  }
#ifdef DEBUG2
  printf("%s(), line %d, Tpm2_PolicyPassword succeeded\n", __func__, __LINE__);
#endif

  TPM2B_DIGEST expected_digest;
  expected_digest.size = 0;
  if (!Tpm2_PolicyPcr(tpm, *session_handle, expected_digest, pcrSelect)) {
    printf("%s() error, line %d, Tpm2_StartAuthSession fails\n",
           __func__,
           __LINE__);
    Tpm2_FlushContext(tpm, *session_handle);
    return false;
  }
#ifdef DEBUG2
  printf("%s(), line %d, Tpm2_PolicyPcr succeeded\n", __func__, __LINE__);
#endif

  return true;
}

bool create_seal_hierarchy_and_secret(local_tpm    &tpm,
                                      int           num_pcrs,
                                      byte_t       *pcrs,
                                      const string &seal_file) {

  string             srkAuth;
  string             sealAuth;
  string             emptyAuth;
  TPM2B_PUBLIC       pub_out;
  TPML_PCR_SELECTION pcrSelect;
  memset((void *)&pcrSelect, 0, sizeof(TPML_PCR_SELECTION));

  TPM_HANDLE srk_handle;

  if (num_pcrs < 1) {
    printf("%s() error, line %d: No pcrs\n", __func__, __LINE__);
    return false;
  }
  init_single_pcr_selection(pcrs[0], TPM_ALG_SHA256, &pcrSelect);
  for (int i = 1; i < num_pcrs; i++) {
    add_pcr_selection(pcrs[i], TPM_ALG_SHA256, &pcrSelect);
  }

  TPMA_OBJECT primary_flags;
  *(uint32_t *)(&primary_flags) = 0;
  primary_flags.fixedTPM = 1;
  primary_flags.fixedParent = 1;
  primary_flags.sensitiveDataOrigin = 1;
  primary_flags.userWithAuth = 1;
  primary_flags.decrypt = 1;
  primary_flags.restricted = 1;

  // Creating a new SRK
  if (!Tpm2_CreatePrimary(tpm,
                          TPM_RH_OWNER,
                          srkAuth,
                          pcrSelect,
                          TPM_ALG_RSA,
                          TPM_ALG_SHA256,
                          primary_flags,
                          TPM_ALG_AES,
                          256,
                          TPM_ALG_CFB,
                          TPM_ALG_NULL,
                          2048,
                          0x010001,
                          &srk_handle,
                          &pub_out)) {
    printf("%s() error, line %d, CreatePrimary failed\n", __func__, __LINE__);
  }
#ifdef DEBUG2
  printf("\n");
  printf("%s() line %d, CreatePrimary succeeded\n", __func__, __LINE__);
#endif

  TPM2B_DIGEST secret;
  secret.size = 32;
  if (!Tpm2_GetRandom(tpm, secret.size, secret.buffer)) {
    printf("\n");
    printf("%s() error, line %d, Can't get random key\n", __func__, __LINE__);
    return false;
  }
#ifdef DEBUG
  printf("Secret: ");
  print_bytes(secret.size, secret.buffer);
  printf("\n");
#endif

  TPM2B_DIGEST digest_out;
  TPM2B_NONCE  initial_nonce;
  TPM2B_NONCE  nonce_obj;
  TPM_HANDLE   session_handle;

  initial_nonce.size = 32;
  memset(initial_nonce.buffer, 0, initial_nonce.size);

  if (!create_seal_session(tpm, pcrSelect, &session_handle)) {
    printf("\n");
    printf("%s() error, line %d, create_seal_session failed\n",
           __func__,
           __LINE__);
    return false;
  }
#ifdef DEBUG2
  printf("Seal session succeeded\n");
#endif

  // Get policy digest
  TPM2B_DIGEST policy_digest;
  if (!Tpm2_PolicyGetDigest(tpm, session_handle, &policy_digest)) {
    printf("\n");
    printf("%s() error, line %d, Tpm2_PolicyGetDigest failed\n",
           __func__,
           __LINE__);
    return false;
  }
#ifdef DEBUG2
  printf("Policy Digest: ");
  print_bytes(policy_digest.size, policy_digest.buffer);
  printf("\n");
  printf("\n");
#endif

  // Creating new sealed key
  TPM2B_CREATION_DATA creation_out;
  TPMT_TK_CREATION    creation_ticket;
  int                 size_public = MAX_SIZE_PARAMS;
  byte_t              out_public[MAX_SIZE_PARAMS];
  int                 size_private = MAX_SIZE_PARAMS;
  byte_t              out_private[MAX_SIZE_PARAMS];

  TPMA_OBJECT create_flags;
  *(uint32_t *)(&create_flags) = 0;
  create_flags.fixedTPM = 1;
  create_flags.fixedParent = 1;

  if (!Tpm2_CreateSealed(tpm,
                         srk_handle,
                         policy_digest.size,
                         policy_digest.buffer,
                         sealAuth,
                         secret.size,
                         secret.buffer,
                         pcrSelect,
                         TPM_ALG_SHA256,
                         create_flags,
                         TPM_ALG_NULL,
                         (TPMI_AES_KEY_BITS)0,
                         TPM_ALG_ECB,
                         TPM_ALG_RSASSA,
                         2048,
                         0x010001,
                         &size_public,
                         out_public,
                         &size_private,
                         out_private,
                         &creation_out,
                         &digest_out,
                         &creation_ticket)) {
    printf("%s() error, line %d, Create with digest failed\n",
           __func__,
           __LINE__);
    Tpm2_FlushContext(tpm, session_handle);
    return false;
  }
#ifdef DEBUG2
  printf("\n");
  printf("Create with digest succeeded private size: %d, public size: %d\n",
         size_private,
         size_public);
#endif

  // Save the stuff for load
  tpm_load_key_info key_info;

  key_info.set_hierarchy_name("Seal-Key-Hierarchy");

  // See the note in create quote hierarchy
  key_info.set_pub_key((byte_t *)out_public, size_public + 2);
  key_info.set_priv_key((byte_t *)out_private, size_private + 2);

#ifdef DEBUG2
  printf("After creation private size: %d, public size: %d\n",
         size_private,
         size_public);
#endif

  string serialized_key_info;
  if (!key_info.SerializeToString(&serialized_key_info)) {
    printf("\n");
    printf("%s() error, line: %d, Can't serialize key_info\n",
           __func__,
           __LINE__);
    return false;
  }
  if (!write_file_from_string(seal_file, serialized_key_info)) {
    printf("\n");
    printf("%s() error, line: %d, Can't writ key_inf file %s\n",
           __func__,
           __LINE__,
           seal_file.c_str());
    return false;
  }
  Tpm2_FlushContext(tpm, session_handle);
  Tpm2_FlushContext(tpm, srk_handle);
  return true;
}

bool recover_sealing_secret(local_tpm    &tpm,
                            int           num_pcrs,
                            byte_t       *pcrs,
                            const string &file_name,
                            string       *seal_secret) {

  string srkAuth;
  string sealAuth;

  TPM2B_PUBLIC       pub_out;
  TPML_PCR_SELECTION pcrSelect;
  memset((void *)&pcrSelect, 0, sizeof(TPML_PCR_SELECTION));

  TPM_HANDLE srk_handle;
  TPM_HANDLE seal_handle;
  TPM_HANDLE session_handle;

  if (num_pcrs < 1) {
    printf("\n");
    printf("%s() error, line %d: No pcrs\n", __func__, __LINE__);
    return false;
  }
  init_single_pcr_selection(pcrs[0], TPM_ALG_SHA256, &pcrSelect);
  for (int i = 1; i < num_pcrs; i++) {
    add_pcr_selection(pcrs[i], TPM_ALG_SHA256, &pcrSelect);
  }

  TPMA_OBJECT primary_flags;
  *(uint32_t *)(&primary_flags) = 0;
  primary_flags.fixedTPM = 1;
  primary_flags.fixedParent = 1;
  primary_flags.sensitiveDataOrigin = 1;
  primary_flags.userWithAuth = 1;
  primary_flags.decrypt = 1;
  primary_flags.restricted = 1;

  // Creating a new SRK
  if (!Tpm2_CreatePrimary(tpm,
                          TPM_RH_OWNER,
                          srkAuth,
                          pcrSelect,
                          TPM_ALG_RSA,
                          TPM_ALG_SHA256,
                          primary_flags,
                          TPM_ALG_AES,
                          256,
                          TPM_ALG_CFB,
                          TPM_ALG_NULL,
                          2048,
                          0x010001,
                          &srk_handle,
                          &pub_out)) {
    printf("%s() error, line %d, CreatePrimary failed\n", __func__, __LINE__);
    return false;
  }
#ifdef DEBUG2
  printf("%s() line %d, CreatePrimary succeeded\n", __func__, __LINE__);
#endif

  // Get info for load
  tpm_load_key_info key_info;
  string            serialized_key_info;

  if (!read_file_into_string(file_name, &serialized_key_info)) {
    printf("%s() error, line %d, Can't read seal file %s\n",
           __func__,
           __LINE__,
           file_name.c_str());
    return false;
  }
  if (!key_info.ParseFromString(serialized_key_info)) {
    printf("%s() error, line: %d, Can't deserialize key_info\n",
           __func__,
           __LINE__);
    return false;
  }

#ifdef DEBUG2
  printf("After recovery private size: %d, public size: %d\n",
         (int)key_info.priv_key().size(),
         (int)key_info.pub_key().size());
#endif
  TPM2B_NAME name;
  if (!Tpm2_Load(tpm,
                 srk_handle,
                 sealAuth,
                 key_info.pub_key().size() - 2,
                 (byte_t *)key_info.pub_key().data(),
                 key_info.priv_key().size() - 2,
                 (byte_t *)key_info.priv_key().data(),
                 &seal_handle,
                 &name)) {
    printf("\n");
    printf("%s() error, line %d, Load failed\n", __func__, __LINE__);
    Tpm2_FlushContext(tpm, srk_handle);
    return false;
  }
#ifdef DEBUG2
  printf("Load succeeded\n");
#endif

  if (!create_seal_session(tpm, pcrSelect, &session_handle)) {
    printf("%s() error, line %d, create_seal_session failed\n",
           __func__,
           __LINE__);
    Tpm2_FlushContext(tpm, seal_handle);
    Tpm2_FlushContext(tpm, srk_handle);
    return false;
  }

  int          unsealed_size = MAX_SIZE_PARAMS;
  byte_t       unsealed[MAX_SIZE_PARAMS];
  TPM2B_DIGEST hmac;
  TPM2B_NONCE  nonce_obj;
  hmac.size = 0;
  if (!Tpm2_Unseal(tpm,
                   seal_handle,
                   sealAuth,
                   session_handle,
                   nonce_obj,
                   0x01,
                   hmac,
                   &unsealed_size,
                   unsealed)) {
    printf("%s() error, line %d, unseal failed\n", __func__, __LINE__);
    Tpm2_FlushContext(tpm, session_handle);
    Tpm2_FlushContext(tpm, seal_handle);
    Tpm2_FlushContext(tpm, srk_handle);
    return false;
  }
#ifdef DEBUG
  printf("Unseal succeeded, unsealed (%d): ", unsealed_size);
  print_bytes(unsealed_size, unsealed);
  printf("\n");
#endif

  TPM2B_SENSITIVE_DATA *unsealed_return =
      (TPM2B_SENSITIVE_DATA *)(&unsealed[2]);
#ifdef DEBUG2
  uint16_t ss;
  change_endian16(&unsealed_return->size, &ss);
  printf("Sensitive data size: %d\n", ss);
#endif
  TPM2B_DATA *sym = (TPM2B_DATA *)unsealed_return->buffer;
  uint16_t    sb;
  change_endian16(&(sym->size), &sb);
#ifdef DEBUG2
  printf("\n");
  printf("Buffer (%d): ", sb);
  print_bytes(sb, sym->buffer);
  printf("\n");
#endif
  seal_secret->assign((char *)sym->buffer, sb);

  Tpm2_FlushContext(tpm, session_handle);
  Tpm2_FlushContext(tpm, seal_handle);
  Tpm2_FlushContext(tpm, srk_handle);
  return true;
}

bool make_and_install_endorsement_cert(local_tpm &tpm,
                                       string    &signng_key_file,
                                       int        nv_slot,
                                       string    *cert_out) {
  // EK Certificate is at 0x01c00002 (RSA) or 0x01c0000a (ECC)
  // in nvram
  return true;
}

bool get_endorsement_key(local_tpm &tpm, TPM_HANDLE *ek_handle) {
  string emptyAuth;

  TPM2B_PUBLIC pub_out;
  TPM2B_NAME   pub_name;
  TPM2B_NAME   qualified_pub_name;
  uint16_t     pub_blob_size = 4096;
  byte_t       pub_blob[pub_blob_size];

  TPML_PCR_SELECTION pcrSelect;
  memset((void *)&pcrSelect, 0, sizeof(TPML_PCR_SELECTION));

  // TPM_RH_ENDORSEMENT
  TPMA_OBJECT primary_flags;
  *(uint32_t *)(&primary_flags) = 0;
  primary_flags.fixedTPM = 1;
  primary_flags.fixedParent = 1;
  primary_flags.sensitiveDataOrigin = 1;
  primary_flags.userWithAuth = 1;
  primary_flags.decrypt = 1;
  primary_flags.restricted = 1;

  // Create Endorsement key with handle ekHandle
  if (!Tpm2_CreatePrimary(tpm,
                          TPM_RH_ENDORSEMENT,
                          emptyAuth,
                          pcrSelect,
                          TPM_ALG_RSA,
                          TPM_ALG_SHA256,
                          primary_flags,
                          TPM_ALG_AES,
                          256,
                          TPM_ALG_CFB,
                          TPM_ALG_NULL,
                          2048,
                          0x010001,
                          ek_handle,
                          &pub_out)) {
    printf("%s() error, line %d, CreatePrimary failed\n", __func__, __LINE__);
    return false;
  }
#ifdef DEBUG
  printf("CreatePrimary succeeded primary: %08x\n", *ek_handle);
#endif

#ifdef DEBUG1
  if (!Tpm2_ReadPublic(tpm,
                       *ek_handle,
                       &pub_blob_size,
                       pub_blob,
                       &pub_out,
                       &pub_name,
                       &qualified_pub_name)) {
    printf("%s() error, line %d, ReadPublic failed\n", __func__, __LINE__);
    return false;
  }
  printf("Public blob: ");
  print_bytes(pub_blob_size, pub_blob);
  printf("\n");
  printf("Name: ");
  print_bytes(pub_name.size, pub_name.name);
  printf("\n");
  printf("Qualified name: ");
  print_bytes(qualified_pub_name.size, qualified_pub_name.name);
  printf("\n");
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
#endif

  return true;
}

bool get_endorsement_cert(const string &file_name, string *out) {
  return read_file_into_string(file_name, out);
}

bool get_endorsement_cert(local_tpm &tpm, string *out) {
  // EK Certificate is at 0x01c00002 (RSA) or 0x01c0000a (ECC)
  int handle = 0x01c00002;

  int    out_size = 2048;
  byte_t out_buf[out_size];
  string authString;

  if (!read_nv_handle(tpm, handle, authString, out)) {
    printf("%s() error, line %d, read_nv_handle failed\n", __func__, __LINE__);
    return false;
  }
  return true;
}

bool recover_endorsement_cert(const string &file_name) {
  return false;
}

bool save_endorsement_cert(const string &file_name) {
  return false;
}

bool save_context(local_tpm &tpm, TPM_HANDLE &handle, string *out) {
  uint16_t size = 4096;
  byte_t   saveArea[4096];
  string   authString;

  if (!Tpm2_SaveContext(tpm, handle, &size, saveArea)) {
    printf("%s() error, line %d, SaveContext failed\n", __func__, __LINE__);
    printf("Tpm2_SaveContext failed\n");
    return false;
  }
#ifdef DEBUG
  printf("Tpm2_SaveContext succeeds, save area %d\n", size);
#endif
  out->assign((char *)saveArea, size);
  return true;
}

bool load_context(local_tpm &tpm, TPM_HANDLE &handle, string &in) {
  if (Tpm2_LoadContext(tpm, in.size(), (byte_t *)in.data(), &handle)) {
    printf("%s() error, line %d, LoadContext failed\n", __func__, __LINE__);
    return false;
  }
#ifdef DEBUG
  printf("Tpm2_LoadContext succeeds, handle: %08x, save area size: %d\n",
         handle,
         (int)in.size());
#endif
  return true;
}

bool nv_increment_counter(local_tpm &tpm, int slot) {
  string     authString;
  TPM_HANDLE nv_handle = GetNvHandle(slot);

  if (Tpm2_UndefineSpace(tpm, TPM_RH_OWNER, nv_handle)) {
#ifdef DEBUG
    printf("Tpm2_UndefineSpace %d succeeds\n", slot);
#endif
  } else {
#ifdef DEBUG
    printf("Tpm2_UndefineSpace fails (but that's OK usually)\n");
#endif
  }

  // Should be AuthRead, AuthWrite, Counter, Sha256
  if (Tpm2_DefineSpace(tpm,
                       TPM_RH_OWNER,
                       nv_handle,
                       authString,
                       0,
                       nullptr,
                       NV_COUNTER | NV_AUTHWRITE | NV_AUTHREAD,
                       8)) {
    printf("Tpm2_DefineSpace %d succeeds\n", nv_handle);
  } else {
    printf("Tpm2_DefineSpace fails\n");
    return false;
  }
  if (!Tpm2_IncrementNv(tpm, nv_handle, authString)) {
    printf("%s() error, line %d, IncrementNv failed\n", __func__, __LINE__);
    return false;
  }

  return true;
}

bool read_nv_handle(local_tpm &tpm,
                    TPM_HANDLE handle,
                    string    &authString,
                    string    *out) {
  uint16_t size_data = 2048;
  byte_t   data_out[size_data];

  if (!Tpm2_ReadNv(tpm, handle, authString, &size_data, data_out)) {
    printf("%s() error, line %d, ReadNv failed, handle: %x\n",
           __func__,
           __LINE__,
           handle);
    return false;
  }
#ifdef DEBUG
  printf("Tpm2_ReadNv %d succeeds: ", handle);
  print_bytes(size_data, data_out);
  printf("\n");
#endif

  out->assign((char *)data_out, size_data);
  return true;
}

bool write_nv_handle(local_tpm &tpm,
                     TPM_HANDLE handle,
                     string    &authString,
                     string    &in) {

  if (!Tpm2_WriteNv(tpm, handle, authString, in.size(), (byte_t *)in.data())) {
    printf("%s() error, line %d, WriteNv failed\n", __func__, __LINE__);
    return false;
  }
#ifdef DEBUG
  printf("Tpm2_WriteNv %x succeeds, %d bytes written\n",
         handle,
         (int)in.size());
#endif

  return true;
}

bool read_nv_slot(local_tpm &tpm, int slot, string *out) {
  string   ekAuth;
  uint16_t size_data = 2048;
  byte_t   data_out[size_data];

  // Get endorsement key handle
  TPM_HANDLE   nv_handle = GetNvHandle(slot);

#if 0
  if (Tpm2_UndefineSpace(tpm, TPM_RH_OWNER, nv_handle)) {
#ifdef DEBUG
    printf("Tpm2_UndefineSpace %d succeeds\n", slot);
#endif
  } else {
#ifdef DEBUG
    printf("Tpm2_UndefineSpace fails (but that's OK usually)\n");
#endif
  }

  if (!Tpm2_DefineSpace(tpm,
                        TPM_RH_OWNER,
                        nv_handle,
                        ekAuth,
                        0,
                        nullptr,
                        NV_AUTHWRITE | NV_AUTHREAD,
                        size_data)) {
    printf("%s() error, line %d, DefineSpace failed\n", __func__, __LINE__);
    return false;
  }
#ifdef DEBUG
  printf("Tpm2_DefineSpace %d succeeds\n", nv_handle);
#endif
#endif

  if (!Tpm2_ReadNv(tpm, nv_handle, ekAuth, &size_data, data_out)) {
    printf("%s() error, line %d, ReadNv failed\n", __func__, __LINE__);
    return false;
  }
#ifdef DEBUG
  printf("Tpm2_ReadNv %d succeeds: ", nv_handle);
  print_bytes(size_data, data_out);
  printf("\n");
#endif

  out->assign((char *)data_out, size_data);
  return true;
}

bool write_nv_slot(local_tpm &tpm, int slot, string &in) {

  TPM_HANDLE nv_handle = GetNvHandle(slot);
  string     authString;

  if (Tpm2_UndefineSpace(tpm, TPM_RH_OWNER, nv_handle)) {
#ifdef DEBUG
    printf("Tpm2_UndefineSpace %d succeeds\n", slot);
#endif
  } else {
#ifdef DEBUG
    printf("Tpm2_UndefineSpace fails (but that's OK usually)\n");
#endif
  }
  if (!Tpm2_DefineSpace(tpm,
                        TPM_RH_OWNER,
                        nv_handle,
                        authString,
                        0,
                        nullptr,
                        NV_AUTHWRITE | NV_AUTHREAD,
                        in.size())) {
    printf("%s() error, line %d, DefineSpace failed\n", __func__, __LINE__);
    return false;
  }
#ifdef DEBUG
  else {
  printf("Tpm2_DefineSpace %d succeeds\n", nv_handle);
  }
#endif

  if (!Tpm2_WriteNv(tpm,
                    nv_handle,
                    authString,
                    in.size(),
                    (byte_t *)in.data())) {
    printf("%s() error, line %d, WriteNv failed\n", __func__, __LINE__);
    return false;
  }
#ifdef DEBUG
  printf("Tpm2_WriteNv %d succeeds, %d bytes written\n",
         nv_handle,
         (int)in.size());
#endif

  return true;
}

bool extend_pcrs(local_tpm &tpm, int pcr_num) {
  uint16_t size_eventData = 3;
  byte_t   eventData[3] = {1, 2, 3};
  if (!Tpm2_PCR_Event(tpm, pcr_num, size_eventData, eventData)) {
    printf("%s() error, line %d, Tpm2_PCR_Event failed\n", __func__, __LINE__);
    return false;
  }
#ifdef DEBUG2
  printf("Tpm2_PCR_Event succeeded\n");
#endif
  return true;
}

bool create_quote_hierarchy(local_tpm    &tpm,
                            int           num_pcrs,
                            byte_t       *pcrs,
                            const string &file_name) {

  string     srkAuth;
  string     quoteAuth;
  TPM_HANDLE srk_handle;

  TPM2B_PUBLIC       pub_out;
  TPML_PCR_SELECTION pcrSelect;
  memset((void *)&pcrSelect, 0, sizeof(TPML_PCR_SELECTION));

  if (num_pcrs < 1) {
    printf("%s() error, line %d: No pcrs\n", __func__, __LINE__);
    return false;
  }
  init_single_pcr_selection(pcrs[0], TPM_ALG_SHA256, &pcrSelect);
  for (int i = 1; i < num_pcrs; i++) {
    add_pcr_selection(pcrs[i], TPM_ALG_SHA256, &pcrSelect);
  }

  TPMA_OBJECT primary_flags;
  *(uint32_t *)(&primary_flags) = 0;
  primary_flags.fixedTPM = 1;
  primary_flags.fixedParent = 1;
  primary_flags.sensitiveDataOrigin = 1;
  primary_flags.userWithAuth = 1;
  primary_flags.decrypt = 1;
  primary_flags.restricted = 1;

  // Storage root key
  if (!Tpm2_CreatePrimary(tpm,
                          TPM_RH_OWNER,
                          srkAuth,
                          pcrSelect,
                          TPM_ALG_RSA,
                          TPM_ALG_SHA256,
                          primary_flags,
                          TPM_ALG_AES,
                          256,
                          TPM_ALG_CFB,
                          TPM_ALG_NULL,
                          2048,
                          0x010001,
                          &srk_handle,
                          &pub_out)) {
    printf("%s() error, line %d, CreatePrimary failed\n", __func__, __LINE__);
    return false;
  }

#ifdef DEBUG2
  printf("\nCreate hierarchy\n");
  printf("CreatePrimary succeeded\n");
  print_pcrs(tpm, num_pcrs, pcrs);
  printf("\n");
  TPM2B_NAME pub_name;
  TPM2B_NAME qualified_pub_name;
  uint16_t   pub_blob_size = 4096;
  byte_t     pub_blob[pub_blob_size];
  if (!Tpm2_ReadPublic(tpm,
                       srk_handle,
                       &pub_blob_size,
                       pub_blob,
                       &pub_out,
                       &pub_name,
                       &qualified_pub_name)) {
    printf("%s() error, line %d, ReadPublic failed\n", __func__, __LINE__);
    Tpm2_FlushContext(tpm, srk_handle);
    return false;
  }
  printf("Public blob: ");
  print_bytes(pub_blob_size, pub_blob);
  printf("\n");
  printf("\nName: ");
  print_bytes(pub_name.size, pub_name.name);
  printf("\n");
  printf("Qualified name: ");
  print_bytes(qualified_pub_name.size, qualified_pub_name.name);
  printf("\n");
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
#endif

  TPM2B_CREATION_DATA creation_out;
  TPMT_TK_CREATION    creation_ticket;
  int                 size_public = MAX_SIZE_PARAMS;
  byte_t              out_public[MAX_SIZE_PARAMS];
  int                 size_private = MAX_SIZE_PARAMS;
  byte_t              out_private[MAX_SIZE_PARAMS];
  TPM2B_DIGEST        digest_out;

  TPMA_OBJECT create_flags;
  *(uint32_t *)(&create_flags) = 0;
  create_flags.fixedTPM = 1;
  create_flags.fixedParent = 1;
  create_flags.sensitiveDataOrigin = 1;
  create_flags.userWithAuth = 1;
  create_flags.sign = 1;
  create_flags.restricted = 1;

  // Quote key
  if (!Tpm2_CreateKey(tpm,
                      srk_handle,
                      srkAuth,
                      quoteAuth,
                      pcrSelect,
                      TPM_ALG_RSA,
                      TPM_ALG_SHA256,
                      create_flags,
                      TPM_ALG_NULL,
                      (TPMI_AES_KEY_BITS)256,
                      TPM_ALG_ECB,
                      TPM_ALG_RSASSA,
                      2048,
                      0x010001,
                      &size_public,
                      out_public,
                      &size_private,
                      out_private,
                      &creation_out,
                      &digest_out,
                      &creation_ticket)) {
    printf("%s() error, line %d, CreateKey failed\n", __func__, __LINE__);
    Tpm2_FlushContext(tpm, srk_handle);
    return false;
  }
#ifdef DEBUG2
  printf("CreateKey succeeded, private size: %d, public size: %d\n",
         size_private,
         size_public);
  printf("Digest (%d): ", digest_out.size);
  print_bytes(digest_out.size, digest_out.buffer);
  printf("\n");
  printf("Private: ");
  print_bytes(size_private, out_private);
  printf("\nPublic: ");
  print_bytes(size_public, out_public);
  printf("\n");
#endif

  // Save the stuff for load
  tpm_load_key_info key_info;

  // Copy two extra bytes: document this later.
  key_info.set_hierarchy_name("Quote-Key-Hierarchy");
  key_info.set_pub_key((byte_t *)out_public, size_public + 2);
  key_info.set_priv_key((byte_t *)out_private, size_private + 2);

  string serialized_key_info;
  if (!key_info.SerializeToString(&serialized_key_info)) {
    printf("%s() error, line: %d, Can't serialize key_info\n",
           __func__,
           __LINE__);
    Tpm2_FlushContext(tpm, srk_handle);
    return false;
  }
  if (!write_file_from_string(file_name, serialized_key_info)) {
    printf("%s() error, line: %d, Can't writ key_inf file %s\n",
           __func__,
           __LINE__,
           file_name.c_str());
    return false;
  }

  Tpm2_FlushContext(tpm, srk_handle);
  return true;
}

bool recover_and_load_quote_hierarchy(local_tpm    &tpm,
                                      int           num_pcrs,
                                      byte_t       *pcrs,
                                      const string &file_name,
                                      TPM_HANDLE   *srk_handle,
                                      TPM_HANDLE   *quote_handle) {
  string srkAuth;
  string quoteAuth;

  TPM2B_PUBLIC       pub_out;
  TPML_PCR_SELECTION pcrSelect;
  memset((void *)&pcrSelect, 0, sizeof(TPML_PCR_SELECTION));

  if (num_pcrs < 1) {
    printf("%s() error, line %d: No pcrs\n", __func__, __LINE__);
    return false;
  }
  init_single_pcr_selection(pcrs[0], TPM_ALG_SHA256, &pcrSelect);
  for (int i = 1; i < num_pcrs; i++) {
    add_pcr_selection(pcrs[i], TPM_ALG_SHA256, &pcrSelect);
  }

  TPMA_OBJECT primary_flags;
  *(uint32_t *)(&primary_flags) = 0;
  primary_flags.fixedTPM = 1;
  primary_flags.fixedParent = 1;
  primary_flags.sensitiveDataOrigin = 1;
  primary_flags.userWithAuth = 1;
  primary_flags.decrypt = 1;
  primary_flags.restricted = 1;

  // Storage root key
  if (!Tpm2_CreatePrimary(tpm,
                          TPM_RH_OWNER,
                          srkAuth,
                          pcrSelect,
                          TPM_ALG_RSA,
                          TPM_ALG_SHA256,
                          primary_flags,
                          TPM_ALG_AES,
                          256,
                          TPM_ALG_CFB,
                          TPM_ALG_NULL,
                          2048,
                          0x010001,
                          srk_handle,
                          &pub_out)) {
    printf("%s() error, line %d, CreatePrimary failed\n", __func__, __LINE__);
    return false;
  }

#ifdef DEBUG2
  printf("\nRecover hierarchy\n");
  printf("CreatePrimary succeeded\n");
  print_pcrs(tpm, num_pcrs, pcrs);
  printf("\n");
  TPM2B_NAME pub_name;
  TPM2B_NAME qualified_pub_name;
  uint16_t   pub_blob_size = 4096;
  byte_t     pub_blob[pub_blob_size];
  if (!Tpm2_ReadPublic(tpm,
                       *srk_handle,
                       &pub_blob_size,
                       pub_blob,
                       &pub_out,
                       &pub_name,
                       &qualified_pub_name)) {
    printf("%s() error, line %d, ReadPublic failed\n", __func__, __LINE__);
    Tpm2_FlushContext(tpm, *srk_handle);
    return false;
  }
  printf("Public blob: ");
  print_bytes(pub_blob_size, pub_blob);
  printf("\n");
  printf("Name: ");
  print_bytes(pub_name.size, pub_name.name);
  printf("\n");
  printf("Qualified name: ");
  print_bytes(qualified_pub_name.size, qualified_pub_name.name);
  printf("\n");
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
#endif

  // Get info for load
  tpm_load_key_info key_info;
  string            serialized_key_info;

  if (!read_file_into_string(file_name, &serialized_key_info)) {
    printf("%s() error, line %d, Can't read seal file %s\n",
           __func__,
           __LINE__,
           file_name.c_str());
    Tpm2_FlushContext(tpm, *srk_handle);
    return false;
  }
  if (!key_info.ParseFromString(serialized_key_info)) {
    printf("%s() error, line: %d, Can't deserialize key_info\n",
           __func__,
           __LINE__);
    Tpm2_FlushContext(tpm, *srk_handle);
    return false;
  }
#ifdef DEBUG2
  printf("\nRecoverKey\n");
  printf("Private: ");
  print_bytes((int)key_info.priv_key().size(),
              (byte_t *)key_info.priv_key().data());
  printf("\nPublic: ");
  print_bytes((int)key_info.pub_key().size(),
              (byte_t *)key_info.pub_key().data());
  printf("\n");
  printf("\n");
#endif

  TPM2B_NAME name;
  memset((byte_t *)&name, 0, sizeof(name));
  // There are two bytes after the keys that dont count.
  if (!Tpm2_Load(tpm,
                 *srk_handle,
                 quoteAuth,
                 (int)key_info.pub_key().size() - 2,
                 (byte_t *)key_info.pub_key().data(),
                 (int)key_info.priv_key().size() - 2,
                 (byte_t *)key_info.priv_key().data(),
                 quote_handle,
                 &name)) {
    printf("%s() error, line %d, Load failed\n", __func__, __LINE__);
    Tpm2_FlushContext(tpm, *srk_handle);
    return false;
  }

#ifdef DEBUG
  printf("Load succeeded\n");
#endif
  return true;
}

bool do_quote(local_tpm  &tpm,
              TPM_HANDLE &srk_handle,
              int         num_pcrs,
              byte_t     *pcrs,
              TPM_HANDLE &quote_handle,
              string     &to_quote,
              string     *quote_out) {

  TPML_PCR_SELECTION pcrSelect;
  TPMT_SIG_SCHEME    scheme;
  string             quoteAuth;
  int                quote_size = 2048;
  byte_t             quoted[quote_size];

  memset((void *)&pcrSelect, 0, sizeof(TPML_PCR_SELECTION));

  init_single_pcr_selection(pcrs[0], TPM_ALG_SHA256, &pcrSelect);
  for (int i = 1; i < num_pcrs; i++) {
    add_pcr_selection(pcrs[i], TPM_ALG_SHA256, &pcrSelect);
  }

  int    sig_size = MAX_SIZE_PARAMS;
  byte_t sig[MAX_SIZE_PARAMS];
  if (!Tpm2_Quote(tpm,
                  quote_handle,
                  quoteAuth,
                  to_quote.size(),
                  (byte_t *)to_quote.data(),
                  scheme,
                  pcrSelect,
                  TPM_ALG_RSA,
                  TPM_ALG_SHA256,
                  &quote_size,
                  quoted,
                  &sig_size,
                  sig)) {
    printf("%s() error, line %d, quote failed\n", __func__, __LINE__);
    return false;
  }
  quote_out->assign((char *)sig, sig_size);
#ifdef DEBUG
  printf("Quote succeeded, quoted (%d): ", quote_size);
  print_bytes(quote_size, quoted);
  printf("\n");
  printf("Sig (%d): ", sig_size);
  print_bytes(sig_size, sig);
  printf("\n");
#endif
  return true;
}

bool verify_credential(local_tpm    &tpm,
                       const string &to_quote,
                       const string &quote) {
#if 0
  TPM2B_DIGEST credential;
  TPM2B_ID_OBJECT credentialBlob;
  TPM2B_ENCRYPTED_SECRET secret;
  TPM2B_DIGEST recovered_credential;

  memset((void*)&credential, 0, sizeof(TPM2B_DIGEST));
  memset((void*)&secret, 0, sizeof(TPM2B_ENCRYPTED_SECRET));
  memset((void*)&credentialBlob, 0, sizeof(TPM2B_ID_OBJECT));

  // TODO: Make a real secret here for MakeCredential with
  // size 32 bits.
  credential.size = 20;
  for (int i = 0; i < credential.size; i++)
    credential.buffer[i] = i + 1;

  TPM2B_PUBLIC quoting_pub_out;
  TPM2B_NAME quoting_pub_name;
  TPM2B_NAME quoting_qualified_pub_name;
  uint16_t quoting_pub_blob_size = 1024;
  byte_t quoting_pub_blob[quoting_pub_blob_size];

  memset((void*)&quoting_pub_out, 0, sizeof(TPM2B_PUBLIC));

  if (Tpm2_ReadPublic(tpm, quotingHandle,
                      &quoting_pub_blob_size, quoting_pub_blob,
                      &quoting_pub_out, &quoting_pub_name,
                      &quoting_qualified_pub_name)) {
    printf("ReadPublic succeeded\n");
  } else {
    printf("ReadPublic failed\n");
    return false;
  }
  printf("Active Name (%d): ", quoting_pub_name.size);
  print_bytes(quoting_pub_name.size, quoting_pub_name.name);
  printf("\n");

  if (Tpm2_MakeCredential(tpm, ekHandle, credential, quoting_pub_name,
                          &credentialBlob, &secret)) {
    printf("MakeCredential succeeded\n");
  } else {
    printf("MakeCredential failed\n");
    Tpm2_FlushContext(tpm, quotingHandle);
    Tpm2_FlushContext(tpm, srkHandle);
    Tpm2_FlushContext(tpm, ekHandle);
    return false;
  }
  printf("credBlob size: %d\n", credentialBlob.size);
  printf("secret size: %d\n", secret.size);
  if (Tpm2_ActivateCredential(tpm, quotingHandle, ekHandle,
                              srkAuth, emptyAuth,
                              credentialBlob, secret,
                              &recovered_credential)) {
    printf("ActivateCredential succeeded\n");
    printf("Recovered credential (%d): ", recovered_credential.size);
    print_bytes(recovered_credential.size, recovered_credential.buffer);
    printf("\n");
  } else {
    printf("ActivateCredential failed\n");
    Tpm2_FlushContext(tpm, quotingHandle);
    Tpm2_FlushContext(tpm, srkHandle);
    Tpm2_FlushContext(tpm, ekHandle);
    return false;
  }
  Tpm2_FlushContext(tpm, quotingHandle);
  Tpm2_FlushContext(tpm, srkHandle);
  Tpm2_FlushContext(tpm, ekHandle);
#endif
  return true;
}

//----------------------------------------------------------------------

local_tpm g_tpm;
bool      g_seal_keyinitialized = false;
int       g_seal_key_type;
string    g_seal_key;

bool tpm_init(const string &device_name,
              const string &endorsement_cert_file_name,
              const string &seal_hierarchy_file_name,
              const string &quote_hierarchy_file_name) {
  return false;
}

bool tpm_seal(string &unsealed, string *sealed) {
  // Initialized?
  // Get key
  // Encrypt
  return false;
}

bool tpm_unseal(string &sealed, string *unsealed) {
  // Initialized?
  // Get key
  // Decrypt
  return false;
}

bool tpm_attest(string &to_quote, string *quote) {
  return false;
}

bool tpm_verify_attest(string &quote) {
  return false;
}


// ------------------------------------------------------------------------
