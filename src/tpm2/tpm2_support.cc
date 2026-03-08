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

void print_mask(int n, byte_t *m) {
  while (n-- > 0)
    printf("%02x", *(m++));
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
#ifdef DEBUG2
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
#ifdef DEBUG2
  printf("%s(), line %d, Tpm2_PolicyPcr succeeded\n", __func__, __LINE__);
#endif

  TPM2B_DIGEST policy_digest;
  if (!Tpm2_PolicyGetDigest(tpm, session_handle, policy_out)) {
    printf("%s() error, line %d, PolicyGetDigest failed\n", __func__, __LINE__);
    Tpm2_FlushContext(tpm, session_handle);
    return false;
  }
#ifdef DEBUG2
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

  string sensitiveData;
  string outsideInfo;
  string emptyString;

  int    size_buf = 128;
  byte_t buf[size_buf];

  int m = CreatePasswordAuthArea(emptyString, size_buf, buf);
  if (m < 0) {
    printf("%s() error, line %d, CreatePasswordAuthArea failed\n",
           __func__,
           __LINE__);
    return false;
  }
  srkAuth.assign((char *)(buf + 2), m - 2);

  // Creating a new SRK
  if (!Tpm2_CreatePrimary(tpm,
                          TPM_RH_OWNER,
                          srkAuth,
                          sensitiveData,
                          outsideInfo,
                          emptyString,
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
#ifdef DEBUG2
  printf("\nSecret: ");
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
  printf("\nSeal session succeeded\n");
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
  string outsideData;
  string sensitveData;
  string policyDigest;

  policyDigest.assign((char *)policy_digest.buffer, (int)policy_digest.size);
  sensitiveData.assign((char *)secret.buffer, (int)secret.size);

  if (!Tpm2_CreateSealed(tpm,
                         srk_handle,
                         srkAuth,
                         sensitiveData,
                         outsideData,
                         policyDigest,
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
  string emptyAuth;

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

  int    size_buf = 128;
  byte_t buf[size_buf];

  int m = CreatePasswordAuthArea(emptyAuth, size_buf, buf);
  if (m < 0) {
    printf("%s() error, line %d, CreatePasswordAuthArea failed\n",
           __func__,
           __LINE__);
    return false;
  }

  srkAuth.assign((char *)(buf + 2), m - 2);
  sealAuth.assign((char *)(buf + 2), m - 2);

  TPMA_OBJECT primary_flags;
  primary_flags.fixedTPM = 1;
  primary_flags.fixedParent = 1;
  primary_flags.sensitiveDataOrigin = 1;
  primary_flags.userWithAuth = 1;
  primary_flags.decrypt = 1;
  primary_flags.restricted = 1;

  string sensitiveData;
  string outsideInfo;
  string policyString;

  // Creating a new SRK
  if (!Tpm2_CreatePrimary(tpm,
                          TPM_RH_OWNER,
                          srkAuth,
                          sensitiveData,
                          outsideInfo,
                          policyString,
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
  printf("\nAfter recovery private size: %d, public size: %d\n",
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
  printf("\nLoad succeeded\n");
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
#ifdef DEBUG2
  printf("\nUnseal succeeded, unsealed (%d): ", unsealed_size);
  print_bytes(unsealed_size, unsealed);
  printf("\n");
#endif

  TPM2B_SENSITIVE_DATA *unsealed_return =
      (TPM2B_SENSITIVE_DATA *)(&unsealed[2]);
#ifdef DEBUG2
  uint16_t ss;
  change_endian16(&unsealed_return->size, &ss);
  printf("\nSensitive data size: %d\n", ss);
#endif
  TPM2B_DATA *sym = (TPM2B_DATA *)unsealed_return->buffer;
  uint16_t    sb;
  change_endian16(&(sym->size), &sb);
#ifdef DEBUG2
  printf("\n");
  printf("Secret (%d): ", sb);
  print_bytes(sb, sym->buffer);
  printf("\n");
#endif
  seal_secret->assign((char *)sym->buffer, sb);

  Tpm2_FlushContext(tpm, session_handle);
  Tpm2_FlushContext(tpm, seal_handle);
  Tpm2_FlushContext(tpm, srk_handle);
  return true;
}

bool get_endorsement_cert(const string &file_name, string *out) {
  return read_file_into_string(file_name, out);
}

bool get_endorsement_cert(local_tpm &tpm, string *out) {
  // EK Certificate is at 0x01c00002 (RSA) or 0x01c0000a (ECC)
  int handle = 0x01c00002;

  TPM_HANDLE slot_index;
  uint32_t   slot_attributes;
  uint16_t   slot_size;
  TPM_ALG_ID slot_alg;
  string     slot_policy;
  if (!Tpm2_ReadNvPublic(tpm,
                         handle,
                         &slot_index,
                         &slot_alg,
                         &slot_attributes,
                         &slot_policy,
                         &slot_size)) {
    printf("%s() error, line %d, ReadNvPublic failed\n", __func__, __LINE__);
    return false;
  }
#ifdef DEBUG1
  printf("reported handle: %08x\n", slot_index);
  printf("reported alg: %04x\n", slot_alg);
  printf("reported slot size : %d\n", (int)slot_size);
  printf("reported policy (%d):\n", (int)slot_policy.size());
  print_bytes((int)slot_policy.size(), (byte_t *)slot_policy.data());
  printf("\n");
  printf("\n");
#endif

  int    out_size = (int)slot_size;
  byte_t out_buf[out_size];
  string authString;

  if (!read_nv_handle(tpm, handle, authString, out_size, out)) {
    printf("%s() error, line %d, read_nv_handle failed\n", __func__, __LINE__);
    return false;
  }
  return true;
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
                    int        size,
                    string    *out) {
  uint16_t size_data = (uint16_t)size;
  byte_t   data_out[size_data];

  if (!Tpm2_ReadNv(tpm, handle, authString, &size_data, data_out)) {
    printf("%s() error, line %d, ReadNv failed, handle: %x\n",
           __func__,
           __LINE__,
           handle);
    return false;
  }
#ifdef DEBUG1
  printf("Tpm2_ReadNv %x succeeds: ", handle);
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
  TPM_HANDLE nv_handle = GetNvHandle(slot);

  if (!Tpm2_ReadNv(tpm, nv_handle, ekAuth, &size_data, data_out)) {
    printf("%s() error, line %d, ReadNv failed\n", __func__, __LINE__);
    return false;
  }
#ifdef DEBUG1
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

bool create_endorsement_session(local_tpm  &tpm,
                                string     &authString,
                                string     *nonce,
                                TPM_HANDLE *session_handle) {

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
  nonce->assign((char *)nonce_obj.buffer, nonce_obj.size);

  TPM2B_DIGEST policy_digest;
  if (!Tpm2_PolicyGetDigest(tpm, *session_handle, &policy_digest)) {
    printf("%s() error, line %d, PolicyGetDigest failed\n", __func__, __LINE__);
    Tpm2_FlushContext(tpm, *session_handle);
    return false;
  }
#ifdef DEBUG2
  printf("Endorsement auth session handle: %08x\n", *session_handle);
  printf("starting digest: ");
  print_bytes(policy_digest.size, policy_digest.buffer);
  printf("\n");
#endif

  TPM2B_TIMEOUT timeout;
  TPMT_TK_AUTH  ticket;
  int           zero = 0;
  if (!Tpm2_PolicySecret(tpm,
                         TPM_RH_ENDORSEMENT,
                         authString,
                         *session_handle,
                         zero,
                         &policy_digest,
                         &timeout,
                         &ticket)) {
    printf("%s() error, line %d, PolicySecret failed\n", __func__, __LINE__);
    Tpm2_FlushContext(tpm, *session_handle);
    return false;
  }

#ifdef DEBUG2
  if (!Tpm2_PolicyGetDigest(tpm, *session_handle, &policy_digest)) {
    printf("%s() error, line %d, PolicyGetDigest failed\n", __func__, __LINE__);
    Tpm2_FlushContext(tpm, *session_handle);
    return false;
  }
  printf("Endorsement returned digest: ");
  print_bytes(policy_digest.size, policy_digest.buffer);
  printf("\n");
#endif

  return true;
}

bool create_quote_session(local_tpm          &tpm,
                          TPML_PCR_SELECTION &pcrSelect,
                          string             *nonce,
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
  nonce->assign((char *)nonce_obj.buffer, nonce_obj.size);

#ifdef DEBUG2
  printf("\n");
  printf("Tpm2_StartAuthSession succeeds handle: %08x\n", *session_handle);
  printf("initial nonce (%d): ", initial_nonce.size);
  print_bytes(initial_nonce.size, initial_nonce.buffer);
  printf("\n");
  printf("nonce (%d): ", nonce_obj.size);
  print_bytes(nonce_obj.size, nonce_obj.buffer);
  printf("\n");

  TPM2B_DIGEST policy_digest;
  if (!Tpm2_PolicyGetDigest(tpm, *session_handle, &policy_digest)) {
    printf("%s() error, line %d, PolicyGetDigest failed\n", __func__, __LINE__);
    Tpm2_FlushContext(tpm, *session_handle);
    return false;
  }
  printf("\n");
  printf("%s() line %d, PolicyGetDigest before Pcr succeeded: \n",
         __func__,
         __LINE__);
  print_bytes(policy_digest.size, policy_digest.buffer);
  printf("\n");

  if (!Tpm2_PolicyPassword(tpm, *session_handle)) {
    printf("%s() error, line %d, Tpm2_PolicyPassword fails\n",
           __func__,
           __LINE__);
    Tpm2_FlushContext(tpm, *session_handle);
    return false;
  }
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
#ifdef DEBUG
  printf("pcrs at create_quote\n");
  int    num_pcrs = 1;
  byte_t pcrs[1] = {7};
  print_pcrs(tpm, num_pcrs, pcrs);
#endif
#ifdef DEBUG2
  printf("%s(), line %d, Tpm2_PolicyPcr succeeded\n", __func__, __LINE__);
#endif

  return true;
}

/*
 * Template args
 *
 *  type TPMI_ALG_PUBLIC TPM_ALG_RSA
 *  nameAlg TPMI_ALG_HASH TPM_ALG_SHA256
 *  objectAttributes
 *    fixedTPM = 1
 *    stClear = 0
 *    fixedParent = 1
 *    sensitiveDataOrigin = 1
 *    userWithAuth = 0
 *    adminWithPolicy = 1
 *    noDA = 0
 *    encryptedDuplication = 0
 *    restricted = 1
 *    decrypt = 1
 *    sign = 0
 *  authPolicy
 *    0x83, 0x71, 0x97, 0x67, 0x44, 0x84,
 *    0xB3, 0xF8, 0x1A, 0x90, 0xCC, 0x8D,
 *    0x46, 0xA5, 0xD7, 0x24, 0xFD, 0x52,
 *    0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64,
 *    0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14,
 *    0x69, 0xAA
 *  TPM2_PolicySecret(TPM_RH_ENDORSEMENT)
 *  parameters
 *  symmetric->algorithm TPM_ALG_AES
 *  symmetric->keyBits 128
 *  symmetric->mode TPM_ALG_CFB
 *  symmetric->details NULL
 *  scheme->scheme TPM_ALG_NULL
 *  scheme->details NULL
 *  keyBits 2048
 *  exponent 0
 *  unique
 *    size UINT16 256
 *    buffer BYTE All 0
 */

bool get_endorsement_key(local_tpm  &tpm,
                         string     &authString,
                         string     &policyString,
                         TPM_HANDLE *ek_handle) {

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
  primary_flags.adminWithPolicy = 1;
  primary_flags.decrypt = 1;
  primary_flags.restricted = 1;

  string sensitiveData;
  string outsideInfo;
  string nonce;

#ifdef DEBUG2
  printf("authstring: ");
  print_bytes(authString.size(), (byte_t *)authString.data());
  printf("\n");
  printf("policyString: ");
  print_bytes(policyString.size(), (byte_t *)policyString.data());
  printf("\n");

  TPM_HANDLE endorsement_session_handle = 0;
  if (!create_endorsement_session(tpm,
                                  authString,
                                  &nonce,
                                  &endorsement_session_handle)) {
    printf("%s() error, line %d, create_endorsement_session failed\n",
           __func__,
           __LINE__);
    return false;
  }
  Tpm2_FlushContext(tpm, endorsement_session_handle);
#endif

  // Create Endorsement key with handle ekHandle
  if (!Tpm2_CreatePrimary(tpm,
                          TPM_RH_ENDORSEMENT,  // owner
                          authString,
                          sensitiveData,
                          outsideInfo,
                          policyString,
                          pcrSelect,       // pcrSelect
                          TPM_ALG_RSA,     // enc_alg
                          TPM_ALG_SHA256,  // int_alg
                          primary_flags,
                          TPM_ALG_AES,   // sym_alg
                          128,           // size (128)
                          TPM_ALG_CFB,   // sym_mode
                          TPM_ALG_NULL,  // sym_scheme
                          2048,          // keyBits (mod size)
                          0x0,           // exponent
                          ek_handle,
                          &pub_out)) {
    printf("%s() error, line %d, CreatePrimary failed\n", __func__, __LINE__);
    return false;
  }

#ifdef DEBUG1
  printf("\n");
  printf("Modulus from CreatePrimary (%d):\n",
         pub_out.publicArea.unique.rsa.size);
  print_bytes(pub_out.publicArea.unique.rsa.size,
              pub_out.publicArea.unique.rsa.buffer);
  printf("\n");
  printf("CreatePrimary succeeded primary: %08x\n", *ek_handle);
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
  printf("ReadPublic, Public blob: ");
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
  printf("Policy: ");
  print_bytes(pub_out.publicArea.authPolicy.size,
              pub_out.publicArea.authPolicy.buffer);
  printf("\n");
#endif

  return true;
}

bool create_quote_hierarchy(local_tpm    &tpm,
                            int           num_pcrs,
                            byte_t       *pcrs,
                            const string &file_name) {

  TPM_HANDLE srk_handle;

  TPM2B_PUBLIC       pub_out;
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

  TPMA_OBJECT primary_flags;
  *(uint32_t *)(&primary_flags) = 0;
  primary_flags.fixedTPM = 1;
  primary_flags.fixedParent = 1;
  primary_flags.sensitiveDataOrigin = 1;
  primary_flags.userWithAuth = 1;
  primary_flags.decrypt = 1;
  primary_flags.restricted = 1;

  string srkAuth;
  string sensitiveData;
  string outsideInfo;
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
  srkAuth.assign((char *)(buf + 2), m - 2);

  // Storage root key
  if (!Tpm2_CreatePrimary(tpm,
                          TPM_RH_OWNER,
                          srkAuth,
                          sensitiveData,
                          outsideInfo,
                          policyString,
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

  // Create the policy for the quote key
  TPM_HANDLE   session_handle = 0;
  TPM2B_DIGEST policy_digest;
  string       nonce;
  if (!create_quote_session(tpm, pcrSelect, &nonce, &session_handle)) {
    printf("%s() error, line %d, create_quote_session failed\n",
           __func__,
           __LINE__);
    return false;
  }
  if (!Tpm2_PolicyGetDigest(tpm, session_handle, &policy_digest)) {
    printf("%s() error, line %d, PolicyGetDigest failed\n", __func__, __LINE__);
    Tpm2_FlushContext(tpm, session_handle);
    return false;
  }
  Tpm2_FlushContext(tpm, session_handle);
  policyString.assign((char *)policy_digest.buffer, policy_digest.size);
#ifdef DEBUG
  printf("policy for quote: ");
  print_bytes(policyString.size(), (byte_t *)policyString.data());
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
  // create_flags.adminWithPolicy = 1;

  // Quote key
  if (!Tpm2_CreateKey(tpm,
                      srk_handle,
                      srkAuth,
                      sensitiveData,
                      outsideInfo,
                      policyString,
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
  printf("Quote CreateKey succeeded, private size: %d, public size: %d\n",
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

  string sensitiveData;
  string outsideInfo;
  string emptyAuth;
  string policyString;

  int    size_buf = 128;
  byte_t buf[size_buf];

  int m = CreatePasswordAuthArea(emptyAuth, size_buf, buf);
  if (m < 0) {
    printf("%s() error, line %d, CreatePasswordAuthArea failed\n",
           __func__,
           __LINE__);
    return false;
  }
  srkAuth.assign((char *)(buf + 2), m - 2);

  // Storage root key
  if (!Tpm2_CreatePrimary(tpm,
                          TPM_RH_OWNER,
                          srkAuth,
                          sensitiveData,
                          outsideInfo,
                          policyString,
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
                 srkAuth,
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

#ifdef DEBUG2
  printf("\nLoad succeeded\n");
#endif
  return true;
}

bool do_quote(local_tpm  &tpm,
              TPM_HANDLE &srk_handle,
              int         num_pcrs,
              byte_t     *pcrs,
              TPM_HANDLE &quote_handle,
              string     &to_quote,
              string     *quoted,
              string     *signature) {

  TPML_PCR_SELECTION pcrSelect;
  TPMT_SIG_SCHEME    scheme;
  string             quoteAuth;
  int                quote_size = 2048;
  byte_t             quoted_buf[quote_size];

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
                  quoted_buf,
                  &sig_size,
                  sig)) {
    printf("%s() error, line %d, quote failed\n", __func__, __LINE__);
    return false;
  }
  quoted->assign((char *)quoted_buf, quote_size);
  signature->assign((char *)sig, sig_size);

#ifdef DEBUG2
  printf("\nQuote succeeded, quoted (%d): ", quote_size);
  print_bytes(quote_size, quoted_buf);
  printf("\n");
  printf("Sig (%d): ", sig_size);
  print_bytes(sig_size, sig);
  printf("\n");
#endif
  return true;
}

//----------------------------------------------------------------------

local_tpm g_tpm;

bool g_tpm_initialized = false;
bool g_tpm_environment_initialized = false;

TPM_HANDLE g_ek_handle = 0;
TPM_HANDLE g_srk_handle = 0;
TPM_HANDLE g_quote_handle = 0;

int          g_seal_key_type;
string       g_seal_key;
string       g_endorsement_cert;
string       g_endorsement_cert_file_name;
string       g_seal_hierarchy_file_name;
string       g_quote_hierarchy_file_name;
string       g_seal_thing;
int          g_num_pcrs;
byte_t       g_pcrs[32];
TPM2B_PUBLIC g_public_quote_key;


bool tpm_close() {

#ifdef DEBUG2
  printf("\ntpm_close()\n");
#endif

  if (!g_tpm_initialized) {
    return true;
  }

  if (g_ek_handle != 0) {
    Tpm2_FlushContext(g_tpm, g_ek_handle);
    g_ek_handle = 0;
  }
  if (g_srk_handle != 0) {
    Tpm2_FlushContext(g_tpm, g_srk_handle);
    g_srk_handle = 0;
  }
  if (g_quote_handle != 0) {
    Tpm2_FlushContext(g_tpm, g_quote_handle);
    g_quote_handle = 0;
  }

  if (g_tpm_initialized) {
    g_tpm.close_tpm();
    g_tpm_initialized = false;
  }
  g_tpm_environment_initialized = false;

#ifdef DEBUG2
  printf("tpm_close() returning\n");
#endif
  return true;
}

bool tpm_init(const string &device_name,
              const string &endorsement_cert_file_name,
              const string &seal_hierarchy_file_name,
              const string &quote_hierarchy_file_name,
              int           num_pcrs,
              byte_t       *pcrs) {

  g_endorsement_cert_file_name = endorsement_cert_file_name;
  g_seal_hierarchy_file_name = seal_hierarchy_file_name;
  g_quote_hierarchy_file_name = quote_hierarchy_file_name;

  if (g_seal_hierarchy_file_name == "") {
    printf("%s() error, line %d, no seal key file name\n", __func__, __LINE__);
    return false;
  }
  if (g_quote_hierarchy_file_name == "") {
    printf("%s() error, line %d, no seal key file name\n", __func__, __LINE__);
    return false;
  }
  if (g_endorsement_cert_file_name == "") {
    printf("%s() error, line %d, no endorsement cert file name\n",
           __func__,
           __LINE__);
    return false;
  }

  if (file_size(g_endorsement_cert_file_name) == -1) {
    printf("%s() error, line %d, no endorsement cert\n", __func__, __LINE__);
    return false;
  }
  if (!read_file_into_string(g_endorsement_cert_file_name,
                             &g_endorsement_cert)) {
    printf("%s() error, line %d, can't read endorsement cert: %s\n",
           __func__,
           __LINE__,
           g_endorsement_cert_file_name.c_str());
    return false;
  }

  if (!g_tpm.open_tpm(device_name.c_str())) {
    printf("%s() error, line %d, can't open tpm: %s\n",
           __func__,
           __LINE__,
           device_name.c_str());
    return false;
  }
#ifdef DEBUG
  printf("tpm_init, opened tpm: %s %d\n", device_name.c_str(), g_tpm.tpm_fd_);
#endif
  g_tpm_initialized = true;

#if 0
  // seal hierarchy
  if (file_size(g_seal_hierarchy_file_name) == -1) {
#  ifdef DEBUG
    printf("tpm_init, Creating Seal hierarchy\n");
#  endif
    if (!create_seal_hierarchy_and_secret(g_tpm,
                                          num_pcrs,
                                          pcrs,
                                          g_seal_hierarchy_file_name)) {
      printf("%s() error, line %d, can't create seal hierarchy %s\n",
             __func__,
             __LINE__,
             g_seal_hierarchy_file_name.c_str());
      return false;
    }
  }
  if (!read_file_into_string(g_endorsement_cert_file_name,
                             &g_endorsement_cert)) {
    printf("%s() error, line %d, can't read endorsement cert: %s\n",
           __func__,
           __LINE__,
           g_endorsement_cert_file_name.c_str());
    return false;
  }

  // quote hierarchy
  if (file_size(g_quote_hierarchy_file_name) == -1) {
#  ifdef DEBUG
    printf("tpm_init, Creating Quote hierarchy\n");
#  endif
    if (!create_quote_hierarchy(g_tpm,
                                num_pcrs,
                                pcrs,
                                g_quote_hierarchy_file_name)) {
      printf("%s() error, line %d, can't create quote hierarchy %s\n",
             __func__,
             __LINE__,
             g_quote_hierarchy_file_name.c_str());
      return false;
    }
  }

  if (!recover_sealing_secret(g_tpm,
                              num_pcrs,
                              pcrs,
                              g_seal_hierarchy_file_name,
                              &g_seal_thing)) {
    printf("%s() error, line %d, can't recover seal hierarchy %s\n",
           __func__,
           __LINE__,
           g_seal_hierarchy_file_name.c_str());
    return false;
  }
  if (!recover_and_load_quote_hierarchy(g_tpm,
                                        num_pcrs,
                                        pcrs,
                                        g_quote_hierarchy_file_name,
                                        &g_srk_handle,
                                        &g_quote_handle)) {
    printf("%s() error, line %d, can't recover quote hierarchy %s\n",
           __func__,
           __LINE__,
           g_quote_hierarchy_file_name.c_str());
    return false;
  }

  TPM2B_NAME   q_pub_name;
  TPM2B_NAME   q_qualified_pub_name;
  uint16_t     q_pub_blob_size = 4096;
  byte_t       q_pub_blob[q_pub_blob_size];

  if (!Tpm2_ReadPublic(g_tpm,
                       g_quote_handle,
                       &q_pub_blob_size,
                       q_pub_blob,
                       &g_public_quote_key,
                       &q_pub_name,
                       &q_qualified_pub_name)) {
    printf("%s() error, line %d, ReadPublic failed\n", __func__, __LINE__);
    return false;
  }
#  ifdef DEBUG
  printf("\nQuote key\n");
  printf("Type: %d\n", g_public_quote_key.publicArea.type);
  printf("Name: %d\n", g_public_quote_key.publicArea.nameAlg);
  printf("Scheme: %d\n", g_public_quote_key.publicArea.parameters.rsaDetail.scheme.scheme);
  printf("Modulus (%d):\n", (int)g_public_quote_key.publicArea.unique.rsa.size);
  print_bytes((int)g_public_quote_key.publicArea.unique.rsa.size,
              (byte_t *)g_public_quote_key.publicArea.unique.rsa.buffer);
  printf("\n");
  printf("Exponent: %d\n", g_public_quote_key.publicArea.parameters.rsaDetail.exponent);
  printf("\n");
#  endif

#endif

  g_num_pcrs = num_pcrs;
  memcpy(g_pcrs, pcrs, num_pcrs);
  g_tpm_environment_initialized = true;

#ifdef DEBUG2
  printf("tpm_init, returns true\n");
#endif
  return true;
}

bool tpm_seal(string &unsealed, string *sealed) {
  // Initialized?
  if (!g_tpm_environment_initialized) {
    printf("%s() error, line %d, environment not initialized\n",
           __func__,
           __LINE__);
    return false;
  }

  // Encrypt
  byte iv[32];
  int  out_size = unsealed.size() + 128;
  byte out[out_size];

  if (!get_random(32 * NBITSINBYTE, iv)) {
    printf("%s() error, line %d, gant get iv\n", __func__, __LINE__);
    return false;
  }
  if (!aes_256_gcm_encrypt((byte_t *)unsealed.data(),
                           (int)unsealed.size(),
                           (byte_t *)g_seal_thing.data(),
                           iv,
                           out,
                           &out_size)) {
    printf("%s() error, line %d, encrypt failure\n", __func__, __LINE__);
    return false;
  }
  sealed->assign((char *)out, out_size);
  return true;
}

bool tpm_unseal(string &sealed, string *unsealed) {
  // Initialized?
  if (!g_tpm_environment_initialized) {
    printf("%s() error, line %d, environment not initialized\n",
           __func__,
           __LINE__);
    return false;
  }

  // Decrypt
  int  out_size = sealed.size() + 128;
  byte out[out_size];
  if (!aes_256_gcm_decrypt((byte_t *)sealed.data(),
                           (int)sealed.size(),
                           (byte_t *)g_seal_thing.data(),
                           out,
                           &out_size)) {
    printf("%s() error, line %d, can't decrypt\n", __func__, __LINE__);
    return false;
  }
  unsealed->assign((char *)out, out_size);
  return true;
}

bool local_tpm_attest(TPM_HANDLE &quote_handle,
                      TPM_ALG_ID  hash_alg,
                      TPM_HANDLE &srk_handle,
                      int         num_pcrs,
                      byte_t     *pcrs,
                      string     &to_quote,
                      string     *quoted,
                      string     *signature) {

  if (hash_alg != TPM_ALG_SHA256) {
    printf("%s() error, line %d, unsupported hashing algorithm\n",
           __func__,
           __LINE__);
    return false;
  }

  unsigned int d_len = 32;
  byte_t       digest[d_len];
  if (!digest_message(Digest_method_sha_256,
                      (const byte_t *)to_quote.data(),
                      (int)to_quote.size(),
                      digest,
                      d_len)) {
    printf("%s() error, line %d, digest_message failed\n", __func__, __LINE__);
    return false;
  }

#ifdef DEBUG
  printf("\nHashed to quote: ");
  print_bytes((int)d_len, digest);
  printf("\n");
#endif

  string hashed_to_quote;
  hashed_to_quote.assign((char *)digest, d_len);

  if (!do_quote(g_tpm,
                srk_handle,
                num_pcrs,
                pcrs,
                quote_handle,
                hashed_to_quote,
                quoted,
                signature)) {
    printf("%s() error, line %d, quote failed\n", __func__, __LINE__);
    return false;
  }
  return true;
}

bool tpm_attest(string &to_quote, string *quoted, string *signature) {

  if (!g_tpm_environment_initialized) {
    printf("%s() error, line %d, environment not initialized\n",
           __func__,
           __LINE__);
    return false;
  }

  if (!do_quote(g_tpm,
                g_srk_handle,
                g_num_pcrs,
                g_pcrs,
                g_quote_handle,
                to_quote,
                quoted,
                signature)) {
    printf("%s() error, line %d, quote failed\n", __func__, __LINE__);
    return false;
  }
  return true;
}

int size_hash(uint16_t id) {
  switch (id) {
    case TPM_ALG_SHA1:
      return SHA1_DIGEST_SIZE;
    case TPM_ALG_SHA256:
      return SHA256_DIGEST_SIZE;
    default:
      return -1;
  }
}

// These are the values we have to check
bool decode_quoted(int                 size_buf,
                   byte_t             *buf,
                   string             *extra_data,
                   TPML_PCR_SELECTION *pcrSelect,
                   string             *pcr_digest) {
  /*
   * magic bytes: ff544347
   * type: 8018
   * name:
   * 0022000bb9cdfa540244e908bddf6fae8d9f242e381fe6b6551b9c38155191ef6a685dd7
   * extra data size: 0011 (to quote)
   * extra data: 4920616d206265696e672071756f746564
   * clock info: 0000000000d538933295cbbda8a9dd83013a64b94700320b2500 safe: 00
   * count: 0001
   *    hash: 000b
   *    size of select: 03
   *    select: 800000
   *  digest size: 0014 (a sha1 hash)
   *  pcrdigest: 42b189601aa3424d8d5b946d43fe32de37c192f0
   */

  // Check magic bytes: ff544347
  uint32_t mn;
  if (size_buf < (int)sizeof(uint32_t)) {
    printf("%s() error, line %d, buffer too small\n", __func__, __LINE__);
    return false;
  }
  change_endian32((uint32_t *)buf, &mn);
  if (mn != 0xff544347) {
    printf("%s() error, line %d, magic number doesnt match %08x\n",
           __func__,
           __LINE__,
           mn);
    return false;
  }
  buf += sizeof(uint32_t);
  size_buf -= sizeof(uint32_t);

  // Check type: 8018
  uint16_t type = 0;
  if (size_buf < (int)sizeof(uint16_t)) {
    printf("%s() error, line %d, buffer too small\n", __func__, __LINE__);
    return false;
  }
  change_endian16((uint16_t *)buf, &type);
  if (type != 0x8018) {
    printf("%s() error, line %d, type doesn't match %04x\n",
           __func__,
           __LINE__,
           type);
    return false;
  }
  buf += sizeof(uint16_t);
  size_buf -= sizeof(uint16_t);

  // skip name
  uint16_t size_name = 0;
  change_endian16((uint16_t *)buf, &size_name);
  buf += sizeof(uint16_t);
  size_buf -= sizeof(uint16_t);
  buf += size_name;
  size_buf -= size_name;

  // extra data
  if (size_buf < (int)sizeof(uint16_t)) {
    printf("%s() error, line %d, buffer too short\n", __func__, __LINE__);
    return false;
  }
  uint16_t ed_size = 0;
  if (size_buf < (int)ed_size) {
    printf("%s() error, line %d, buffer too short\n", __func__, __LINE__);
    return false;
  }
  change_endian16((uint16_t *)buf, &ed_size);
  buf += sizeof(uint16_t);
  size_buf -= sizeof(uint16_t);
  extra_data->assign((char *)buf, (int)ed_size);
  buf += ed_size;
  size_buf -= ed_size;

  // clock  (There must be a better way)
  buf += 27;
  size_buf -= 27;

  // pcr selection
  uint16_t count = 0;
  if (size_buf < (int)sizeof(uint16_t)) {
    printf("%s() error, line %d, buffer too short\n", __func__, __LINE__);
    return false;
  }
  change_endian16((uint16_t *)buf, &count);
  buf += sizeof(uint16_t);
  size_buf -= sizeof(uint16_t);
  int size_selection = PCR_SELECT_MAX;

  pcrSelect->count = count;
  for (int i = 0; i < (int)count; i++) {
    uint16_t alg = 0;
    uint16_t size_select = 0;
    if (size_buf < (int)sizeof(uint16_t)) {
      printf("%s() error, line %d, buffer too short\n", __func__, __LINE__);
      return false;
    }

    change_endian16((uint16_t *)buf, &alg);
    pcrSelect->pcrSelections[i].hash = alg;
    buf += sizeof(uint16_t);
    size_buf -= sizeof(uint16_t);

    if (size_buf < (int)sizeof(byte_t)) {
      printf("%s() error, line %d, buffer too short\n", __func__, __LINE__);
      return false;
    }
    pcrSelect->pcrSelections[i].sizeofSelect = *buf;
    buf += sizeof(byte_t);
    size_buf -= sizeof(byte_t);

    if (size_buf < size_selection) {
      printf("%s() error, line %d, buffer too short\n", __func__, __LINE__);
      return false;
    }
#if 0
    memcpy(pcrSelect->pcrSelections[i].pcrSelect, buf, size_selection);
#else
    reverse_byte_copy(size_selection,
                      buf,
                      pcrSelect->pcrSelections[i].pcrSelect);
#endif
    buf += size_selection;
    size_buf -= size_selection;
  }

  // digests
  if (size_buf < (int)sizeof(uint16_t)) {
    printf("%s() error, line %d, buffer too short\n", __func__, __LINE__);
    return false;
  }
  uint16_t d_size = 0;
  change_endian16((uint16_t *)buf, &d_size);
  buf += sizeof(uint16_t);
  size_buf -= sizeof(uint16_t);

  if (size_buf < d_size) {
    printf("%s() error, line %d, buffer too short\n", __func__, __LINE__);
    return false;
  }
  pcr_digest->assign((char *)buf, d_size);
  buf += d_size;
  size_buf -= d_size;

  return true;
}

bool tpm_verify_attest(key_message  &quote_key,
                       string       &to_quote,
                       string       &quoted,
                       const string &hash_name,
                       const string &sig_scheme,
                       string       &signature) {
#ifdef DEBUG
  printf("\ntpm_verify_attest:\n");
  print_key(quote_key);
  printf("\n");

  printf("hash name: %s, sig scheme: %s\n",
         hash_name.c_str(),
         sig_scheme.c_str());
  printf("to_quote: ");
  print_bytes((int)to_quote.size(), (byte_t *)to_quote.data());
  printf("\n");
  printf("quoted: ");
  print_bytes((int)quoted.size(), (byte_t *)quoted.data());
  printf("\n");
  printf("signature: ");
  print_bytes((int)signature.size(), (byte_t *)signature.data());
  printf("\n");
#endif

  if (hash_name != Digest_method_sha_256) {
    printf("%s() error, line %d, unsupported hashing algorithm\n",
           __func__,
           __LINE__);
    return false;
  }

  // Hash the thing to be quoted
  unsigned int d_len = 32;
  byte_t       digest[d_len];
  if (!digest_message(Digest_method_sha_256,
                      (const byte_t *)to_quote.data(),
                      (int)to_quote.size(),
                      digest,
                      d_len)) {
    printf("%s() error, line %d, digest_message failed\n", __func__, __LINE__);
    return false;
  }

#ifdef DEBUG
  printf("\nHashed to quote: ");
  print_bytes((int)d_len, digest);
  printf("\n");
#endif

  string hashed_to_quote;
  hashed_to_quote.assign((char *)digest, d_len);

  string             extra_data;
  TPML_PCR_SELECTION pcrSelect;
  string             pcr_digest;

  if (!decode_quoted((int)quoted.size(),
                     (byte_t *)quoted.data(),
                     &extra_data,
                     &pcrSelect,
                     &pcr_digest)) {
    printf("%s() error, line %d, decode_quoted fails\n", __func__, __LINE__);
    return false;
  }

#ifdef DEBUG
  printf("\ntpm_verify_attest:\n\n");
  printf("  extra data: ");
  print_bytes((int)extra_data.size(), (byte_t *)extra_data.data());
  printf("\n");
  printf("  pcr selection (count= %d)\n", pcrSelect.count);
  for (int i = 0; i < (int)pcrSelect.count; i++) {
    printf("    hash: %04x, size of select: %d, mask: ",
           pcrSelect.pcrSelections[i].hash,
           pcrSelect.pcrSelections[i].sizeofSelect);
    print_mask(pcrSelect.pcrSelections[i].sizeofSelect,
               pcrSelect.pcrSelections[i].pcrSelect);
    printf("\n");
  }
  printf("  pcr digest (%d): ", (int)pcr_digest.size());
  print_bytes((int)pcr_digest.size(), (byte_t *)pcr_digest.data());
  printf("\n");
  printf("\n");
#endif

  // check pcr_section
  // decrypt signature and check the hashes match
  // make sure to_quote matches "extraData" in quoted.
  // make sure hash of quoted matches the decrypted one

  if (hash_name != Digest_method_sha_256) {
    printf("%s() error, line %d, unsupported hash (not sha256) %s %s\n",
           __func__,
           __LINE__,
           hash_name.c_str(),
           Digest_method_sha256);
    return false;
  }

  unsigned int d_len2 = 32;
  byte_t       digest2[d_len2];
  if (!digest_message(Digest_method_sha_256,
                      (const byte_t *)quoted.data(),
                      (int)quoted.size(),
                      digest2,
                      d_len2)) {
    printf("%s() error, line %d, digest_message failed\n", __func__, __LINE__);
    return false;
  }

#ifdef DEBUG
  printf("\nHashed quoted: ");
  print_bytes((int)d_len2, digest2);
  printf("\n");
#endif

  // Get key for openssl
  EVP_PKEY   *key = pkey_from_key((const key_message &)quote_key);
  EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();

  if (key == nullptr) {
    printf("%s() error, line %d, can't get pkey from key\n",
           __func__,
           __LINE__);
    return false;
  }
  if (md_ctx == nullptr) {
    printf("%s() error, line %d, can't get context\n", __func__, __LINE__);
    return false;
  }

  // Initialize public quote key
  if (1 != EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, key)) {
    printf("%s() error, line %d, EVP_DigestVerifyInit fails\n",
           __func__,
           __LINE__);
    return false;
  }
#ifdef DEBUG2
  printf("\nEVP_DigestVerifyInit succeeded\n");
#endif
  if (1
      != EVP_DigestVerifyUpdate(md_ctx,
                                (const byte_t *)quoted.data(),
                                (int)quoted.size())) {
    printf("%s() error, line %d, EVP_DigestVerifyUpdate fails\n",
           __func__,
           __LINE__);
    return false;
  }
#ifdef DEBUG2
  printf("\nEVP_DigestVerifyUpdate succeeded\n");
#endif
  if (1
      != EVP_DigestVerifyFinal(md_ctx,
                               (byte_t *)signature.data(),
                               (int)signature.size())) {
    printf("%s() error, line %d, EVP_DigestVerifyFinal fails\n",
           __func__,
           __LINE__);
    return false;
  }
#ifdef DEBUG2
  printf("\nEVP_DigestVerifyFinal succeeded\n");
#endif

  // free key and md_ctx
  EVP_MD_CTX_free(md_ctx);
  EVP_PKEY_free(key);

  return true;
}

bool tpm_verify_attest(string            &cert,
                       const key_message &policy_public_key,
                       string            &to_quote,
                       string            &quoted,
                       string            &signature) {

  // recover quote key form its cert
  key_message quote_key;

#if 0
  return tpm_verify_attest(quote_key,
                           to_quote,
                           quoted,
                           hash_alg,
                           scheme,
                           signature);
#else
  return false;
#endif
}

// ------------------------------------------------------------------------

// Sequence for quote key verification protocol is:
//
//    On client: Make a construct_request_credential_message to make
//      request protobuf to send to provider
//
//    On provider:
//      verify pcrs and properties
//      produce quote key cert
//      call make_credential to construct credential
//
//    On client
//      Call activate credential to get quote key certificate
//      and return it


// This makes the certificate on the provider given
// the subject quote key, signing key, measurement (pcrs),
// and proposed subject auth key
bool construct_quote_key_cert(const key_message &signing_key,
                              const key_message &quote_public_key,
                              const string      &measurement,
                              string            *cert_out) {
  return false;
}

bool make_credential(const TPM2B_PUBLIC &quoting_key,
                     string             &quote_key_name,
                     const string       &cert_in,
                     string             &credential,
                     string             *cred_blob,
                     string             *encrypted_secret) {

  //
  // Performs the following steps:
  //   1. Generate a random secret, which is the actual credential data
  //       or a key to decrypt it.
  //   2. Obtain the public EK of the target TPM.
  //   3. Obtain the "name" of the Attestation Identity Key (AIK) on the target
  // TPM.
  //   4.  Wrap the generated secret data using EK.
  //
  // share secret with public key(&seed, label, 9, &encrypted_seed)
  // tpm2_kdfa(parent_alg, (TPM2B *) protection_seed, "INTEGRITY",
  //           &null_2b, &null_2b, parent_hash_size * 8, protection_hmac_key)
  // tpm2_kdfa(parent_alg, (TPM2B *) protection_seed, "STORAGE",
  //        (TPM2B *) pubname, &null_2b, pub_key_bits, protection_enc_key)
  // outer_integrity_hmac_key_and_dupsensitive_enc_key(&seed, &hmac_key,
  // &enc_key Perform inner encryption (encIdentity) and outer HMAC (outerHMAC))
  // cred_bloc = outer_hmac || encrypted_sensitive
  // secret = encrypted_seed (with pubEK) // use oaep
  //  (EVP_PKEY_encrypt(ctx, encrypted_protection_seed->secret, &outlen,
  //        protection_seed->buffer, protection_seed->size)

  TPM_ALG_ID hash_alg_id = quoting_key.publicArea.nameAlg;

  byte_t zero_iv[32];
  memset(zero_iv, 0, 32);

  // 1. Generate seed
  int    size_seed = 32;
  byte_t seed[size_seed];
  RAND_bytes(seed, size_seed);

  // Get endorsement public key, which is protector key
  X509   *endorsement_cert = nullptr;
  byte_t *p = (byte_t *)cert_in.data();
  endorsement_cert = d2i_X509(nullptr, (const byte_t **)&p, cert_in.size());
  if (endorsement_cert == nullptr) {
    printf("%s() error, line %d, Can't translate endorsement cert\n",
           __func__,
           __LINE__);
    return false;
  }
  EVP_PKEY *protector_evp_key = X509_get_pubkey(endorsement_cert);
  RSA      *protector_key = EVP_PKEY_get1_RSA(protector_evp_key);
  RSA_up_ref(protector_key);

  // 2. Secret= E(protector_key, seed || "IDENTITY")
  //   args: to, from, label, len
  int    size_secret_buf = 256;
  byte_t secret_buf[size_secret_buf];
  int    size_encrypted_secret = 512;
  byte_t encrypted_secret_buf[size_encrypted_secret];

  memset(secret_buf, 0, size_secret_buf);
  memset(encrypted_secret_buf, 0, size_encrypted_secret);

  int m = RSA_padding_add_PKCS1_OAEP(secret_buf,
                                     256,
                                     seed,
                                     size_seed,
                                     (byte_t *)"IDENTITY",
                                     strlen("IDENTITY") + 1);
  if (m <= 0) {
    printf("%s() error, line %d, RSA_padding_add_PKCS1_OAEP fails\n",
           __func__,
           __LINE__);
    return false;
  }
#ifdef DEBUG
  printf("\n");
  X509_print_fp(stdout, endorsement_cert);
  printf("\n");
  printf("seed (%d): ", size_seed);
  print_bytes(size_seed, seed);
  printf("\n");
  printf("padded (%d):\n", m);
  print_bytes(size_secret_buf, secret_buf);
  printf("\n\n");
#endif

  int n = RSA_public_encrypt(size_secret_buf,
                             secret_buf,
                             encrypted_secret_buf,
                             protector_key,
                             RSA_NO_PADDING);
  if (n <= 0) {
    printf("%s() error, line %d, RSA_public_encrypt fails\n",
           __func__,
           __LINE__);
    return false;
  }
  encrypted_secret->assign((char *)encrypted_secret_buf, n);

  byte_t symKey[MAX_SIZE_PARAMS];
  string label;
  string salt;
  string contextU;
  string contextV;

  // 3. Calculate symKey
  // KDFa(ekNameAlg, seed, "STORAGE", name, NULL, bits)
  label = "STORAGE";
  salt.assign((const char *)seed, size_seed);
  contextU.assign((char *)quote_key_name.data(), quote_key_name.size());
  contextV.clear();

  string   sym_key;
  uint32_t size_symKey_bits = 128;

  if (!kdfa(hash_alg_id,
            salt,
            label,
            contextU,
            contextV,
            size_symKey_bits,
            &sym_key)) {
    printf("%s() error, line %d, Can't KDFa symKey\n", __func__, __LINE__);
    return false;
  }

  int size_symKey = size_symKey_bits / 8;
  memcpy(symKey, (byte_t *)sym_key.data(), size_symKey);
#ifdef DEBUG
  printf("\nsymKey (%d)      : ", size_symKey);
  print_bytes(size_symKey, symKey);
  printf("\n");
#endif

  // 4. encIdentity
  TPM2B_DIGEST marshaled_credential;
  int          size_encIdentity = 256;
  byte_t       encIdentity[size_encIdentity];
  uint16_t     c_size = credential.size();
  change_endian16((uint16_t *)&c_size, (uint16_t *)&marshaled_credential.size);
  memcpy(marshaled_credential.buffer, (byte_t *)credential.data(), c_size);
  if (!AesCFBEncrypt(symKey,
                     credential.size() + sizeof(uint16_t),
                     (byte_t *)&marshaled_credential,
                     16,
                     zero_iv,
                     &size_encIdentity,
                     encIdentity)) {
    printf("%s() error, line %d, Can't AesCFBEncrypt\n", __func__, __LINE__);
    return false;
  }
#ifdef DEBUG
  printf("encIdentity (%d) : ", size_encIdentity);
  print_bytes(size_encIdentity, encIdentity);
  printf("\n");
#endif

  int    size_hmacKey = SizeHash(hash_alg_id);
  byte_t hmacKey[128];

  // 5. HMACkey ≔ KDFa (ekNameAlg, seed, “INTEGRITY”, NULL, NULL, bits)
  TPM_ALG_ID   ekNameAlg = hash_alg_id;
  TPM2B_DIGEST unmarshaled_integrityHmac;
  TPM2B_DIGEST marshaled_integrityHmac;

  // KDFa(ekNameAlg, seed, "INTEGRITY", NULL, NULL, bits)
  label = "INTEGRITY";
  string hmac_key;
  contextU.clear();
  contextV.clear();

  contextV.clear();
  if (!kdfa(hash_alg_id,
            salt,
            label,
            contextU,
            contextV,
            8 * size_hmacKey,
            &hmac_key)) {
    printf("%s() error, line %d, Can't KDFa symKey\n", __func__, __LINE__);
    return false;
  }
  memcpy(hmacKey, (byte_t *)hmac_key.data(), size_hmacKey);
#ifdef DEBUG
  printf("hmacKey (%d)     : ", size_hmacKey);
  print_bytes(size_hmacKey, hmacKey);
  printf("\n");
#endif

  // 6. Calculate outerMac = HMAC(hmacKey, encIdentity || name);
  HMAC_CTX *hctx = HMAC_CTX_new();
  if (hctx == nullptr) {
    printf("%s() error, line %d, Can't get hmac context\n", __func__, __LINE__);
    return false;
  }

  if (hash_alg_id != TPM_ALG_SHA256) {
    printf("%s() error, line %d, unsupported hmac\n", __func__, __LINE__);
    return false;
  }

  HMAC_Init_ex(hctx, hmacKey, size_hmacKey, EVP_sha256(), nullptr);
  HMAC_Update(hctx, (const byte_t *)encIdentity, (size_t)size_encIdentity);
  HMAC_Update(hctx,
              (const byte_t *)quote_key_name.data(),
              quote_key_name.size());
  unmarshaled_integrityHmac.size = size_hmacKey;
  HMAC_Final(hctx, unmarshaled_integrityHmac.buffer, (uint32_t *)&size_hmacKey);
  HMAC_CTX_free(hctx);
#ifdef DEBUG
  printf("Outer Mac (%d)   : ", size_hmacKey);
  print_bytes(size_hmacKey, unmarshaled_integrityHmac.buffer);
  printf("\n");
#endif

  // credBlob: (20 bytes) || hmac || encrypted
  uint16_t bsize = size_hmacKey;
  uint16_t csize = 0;
  change_endian16(&bsize, &csize);
  cred_blob->assign((char *)&csize, 2);
  cred_blob->append((char *)unmarshaled_integrityHmac.buffer, size_hmacKey);
  cred_blob->append((char *)encIdentity, size_encIdentity);

#ifdef DEBUG2
  printf("\nencIdentity: ");
  print_bytes(size_encIdentity, (byte_t *)encIdentity);
  printf("\n");
  printf("hmac       : ");
  print_bytes(size_hmacKey, (byte_t *)unmarshaled_integrityHmac.buffer);
  printf("\n");
  printf("encrypted secret:\n");
  print_bytes(encrypted_secret->size(), (byte_t *)encrypted_secret->data());
  printf("\n");
  printf("credBlob (%d): ", (int)cred_blob->size());
  print_bytes(cred_blob->size(), (byte_t *)cred_blob->data());
  printf("\n");
#endif
  return true;
}

// This is the code on the client that requests a quote
// key certificate using make credential on a provider
// without a tpm
bool make_credential_message(const key_message &quote_public_key,
                             const string      &measurement,
                             const string      &quote_public_area,
                             string            *serialized_credential_request) {
  return false;
}

// This is the code on the client which obtains the quote
// key certificate from the make credential message constructed
// on the provider using ActivateCredential
bool recover_quote_key_certificate(const string &serialized_cred_response,
                                   string       *cert) {
  return false;
}

// ------------------------------------------------------------------------

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

#ifdef DEBUG
  printf("TPM MakeCredential succeeded\n");
  printf("credBlob size: %d\n", credentialBlob.size);
  print_bytes(credentialBlob.size, credentialBlob.credential);
  printf("\n");
  printf("secret size: %d\n", secret.size);
  print_bytes(secret.size, secret.secret);
  printf("\n");
  printf("Policy: ");
  print_bytes(quoting_pub_out.publicArea.authPolicy.size,
              quoting_pub_out.publicArea.authPolicy.buffer);
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

#define TPMMAKECRED
#ifdef TPMMAKECRED
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
#endif

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

#ifdef DEBUG
  printf("\nStandalone MakeCredential succeeded\n");
  printf("credBlob size: %d\n", (int)cred_blob_out.size());
  print_bytes(cred_blob_out.size(), (byte_t *)cred_blob_out.data());
  printf("\n");
  printf("secret size: %d\n", (int)encrypted_secret_out.size());
  print_bytes(encrypted_secret_out.size(),
              (byte_t *)encrypted_secret_out.data());
  printf("\n");
#endif

  memset((byte_t *)&recovered_credential, 0, sizeof(recovered_credential));
  memset((byte_t *)&credentialBlob, 0, sizeof(credentialBlob));
  memset((byte_t *)&secret, 0, sizeof(secret));
  credentialBlob.size = cred_blob_out.size();
  memcpy(credentialBlob.credential,
         (byte_t *)cred_blob_out.data(),
         cred_blob_out.size());
  secret.size = encrypted_secret_out.size();
  memcpy(secret.secret,
         (byte_t *)encrypted_secret_out.data(),
         encrypted_secret_out.size());
#ifndef TPMMAKECRED
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
#endif


  Tpm2_FlushContext(tpm, ek_handle);
  Tpm2_FlushContext(tpm, endorsement_session_handle);
  return true;
}

// ------------------------------------------------------------------------
