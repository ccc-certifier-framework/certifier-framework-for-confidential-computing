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
// Portions of this code were derived TPM2.0-TSS published
// by Intel under the license set forth in intel_license.txt
// and downloaded on or about August 6, 2015.
// Portions of this code were derived tboot published
// by Intel under the license set forth in intel_license.txt
// and downloaded on or about August 6, 2015.
// Portions of this code were derived from the crypto utility
// published by John Manferdelli under the Apache 2.0 license.
// See github.com/jlmucb/crypto.
// File: tpm2_support.cc

bool endorsement_test(local_tpm& tpm) {
  string authString("01020304");
  string srkAuth("01020304");
  string emptyAuth;

  TPM_HANDLE ekHandle;
  TPM2B_PUBLIC pub_out;
  TPM2B_NAME pub_name;
  TPM2B_NAME qualified_pub_name;
  uint16_t pub_blob_size = 4096;
  byte_t pub_blob[pub_blob_size];

  TPML_PCR_SELECTION pcrSelect;
  memset((void*)&pcrSelect, 0, sizeof(TPML_PCR_SELECTION));

  // TPM_RH_ENDORSEMENT
  TPMA_OBJECT primary_flags;
  *(uint32_t*)(&primary_flags) = 0;
  primary_flags.fixedTPM = 1;
  primary_flags.fixedParent = 1;
  primary_flags.sensitiveDataOrigin = 1;
  primary_flags.userWithAuth = 1;
  primary_flags.decrypt = 1;
  primary_flags.restricted = 1;

  // Create Endorsement key with handle ekHandle
  if (Tpm2_CreatePrimary(tpm, TPM_RH_ENDORSEMENT, emptyAuth, pcrSelect,
                         TPM_ALG_RSA, TPM_ALG_SHA256, primary_flags,
                         TPM_ALG_AES, 256, TPM_ALG_CFB, TPM_ALG_NULL,
                         2048, 0x010001, &ekHandle, &pub_out)) {
    printf("CreatePrimary succeeded primary: %08x\n", ekHandle);
  } else {
    printf("CreatePrimary failed --- primary key\n");
    return false;
  }
  if (Tpm2_ReadPublic(tpm, ekHandle, &pub_blob_size, pub_blob,
                      &pub_out, &pub_name, &qualified_pub_name)) {
    printf("ReadPublic succeeded\n");
  } else {
    printf("ReadPublic failed\n");
    return false;
  }
  printf("Public blob: ");
  PrintBytes(pub_blob_size, pub_blob);
  printf("\n");
  printf("\nName: ");
  PrintBytes(pub_name.size, pub_name.name);
  printf("\n");
  printf("Qualified name: ");
  PrintBytes(qualified_pub_name.size, qualified_pub_name.name);
  printf("\n");
  printf("\n");
  printf("Pubout size: %d\n", pub_out.size);
  printf("Type: %d\n", pub_out.publicArea.type);
  printf("Name: %d\n", pub_out.publicArea.nameAlg);
  printf("Scheme: %d\n", pub_out.publicArea.parameters.rsaDetail.scheme.scheme);
  printf("Bytes (%d):\n", (int)pub_out.publicArea.unique.rsa.size);
  PrintBytes((int)pub_out.publicArea.unique.rsa.size,
             (byte_t*)pub_out.publicArea.unique.rsa.buffer);
  printf("\n");
  printf("Exponent: %d\n", pub_out.publicArea.parameters.rsaDetail.exponent);
  printf("\n");

  TPM_HANDLE srkHandle;
  TPM_HANDLE quotingHandle;
  TPM2B_PUBLIC srk_pub_out;
  TPML_PCR_SELECTION srk_pcrSelect;
  init_single_pcr_selection(7, TPM_ALG_SHA256, &srk_pcrSelect);

  TPMA_OBJECT srk_flags;
  *(uint32_t*)(&srk_flags) = 0;
  srk_flags.fixedTPM = 1;
  srk_flags.fixedParent = 1;
  srk_flags.sensitiveDataOrigin = 1;
  srk_flags.userWithAuth = 1;
  srk_flags.decrypt = 1;
  srk_flags.restricted = 1;

  // Storage root key
  init_single_pcr_selection(7, TPM_ALG_SHA256, &pcrSelect);
  if (Tpm2_CreatePrimary(tpm, TPM_RH_OWNER, authString, srk_pcrSelect,
                         TPM_ALG_RSA, TPM_ALG_SHA256, srk_flags,
                         TPM_ALG_AES, 256, TPM_ALG_CFB, TPM_ALG_NULL,
                         2048, 0x010001,
                         &srkHandle, &srk_pub_out)) {
    printf("CreatePrimary second key succeeded\n");
  } else {
    printf("CreatePrimary failed - second key\n");
    return false;
  }

  // TODO: Save this key for reloading when we quote

  TPM2B_CREATION_DATA creation_out;
  TPM2B_DIGEST digest_out;
  TPMT_TK_CREATION creation_ticket;
  int size_public = MAX_SIZE_PARAMS;
  byte_t out_public[MAX_SIZE_PARAMS];
  int size_private = MAX_SIZE_PARAMS;
  byte_t out_private[MAX_SIZE_PARAMS];

  memset((void*)&pub_out, 0, sizeof(TPM2B_PUBLIC));

  TPMA_OBJECT quoting_flags;
  *(uint32_t*)(&quoting_flags) = 0;
  quoting_flags.fixedTPM = 1;
  quoting_flags.fixedParent = 1;
  quoting_flags.sensitiveDataOrigin = 1;
  quoting_flags.userWithAuth = 1;
  quoting_flags.sign = 1;
  quoting_flags.restricted = 1;

  // Create the Quote Key
  if (Tpm2_CreateKey(tpm, srkHandle, srkAuth, authString,
                     srk_pcrSelect,
                     TPM_ALG_RSA, TPM_ALG_SHA256, quoting_flags, TPM_ALG_NULL,
                     (TPMI_AES_KEY_BITS)0, TPM_ALG_ECB, TPM_ALG_RSASSA,
                     2048, 0x010001, &size_public, out_public,
                     &size_private, out_private,
                     &creation_out, &digest_out, &creation_ticket)) {
    printf("CreateKey succeeded private size: %d, public size: %d\n",
           size_private, size_public);
  } else {
    printf("CreateKey failed\n");
    return false;
  }

  // Load Quote key
  if (Tpm2_Load(tpm, srkHandle, srkAuth, size_public, out_public,
               size_private, out_private, &quotingHandle, &pub_name)) {
    printf("Load succeeded, handle: %08x\n", quotingHandle);
  } else {
    Tpm2_FlushContext(tpm, ekHandle);
    Tpm2_FlushContext(tpm, srkHandle);
    printf("Load failed\n");
    return false;
  }

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
  PrintBytes(quoting_pub_name.size, quoting_pub_name.name);
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
    PrintBytes(recovered_credential.size, recovered_credential.buffer);
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
  return true;
}

bool context_test(local_tpm& tpm) {
  TPM_HANDLE handle;
  uint16_t size = 4096;
  byte_t saveArea[4096];
  string authString("01020304");

  TPM2B_PUBLIC pub_out;
  TPML_PCR_SELECTION pcrSelect;
  init_single_pcr_selection(7, TPM_ALG_SHA1, &pcrSelect);

  TPMA_OBJECT primary_flags;
  *(uint32_t*)(&primary_flags) = 0;
  primary_flags.fixedTPM = 1;
  primary_flags.fixedParent = 1;
  primary_flags.sensitiveDataOrigin = 1;
  primary_flags.userWithAuth = 1;
  primary_flags.sign = 1;

  if (Tpm2_CreatePrimary(tpm, TPM_RH_OWNER, authString, pcrSelect,
                         TPM_ALG_RSA, TPM_ALG_SHA256, primary_flags, TPM_ALG_NULL,
                         (TPMI_AES_KEY_BITS)0, TPM_ALG_ECB, TPM_ALG_RSASSA,
                         1024, 0x010001,
                         &handle, &pub_out)) {
    printf("CreatePrimary succeeded\n");
  } else {
    printf("CreatePrimary failed\n");
    return false;
  }
  if (Tpm2_SaveContext(tpm, handle, &size, saveArea)) {
    printf("Tpm2_SaveContext succeeds, save area %d\n", size);
  } else {
    printf("Tpm2_SaveContext failed\n");
    return false;
  }
  if (Tpm2_FlushContext(tpm, handle)) {
    printf("Tpm2_FlushContext succeeds, save area %d\n", size);
  } else {
    printf("Tpm2_FlushContext failed\n");
    return false;
  }
  handle = 0;
  if (Tpm2_LoadContext(tpm, size, saveArea, &handle)) {
    printf("Tpm2_LoadContext succeeds, handle: %08x, save area %d\n",
           handle, size);
  } else {
    printf("Tpm2_LoadContext failed\n");
    return false;
  }
  Tpm2_FlushContext(tpm, handle);
  return true;
}

bool nv_test(local_tpm& tpm) {
  int slot = 1000;
  string authString("01020304");
  uint16_t size_data = 16;
  byte_t data_in[512] = {
    0x9, 0x8, 0x7, 0x6,
    0x9, 0x8, 0x7, 0x6,
    0x9, 0x8, 0x7, 0x6,
    0x9, 0x8, 0x7, 0x6
  };
  uint16_t size_out = 512;
  byte_t data_out[512];
  TPM_HANDLE nv_handle = GetNvHandle(slot);

  if (Tpm2_UndefineSpace(tpm, TPM_RH_OWNER, nv_handle)) {
    printf("Tpm2_UndefineSpace %d succeeds\n", slot);
  } else {
    printf("Tpm2_UndefineSpace fails (but that's OK usually)\n");
  }
  if (Tpm2_DefineSpace(tpm, TPM_RH_OWNER, nv_handle, authString, 0, nullptr,
                       NV_AUTHWRITE | NV_AUTHREAD, size_data) ) {
    printf("Tpm2_DefineSpace %d succeeds\n", nv_handle);
  } else {
    printf("Tpm2_DefineSpace fails\n");
    return false;
  }
  if (Tpm2_WriteNv(tpm, nv_handle, authString, size_data, data_in)) {
    printf("Tpm2_WriteNv %d succeeds, %d bytes written\n", nv_handle, size_data);
  } else {
    printf("Tpm2_WriteNv fails\n");
    return false;
  }
  size_out = size_data;
  if (Tpm2_ReadNv(tpm, nv_handle, authString, &size_out, data_out)) {
    printf("Tpm2_ReadNv %d succeeds: ", nv_handle);
    PrintBytes(size_out, data_out);
    printf("\n");
  } else {
    printf("Tpm2_ReadNv fails\n");
    return false;
  }

  size_data = 8;
  memset(data_out, 0, 16);
  // Counter tests
  printf("\n\nCounter tests\n");
  if (Tpm2_UndefineSpace(tpm, TPM_RH_OWNER, nv_handle)) {
    printf("Tpm2_UndefineSpace %d succeeds\n", slot);
  } else {
    printf("Tpm2_UndefineSpace fails (but that's OK usually)\n");
  }
  // Should be AuthRead, AuthWrite, Counter, Sha256
  if (Tpm2_DefineSpace(tpm, TPM_RH_OWNER, nv_handle, authString, 0, nullptr,
                       NV_COUNTER | NV_AUTHWRITE | NV_AUTHREAD, 8)) {
    printf("Tpm2_DefineSpace %d succeeds\n", nv_handle);
  } else {
    printf("Tpm2_DefineSpace fails\n");
    return false;
  }
  if (Tpm2_IncrementNv(tpm, nv_handle, authString)) {
    printf("Tpm2_IncrementNv succeeds\n");
  } else {
    printf("Tpm2_IncrementNv fails\n");
  }
  size_out = size_data;
  if (Tpm2_ReadNv(tpm, nv_handle, authString, &size_out, data_out)) {
    printf("Tpm2_ReadNv succeeds\n");
    printf("Counter value: "); PrintBytes(size_out, data_out); printf("\n");
  } else {
    printf("Tpm2_ReadNv fails\n");
  }
  if (Tpm2_IncrementNv(tpm, nv_handle, authString)) {
    printf("Tpm2_IncrementNv succeeds\n");
  } else {
    printf("Tpm2_IncrementNv fails\n");
  }
  if (Tpm2_ReadNv(tpm, nv_handle, authString, &size_out, data_out)) {
    printf("Tpm2_ReadNv succeeds\n");
    printf("Counter value: "); PrintBytes(size_out, data_out); printf("\n");
  } else {
    printf("Tpm2_ReadNv fails\n");
  }
  if (Tpm2_UndefineSpace(tpm, TPM_RH_OWNER, nv_handle)) {
    printf("Tpm2_UndefineSpace %d succeeds\n", slot);
  } else {
    printf("Tpm2_UndefineSpace fails (but that's OK usually)\n");
  }

  return true;
}

bool key_test(local_tpm& tpm, int pcr_num) {
  string authString("01020304");
  string parentAuth("01020304");
  string emptyAuth;

  TPM_HANDLE parent_handle;
  TPM2B_PUBLIC pub_out;
  TPML_PCR_SELECTION pcrSelect;
  init_single_pcr_selection(pcr_num, TPM_ALG_SHA1, &pcrSelect);

  TPMA_OBJECT primary_flags;
  *(uint32_t*)(&primary_flags) = 0;
  primary_flags.fixedTPM = 1;
  primary_flags.fixedParent = 1;
  primary_flags.sensitiveDataOrigin = 1;
  primary_flags.userWithAuth = 1;
  primary_flags.decrypt = 1;
  primary_flags.restricted = 1;

  if (Tpm2_CreatePrimary(tpm, TPM_RH_OWNER, authString, pcrSelect,
                         TPM_ALG_RSA, TPM_ALG_SHA1, primary_flags,
                         TPM_ALG_AES, 128, TPM_ALG_CFB, TPM_ALG_NULL,
                         1024, 0x010001,
                         &parent_handle, &pub_out)) {
    printf("CreatePrimary succeeded\n");
  } else {
    printf("CreatePrimary failed\n");
    return false;
  }
  TPM2B_CREATION_DATA creation_out;
  TPM2B_DIGEST digest_out;
  TPMT_TK_CREATION creation_ticket;
  int size_public = MAX_SIZE_PARAMS;
  byte_t out_public[MAX_SIZE_PARAMS];
  int size_private = MAX_SIZE_PARAMS;
  byte_t out_private[MAX_SIZE_PARAMS];

  TPMA_OBJECT create_flags;
  *(uint32_t*)(&create_flags) = 0;
  create_flags.fixedTPM = 1;
  create_flags.fixedParent = 1;
  create_flags.sensitiveDataOrigin = 1;
  create_flags.userWithAuth = 1;
  create_flags.sign = 1;

  if (Tpm2_CreateKey(tpm, parent_handle, parentAuth, authString, pcrSelect,
                     TPM_ALG_RSA, TPM_ALG_SHA1, create_flags, TPM_ALG_NULL,
                     (TPMI_AES_KEY_BITS)0, TPM_ALG_ECB, TPM_ALG_RSASSA,
                     1024, 0x010001, &size_public, out_public,
                     &size_private, out_private,
                     &creation_out, &digest_out, &creation_ticket)) {
    printf("Create succeeded private size: %d, public size: %d\n",
           size_private, size_public);
  } else {
    printf("Create failed\n");
    return false;
  }

  TPM_HANDLE load_handle = 0;
  TPM2B_NAME name;
  if (Tpm2_Load(tpm, parent_handle, parentAuth, size_public, out_public,
               size_private, out_private, &load_handle, &name)) {
    printf("Load succeeded, handle: %08x\n", load_handle);
  } else {
    Tpm2_FlushContext(tpm, parent_handle);
    printf("Load failed\n");
    return false;
  }
  TPM2B_DATA qualifyingData;
  TPM2B_ATTEST attest;
  TPMT_SIGNATURE sig;
  qualifyingData.size = 3;
  qualifyingData.buffer[0] = 5;
  qualifyingData.buffer[1] = 6;
  qualifyingData.buffer[2] = 7;
  if (Tpm2_Certify(tpm, load_handle, load_handle,
                  parentAuth, parentAuth,
                  qualifyingData, &attest, &sig)) {
    printf("Certify succeeded\n");
    printf("attested (%d): ", attest.size);
    PrintBytes(attest.size, attest.attestationData);
    printf("\n");
    printf("signature (%d %d %d): ", sig.sigAlg, sig.signature.rsassa.hash,
           sig.signature.rsassa.sig.size);
    PrintBytes(sig.signature.rsassa.sig.size, sig.signature.rsassa.sig.buffer);
    printf("\n");
  } else {
    Tpm2_FlushContext(tpm, load_handle);
    Tpm2_FlushContext(tpm, parent_handle);
    printf("Certify failed\n");
    return false;
  }

  // evict Control
  TPM_HANDLE persistant_handle = 0x810003e8;

  if (!Tpm2_EvictControl(tpm, TPM_RH_OWNER, persistant_handle,
                         authString, persistant_handle)) {
  printf("Tpm2_EvictControl first evicting fails\n");
  } else {
    printf("Tpm2_EvictControl first evicting succeeds\n");
  }

  // make control permanent
  if (!Tpm2_EvictControl(tpm, TPM_RH_OWNER, load_handle, authString,
                       persistant_handle)) {
    printf("Tpm2_EvictControl fails\n");
  } else {
    printf("Tpm2_EvictControl succeeds %08x\n", persistant_handle);
  }

  // evict it again
  if (!Tpm2_EvictControl(tpm, TPM_RH_OWNER, persistant_handle,
                         authString, persistant_handle)) {
  printf("Tpm2_EvictControl second evicting fails\n");
  } else {
    printf("Tpm2_EvictControl second evicting succeeds\n");
  }

  if (load_handle != 0)
    Tpm2_FlushContext(tpm, load_handle);
  Tpm2_FlushContext(tpm, parent_handle);
  return true;
}

bool seal_test(local_tpm& tpm, int pcr_num) {
  string authString("01020304");
  string parentAuth("01020304");
  string emptyAuth;

  TPM_HANDLE parent_handle;
  TPM2B_PUBLIC pub_out;
  TPML_PCR_SELECTION pcrSelect;
  init_single_pcr_selection(pcr_num, TPM_ALG_SHA256, &pcrSelect);

  TPMA_OBJECT primary_flags;
  *(uint32_t*)(&primary_flags) = 0;
  primary_flags.fixedTPM = 1;
  primary_flags.fixedParent = 1;
  primary_flags.sensitiveDataOrigin = 1;
  primary_flags.userWithAuth = 1;
  primary_flags.decrypt = 1;
  primary_flags.restricted = 1;

  // Creating a new SRK
  if (Tpm2_CreatePrimary(tpm, TPM_RH_OWNER, authString, pcrSelect, 
                         TPM_ALG_RSA, TPM_ALG_SHA256, primary_flags,
                         TPM_ALG_AES, 256, TPM_ALG_CFB, TPM_ALG_NULL,
                         2048, 0x010001,
                        &parent_handle, &pub_out)) {
    printf("CreatePrimary succeeded\n");
  } else {
    printf("CreatePrimary failed\n");
    return false;
  }
  TPM2B_DIGEST secret;
  secret.size = 32;
  if (!Tpm2_GetRandom(tpm, secret.size, secret.buffer)) {
    printf("Can't get random key\n");
    return false;
  }
  printf("Secret: ");
  PrintBytes(secret.size, secret.buffer);
  printf("\n");

  TPM2B_CREATION_DATA creation_out;
  TPMT_TK_CREATION creation_ticket;
  int size_public = MAX_SIZE_PARAMS;
  byte_t out_public[MAX_SIZE_PARAMS];
  int size_private = MAX_SIZE_PARAMS;
  byte_t out_private[MAX_SIZE_PARAMS];

  TPM2B_DIGEST digest_out;
  TPM2B_NONCE initial_nonce;
  TPM2B_ENCRYPTED_SECRET salt;
  TPMT_SYM_DEF symmetric;
  TPM_HANDLE session_handle;
  TPM2B_NONCE nonce_obj;

  initial_nonce.size = 16;
  memset(initial_nonce.buffer, 0, initial_nonce.size);
  salt.size = 0;
  symmetric.algorithm = TPM_ALG_NULL;
 
  // In a real use, we need to create a session when
  // we make the key (like here) AND when we use it.

  // Start auth session
  if (Tpm2_StartAuthSession(tpm, TPM_RH_NULL, TPM_RH_NULL,
                            initial_nonce, salt, TPM_SE_POLICY,
                            symmetric, TPM_ALG_SHA256, &session_handle,
                            &nonce_obj)) {
    printf("Tpm2_StartAuthSession succeeds handle: %08x\n",
           session_handle);
    printf("nonce (%d): ", nonce_obj.size);
    PrintBytes(nonce_obj.size, nonce_obj.buffer);
    printf("\n");
  } else {
    printf("Tpm2_StartAuthSession fails\n");
    return false;
  }

  TPM2B_DIGEST policy_digest;
  // get policy digest
  if(Tpm2_PolicyGetDigest(tpm, session_handle, &policy_digest)) {
    printf("PolicyGetDigest before Pcr succeeded: ");
    PrintBytes(policy_digest.size, policy_digest.buffer); printf("\n");
  } else {
    Tpm2_FlushContext(tpm, session_handle);
    printf("PolicyGetDigest failed\n");
    return false;
  }

  if (Tpm2_PolicyPassword(tpm, session_handle)) {
    printf("PolicyPassword succeeded\n");
  } else {
    Tpm2_FlushContext(tpm, session_handle);
    printf("PolicyPassword failed\n");
    return false;
  }

  TPM2B_DIGEST expected_digest;
  expected_digest.size = 0;
  if (Tpm2_PolicyPcr(tpm, session_handle,
                     expected_digest, pcrSelect)) {
    printf("PolicyPcr succeeded\n");
  } else {
    printf("PolicyPcr failed\n");
    Tpm2_FlushContext(tpm, session_handle);
    return false;
  }

  if(Tpm2_PolicyGetDigest(tpm, session_handle, &policy_digest)) {
    printf("PolicyGetDigest succeeded: ");
    PrintBytes(policy_digest.size, policy_digest.buffer); printf("\n");
  } else {
    printf("PolicyGetDigest failed\n");
    return false;
  }

  TPMA_OBJECT create_flags;
  *(uint32_t*)(&create_flags) = 0;
  create_flags.fixedTPM = 1;
  create_flags.fixedParent = 1;

  // Creating new sealed key
  if (Tpm2_CreateSealed(tpm, parent_handle, policy_digest.size,
                        policy_digest.buffer, parentAuth, secret.size,
                        secret.buffer, pcrSelect, TPM_ALG_SHA256, create_flags,
                        TPM_ALG_NULL, (TPMI_AES_KEY_BITS)0, TPM_ALG_ECB,
                        TPM_ALG_RSASSA, 2048, 0x010001,
                        &size_public, out_public, &size_private, out_private,
                        &creation_out, &digest_out, &creation_ticket)) {
    printf("Create with digest succeeded private size: %d, public size: %d\n",
           size_private, size_public);
  } else {
    printf("Create with digest failed\n");
    Tpm2_FlushContext(tpm, session_handle);
    return false;
  }

  // Usually, we'd save the new SRK and sealing key
  // when creating and then reload them using a
  // recreated auth session like the one above.

  TPM_HANDLE load_handle;
  TPM2B_NAME name;
  if (Tpm2_Load(tpm, parent_handle, parentAuth, size_public, out_public,
               size_private, out_private, &load_handle, &name)) {
    printf("Load succeeded\n");
  } else {
    printf("Load failed\n");
    Tpm2_FlushContext(tpm, session_handle);
    return false;
  }

  int unsealed_size = MAX_SIZE_PARAMS;
  byte_t unsealed[MAX_SIZE_PARAMS];
  TPM2B_DIGEST hmac;
  hmac.size = 0;
  if (!Tpm2_Unseal(tpm, load_handle, parentAuth, session_handle,
                   nonce_obj, 0x01, hmac,
                   &unsealed_size, unsealed)) {
    printf("Unseal failed\n");
    Tpm2_FlushContext(tpm, session_handle);
    Tpm2_FlushContext(tpm, load_handle);
    return false;
  }
  printf("Unseal succeeded, unsealed (%d): ", unsealed_size); 
  PrintBytes(unsealed_size, unsealed);
  printf("\n"); 

  TPM2B_SENSITIVE_DATA* unsealed_return = (TPM2B_SENSITIVE_DATA*)(&unsealed[2]);
  uint16_t ss;
  change_endian16(&unsealed_return->size, &ss);
  printf("Sensitive data size: %d\n", ss);
  TPM2B_DATA* sym = (TPM2B_DATA*) unsealed_return->buffer;
  uint16_t sb;
  change_endian16(&sym->size, &sb);
  printf("Buffer (%d): ", sb);
  PrintBytes(sb, sym->buffer);
  printf("\n");

  if  (memcmp(secret.buffer, sym->buffer, sb) == 0) {
    printf("unsealed string matches\n");
  } else {
    printf("unsealed string DOES NOT matches\n");
  }

  Tpm2_FlushContext(tpm, session_handle);
  Tpm2_FlushContext(tpm, load_handle);
  return true;
}

bool quote_test(local_tpm& tpm, int pcr_num) {
  string authString("01020304");
  string parentAuth("01020304");
  string emptyAuth;

  // Usually, we'd just load the SRK created in
  // the endorsement test and the quoting key
  // rather than making new ones.

  TPM_HANDLE parent_handle;
  TPM2B_PUBLIC pub_out;
  TPML_PCR_SELECTION pcr_selection;
  init_single_pcr_selection(pcr_num, TPM_ALG_SHA256, &pcr_selection);

  TPMA_OBJECT primary_flags;
  *(uint32_t*)(&primary_flags) = 0;
  primary_flags.fixedTPM = 1;
  primary_flags.fixedParent = 1;
  primary_flags.sensitiveDataOrigin = 1;
  primary_flags.userWithAuth = 1;
  primary_flags.decrypt = 1;
  primary_flags.restricted = 1;

  // Storage root key
  if (Tpm2_CreatePrimary(tpm, TPM_RH_OWNER, authString, pcr_selection, 
                         TPM_ALG_RSA, TPM_ALG_SHA256, primary_flags,
                         TPM_ALG_AES, 256, TPM_ALG_CFB, TPM_ALG_NULL,
                         2048, 0x010001,
                         &parent_handle, &pub_out)) {
    printf("CreatePrimary succeeded 1 (2048)\n");
  } else {
    printf("CreatePrimary failed\n");
    return false;
  }

  if (pcr_num >= 0) {
    uint16_t size_eventData = 3;
    byte_t eventData[3] = {1, 2, 3};
    if (Tpm2_PCR_Event(tpm, pcr_num, size_eventData, eventData)) {
      printf("Tpm2_PCR_Event succeeded\n");
    } else {
      printf("Tpm2_PCR_Event failed\n");
    }
  }

  TPM2B_CREATION_DATA creation_out;
  TPMT_TK_CREATION creation_ticket;
  int size_public = MAX_SIZE_PARAMS;
  byte_t out_public[MAX_SIZE_PARAMS];
  int size_private = MAX_SIZE_PARAMS;
  byte_t out_private[MAX_SIZE_PARAMS];
  TPM2B_DIGEST digest_out;

  TPMA_OBJECT create_flags;
  *(uint32_t*)(&create_flags) = 0;
  create_flags.fixedTPM = 1;
  create_flags.fixedParent = 1;
  create_flags.sensitiveDataOrigin = 1;
  create_flags.userWithAuth = 1;
  create_flags.sign = 1;
  create_flags.restricted = 1;

  // Quote key
  if (Tpm2_CreateKey(tpm, parent_handle, parentAuth, authString, pcr_selection,
                     TPM_ALG_RSA, TPM_ALG_SHA256, create_flags, TPM_ALG_NULL,
                     (TPMI_AES_KEY_BITS)256, TPM_ALG_ECB, TPM_ALG_RSASSA,
                     2048, 0x010001,
                     &size_public, out_public, &size_private, out_private,
                     &creation_out, &digest_out, &creation_ticket)) {
    printf("CreateKey succeeded, private size: %d, public size: %d\n",
           size_private, size_public);
  } else {
    printf("Create failed\n");
    return false;
  }

  TPM_HANDLE load_handle;
  TPM2B_NAME name;
  if (Tpm2_Load(tpm, parent_handle, parentAuth, size_public, out_public,
               size_private, out_private, &load_handle, &name)) {
    printf("Load succeeded\n");
  } else {
    printf("Load failed\n");
    return false;
  }

  TPM2B_DATA to_quote;
  to_quote.size = 32;
  for  (int i = 0; i < to_quote.size; i++)
    to_quote.buffer[i] = (byte_t)(i + 1);
  TPMT_SIG_SCHEME scheme;

  int quote_size = MAX_SIZE_PARAMS;
  byte_t quoted[MAX_SIZE_PARAMS];
  int sig_size = MAX_SIZE_PARAMS;
  byte_t sig[MAX_SIZE_PARAMS];
  if (!Tpm2_Quote(tpm, load_handle, authString,
                  to_quote.size, to_quote.buffer,
                  scheme, pcr_selection, TPM_ALG_RSA, TPM_ALG_SHA256,
                  &quote_size, quoted, &sig_size, sig)) {
    printf("Quote failed, pcr_num: %d\n", pcr_num);
    Tpm2_FlushContext(tpm, load_handle);
    Tpm2_FlushContext(tpm, parent_handle);
    return false;
  }
  printf("Quote succeeded, quoted (%d): ", quote_size); 
  PrintBytes(quote_size, quoted);
  printf("\n"); 
  printf("Sig (%d): ", sig_size); 
  PrintBytes(sig_size, sig);
  printf("\n"); 
  Tpm2_FlushContext(tpm, load_handle);
  Tpm2_FlushContext(tpm, parent_handle);
  return true;
}

void seperate_key_test() {
  RSA* rsa_key = RSA_generate_key(2048, 0x010001ULL, nullptr, nullptr);
  if (rsa_key == nullptr) {
    printf("Can't generate RSA key\n");
    return;
  }
  TPM2B_DIGEST secret;
  TPM2B_ENCRYPTED_SECRET salt;
  secret.size = 20;
  memcpy(secret.buffer, (byte_t*)"12345678901234567890", secret.size);

// Encrypt salt
  printf("\nencrypting salt\n");
  int size_padded_secret= 256;
  byte_t padded_secret[256];
  RSA_padding_add_PKCS1_OAEP(padded_secret, 256, secret.buffer, secret.size,
      (byte_t*)"SECRET", strlen("SECRET")+1);
  int n = RSA_public_encrypt(size_padded_secret, padded_secret, salt.secret,
                             rsa_key, RSA_NO_PADDING);
  salt.size = n;

  byte_t decrypted_with_pad[512];
  byte_t recovered_secret[512];
  memset(recovered_secret, 0, 512);
  memset(decrypted_with_pad, 0, 512);

  printf("\nEncrypted salt (%d): ", n);
  PrintBytes(n, salt.secret); printf("\n");
  int m = RSA_private_decrypt(n, (byte_t*) salt.secret,
               (byte_t*)decrypted_with_pad, rsa_key,
               RSA_NO_PADDING);
  if (m < 0) {
    printf("Can't decrypt\n");
    return;
  }
  printf("decrypted(%d): ", m);
  PrintBytes(m, decrypted_with_pad);printf("\n");
  salt.size = m;
  int k = 0;
  while(k < 256 && decrypted_with_pad[k] == 0) k++;
  RSA_padding_check_PKCS1_OAEP(recovered_secret, 256, 
      &decrypted_with_pad[k], 256-k, 256,
      (byte_t*)"SECRET", strlen("SECRET")+1);
}

