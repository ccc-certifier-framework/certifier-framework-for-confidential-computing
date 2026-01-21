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

#include <openssl_helpers.h>

#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

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
// File: tpm2_util.cc


// Calling sequence
// tpm2_util.exe --Commmand=command 

using std::string;

DEFINE_string(command, "", "command");
DEFINE_int32(numbytes, 16, "numbytes");
DEFINE_int32(num_param, 16, "integer parameter");
DEFINE_string(password, "password", "password");
DEFINE_string(authString, "", "authString");
DEFINE_string(parentAuth, "", "parent auth String");
DEFINE_string(handle, "", "handle");
DEFINE_int32(pcr_num, -1, "integer parameter");
DEFINE_int32(index, -1, "nv index");
DEFINE_int32(nv_slot, 1000, "nv slot");
DEFINE_int32(nv_size, -1, "nv size");
DEFINE_string(parent_public_file, "", "parent public area");
DEFINE_string(public_file, "", "public area");
DEFINE_string(private_file, "", "private public area");
DEFINE_string(creation_data_file, "", "private public area");
DEFINE_string(save_context_file, "", "save(d) context area");
DEFINE_string(decrypt, "", "decrypt flag");
DEFINE_uint64(startHandle, 0x80000000, "start handle range");

#ifndef GFLAGS_NS
#define GFLAGS_NS google
#endif

int num_tpmutil_ops = 28;
std::string tpmutil_ops[] = {
    "--command=Startup",
    "--command=Shutdown",
    "--command=GetCapabilities",
    "--command=Flushall",
    "--command=GetRandom",
    "--command=ReadClock",
    "--command=CreatePrimary",
    "--command=Load",
    "--command=Save",
    "--command=CreateKey",
    "--command=ReadPcr",
    "--command=Unseal",
    "--command=Quote",
    "--command=LoadContext",
    "--command=SaveContext",
    "--command=FlushContext",
    "--command=ReadNv",
    "--command=WriteNv",
    "--command=DefineSpace",
    "--command=UndefineSpace",
    "--command=SealCombinedTest",
    "--command=QuoteCombinedTest",
    "--command=DictionaryAttackLockReset",
    "--command=KeyCombinedTest",
    "--command=NvCombinedTest",
    "--command=ContextCombinedTest",
    "--command=EndorsementCombinedTest",
    "--command=NvCombinedSessionTest",
};

// standard buffer size
#define MAX_SIZE_PARAMS 4096

// Combined tests
bool Tpm2_SealCombinedTest(LocalTpm& tpm, int pcr_num);
bool Tpm2_QuoteCombinedTest(LocalTpm& tpm, int pcr_num);
bool Tpm2_KeyCombinedTest(LocalTpm& tpm, int pcr_num);
bool Tpm2_NvCombinedTest(LocalTpm& tpm);
bool Tpm2_NvCombinedSessionTest(LocalTpm& tpm);
bool Tpm2_ContextCombinedTest(LocalTpm& tpm);
bool Tpm2_EndorsementCombinedTest(LocalTpm& tpm);

void PrintOptions() {
  printf("Permitted operations:\n");
  for (int i = 0; i < num_tpmutil_ops; i++) {
    printf("  tpmutil.exe %s\n", tpmutil_ops[i].c_str());
  }
  return;
}

int main(int an, char** av) {
  LocalTpm tpm;

  GFLAGS_NS::ParseCommandLineFlags(&an, &av, true);
  if (!tpm.OpenTpm("/dev/tpm0")) {
    printf("Can't open tpm\n");
    return 1;
  }

  if (FLAGS_command == "GetCapabilities") {
    int size = 512;
    byte buf[512];
    if (!Tpm2_GetCapability(tpm, TPM_CAP_TPM_PROPERTIES, FLAGS_startHandle,
                            &size, buf)) {
      printf("Tpm2_GetCapability failed\n");
    }
    PrintCapabilities(size, buf);
  } else if (FLAGS_command == "Startup") {
    if (!Tpm2_Startup(tpm)) {
      printf("Tpm2_Startup failed\n");
    }
  } else if (FLAGS_command == "Shutdown") {
    if (!Tpm2_Shutdown(tpm)) {
      printf("Tpm2_Shutdown failed\n");
    }
  } else if (FLAGS_command == "GetRandom") {
    byte buf[256];

    if (FLAGS_numbytes >256) {
      printf("Can only get up to 256 bytes\n");
      goto done;
    }
    memset(buf, 0, 256);
    if (Tpm2_GetRandom(tpm, FLAGS_numbytes, buf)) {
      printf("Random bytes: ");
      PrintBytes(FLAGS_numbytes, buf);
      printf("\n");
    } else {
      printf("GetRandom failed\n");
    }
  } else if (FLAGS_command == "ReadClock") {
    uint64_t current_time, current_clock;
    if (Tpm2_ReadClock(tpm, &current_time, &current_clock)) {
      printf("time: %lx %lx\n\n", current_time, current_clock);
    } else {
      printf("ReadClock failed\n");
    }
  } else if (FLAGS_command == "CreatePrimary") {
#if 0
    TPM_HANDLE handle;
    TPM2B_PUBLIC pub_out;
    TPML_PCR_SELECTION pcrSelect;
    InitSinglePcrSelection(FLAGS_pcr_num, TPM_ALG_SHA1, &pcrSelect);
    bool sign = true;
    if (FLAGS_decrypt.size() > 0)
      sign = false;
    if (Tpm2_CreatePrimary(tpm, TPM_RH_OWNER, FLAGS_authString,
                           pcrSelect, sign,
                           &handle, &pub_out)) {
      printf("Tpm2_CreatePrimary succeeds\n");
      printf("Public handle: %08x\n", (uint32_t)handle);
      printf("type: %04x\n", pub_out.publicArea.type);
      printf("nameAlg: %04x\n", pub_out.publicArea.nameAlg);
      printf("Attributes: %08x\n", *(uint32_t*)
                &pub_out.publicArea.objectAttributes);
      printf("Algorithm: %08x\n",
        pub_out.publicArea.parameters.rsaDetail.symmetric.algorithm);
      printf("keySize: %04x\n", pub_out.publicArea.parameters.rsaDetail.keyBits);
      printf("Modulus: ");
      PrintBytes(pub_out.publicArea.unique.rsa.size,
                pub_out.publicArea.unique.rsa.buffer);
      printf("\n");
    } else {
      printf("CreatePrimary failed\n");
    }
#endif
  } else if (FLAGS_command == "Load") {
    TPM_HANDLE parent_handle = 0x80000000;
    TPM_HANDLE new_handle;
    TPM2B_NAME name;
    if (FLAGS_handle.size() >0 ) {
      long unsigned t;
      t = std::stoul(FLAGS_handle.c_str(), nullptr, 16);
      parent_handle = (TPM_HANDLE) t;
    } 
    int size_public = 4096;
    byte inPublic[4096];
    int size_private = 4096;
    byte inPrivate[4096];
    bool ok = true;
    if (!ReadFileIntoBlock(FLAGS_public_file, &size_public, inPublic)) {
      printf("Can't read public block\n");
      ok = false;
    }
    if (!ReadFileIntoBlock(FLAGS_private_file, &size_private, inPrivate)) {
      printf("Can't read public block\n");
      ok = false;
    }
    if (ok && Tpm2_Load(tpm, parent_handle, FLAGS_parentAuth, size_public, inPublic,
                        size_private, inPrivate, &new_handle, &name)) {
      printf("Load succeeded, new handle: %08x\n", new_handle);
    } else {
      printf("Load failed\n");
    }
  } else if (FLAGS_command == "Save") {
    if (Tpm2_Save(tpm)) {
      printf("Save succeeded\n");
    } else {
      printf("Save failed\n");
    }
  } else if (FLAGS_command == "ReadPcr") {
    uint32_t updateCounter;
    TPML_PCR_SELECTION pcrSelectOut;
    TPML_DIGEST values;
    if (Tpm2_ReadPcr(tpm, FLAGS_pcr_num, &updateCounter,
                     &pcrSelectOut, &values)) {
      printf("ReadPcr succeeds, updateCounter: %08x\n", updateCounter);
      printf("Pcr %d :", FLAGS_pcr_num);
      PrintBytes(values.digests[0].size, values.digests[0].buffer);
      printf("\n");
    } else {
      printf("ReadPcr failed\n");
    }
  } else if (FLAGS_command == "CreateKey") {
#if 0
    TPM_HANDLE parent_handle;

    TPM2B_CREATION_DATA creation_out;
    TPM2B_DIGEST digest_out;
    TPMT_TK_CREATION creation_ticket;
    int size_public = 4096;
    byte out_public[4096];
    int size_private = 4096;
    byte out_private[4096];

    parent_handle = 0x80000000;
    if (FLAGS_handle.size() > 0 ) {
      long unsigned t;
      t = std::stoul(FLAGS_handle.c_str(), nullptr, 16);
      parent_handle = (TPM_HANDLE) t;
    } 
    TPML_PCR_SELECTION pcrSelect;
    InitSinglePcrSelection(FLAGS_pcr_num, TPM_ALG_SHA1, &pcrSelect);
    bool sign = true;
    if (FLAGS_decrypt.size() > 0)
      sign = false;
    if (Tpm2_CreateKey(tpm, parent_handle, FLAGS_parentAuth,
                    FLAGS_authString, pcrSelect,
                    sign, false, &size_public, out_public,
                    &size_private, out_private,
                    &creation_out, &digest_out, &creation_ticket)) {
      printf("CreateKey succeeded\n");
      printf("Public (%d): ", size_public);
      PrintBytes(size_public, out_public);
      printf("\n");
      printf("Private (%d): ", size_private);
      PrintBytes(size_private, out_private);
      printf("\n");
      if (!WriteFileFromBlock(FLAGS_public_file, 
                              size_public, out_public)) {
        printf("Can't write %s, CreateKey failed\n", FLAGS_private_file.c_str());
      } else if (!WriteFileFromBlock(FLAGS_private_file,
                                     size_private, out_private)){ 
        printf("Can't write %s\n", FLAGS_private_file.c_str());
      } else {
        printf("CreateKey succeeded\n");
      }
    }
    printf("CreateKey failed\n");
#endif
  } else if (FLAGS_command == "Unseal") {
#if 0
    TPM_HANDLE item_handle = 0;
    int out_size = 1024;
    byte out[1024];
    int size_digest = 0;
    byte digest[64];
    if (Tpm2_Unseal(tpm, item_handle, FLAGS_parentAuth,
                    pcrSelector, TPM_ALG_SHA1, size_digest, digest,
                    &out_size, out)) {
      printf("Unseal succeeded: ");
      PrintBytes(out_size, out);
      printf("\n");
    } else {
      printf("Unseal failed\n");
    }
#endif
  } else if (FLAGS_command == "Quote") {
#if 0
    int quote_size = 1024;
    byte quote[1024];
    TPM_HANDLE signingHandle = 0;
    TPMT_SIG_SCHEME scheme;
    TPML_PCR_SELECTION pcr_selection;
    int attest_size = 1024;
    byte attest[1024];
    int sig_size = 1024;
    byte sig[1024];
    if (Tpm2_Quote(tpm, signingHandle, quote_size, quote, scheme, pcr_selection,
               &attest_size, attest, &sig_size, sig)) {
      printf("Quote succeeded\n");
    } else {
      printf("Quote failed\n");
    }
#endif
  } else if (FLAGS_command == "UndefineSpace") {
    TPM_HANDLE nv_handle = GetNvHandle(FLAGS_nv_slot);
    
    if (FLAGS_nv_slot < 0) {
      printf("Invalid index\n");
    } else if (!Tpm2_UndefineSpace(tpm, TPM_RH_OWNER, nv_handle)) {
      printf("UndefineSpace succeeded\n");
    } else {
      printf("UndefineSpace failed\n");
    }
  } else if (FLAGS_command == "DefineSpace") {
    TPM_HANDLE nv_handle = GetNvHandle(FLAGS_nv_slot);
    uint16_t size_data = (uint16_t) FLAGS_nv_size;
    if (Tpm2_DefineSpace(tpm, TPM_RH_OWNER, nv_handle, FLAGS_authString,
                         0, nullptr, NV_AUTHWRITE | NV_AUTHREAD, size_data)) {
      printf("DefineSpace succeeded\n");
    } else {
      printf("DefineSpace failed\n");
    }
  } else if (FLAGS_command == "LoadContext") {
    int size = 4096;
    byte saveArea[4096];
    memset(saveArea, 0, 4096);
    TPM_HANDLE handle = 0;

    if (!ReadFileIntoBlock(FLAGS_save_context_file, &size, saveArea)) {
        printf("Can't read %s, LoadContext failed\n", FLAGS_save_context_file.c_str());
    } else if (Tpm2_LoadContext(tpm, size, saveArea, &handle)) {
      printf("LoadContext succeeded\n");
    } else {
      printf("LoadContext failed\n");
    }
  } else if (FLAGS_command == "SaveContext") {
    uint16_t size = 4096;
    byte saveArea[4096];
    memset(saveArea, 0, 4096);

    TPM_HANDLE handle = 0x80000000;
    if (FLAGS_handle.size() > 0 ) {
      long unsigned t;
      t = std::stoul(FLAGS_handle.c_str(), nullptr, 16);
      handle = (TPM_HANDLE) t;
    } else if (Tpm2_SaveContext(tpm, handle, &size, saveArea)) {
      if (!WriteFileFromBlock(FLAGS_save_context_file, size, saveArea)) {
        printf("Can't write %s, SaveContext failed\n", FLAGS_save_context_file.c_str());
      } else { 
        printf("SaveContext successful\n");
      }
    } else {
      printf("SaveContext failed\n");
    }
  } else if (FLAGS_command == "FlushContext") {
    TPM_HANDLE handle = 0x80000000;
    if (FLAGS_handle.size() >0 ) {
      long unsigned t;
      t = std::stoul(FLAGS_handle.c_str(), nullptr, 16);
      handle = (TPM_HANDLE) t;
    } 
    if (Tpm2_FlushContext(tpm, handle)) {
      printf("FlushContext succeeded\n");
    } else {
      printf("FlushContext failed\n");
    }
  } else if (FLAGS_command == "Tpm2_Read_Nv") {
    TPMI_RH_NV_INDEX index = (TPMI_RH_NV_INDEX) FLAGS_index;
    uint16_t size_data = 16;
    byte data[1024];
    if (Tpm2_ReadNv(tpm, index, FLAGS_authString, &size_data, data)) {
      printf("Tpm2_Read_Nv succeeded\n");
      PrintBytes(size_data, data);
      printf("\n");
    } else {
      printf("Tpm2_Read_Nv failed\n");
    }
  } else if (FLAGS_command == "Tpm2_Write_Nv") {
    TPMI_RH_NV_INDEX index = (TPMI_RH_NV_INDEX) FLAGS_index;
    int size_data = 0;
    byte data[1024];
    if (Tpm2_WriteNv(tpm, index, FLAGS_authString, size_data, data)) {
      printf("Tpm2_Write_Nv succeeded\n");
    } else {
      printf("Tpm2_Write_Nv failed\n");
    }
  } else if (FLAGS_command == "Flushall") {
    if (Tpm2_Flushall(tpm, FLAGS_startHandle)) {
      printf("Flushall succeeded\n");
    } else {
      printf("Flushall failed\n");
    }
  } else if (FLAGS_command == "KeyCombinedTest") {
    if (Tpm2_KeyCombinedTest(tpm, FLAGS_pcr_num)) {
      printf("Tpm2_KeyCombinedTest succeeded\n");
    } else {
      printf("Tpm2_KeyCombinedTest failed\n");
    }
  } else if (FLAGS_command == "SealCombinedTest") {
    if (Tpm2_SealCombinedTest(tpm, FLAGS_pcr_num)) {
      printf("SealCombinedTest succeeded\n");
    } else {
      printf("SealCombinedTest failed\n");
    }
  } else if (FLAGS_command == "QuoteCombinedTest") {
    if (Tpm2_QuoteCombinedTest(tpm, FLAGS_pcr_num)) {
      printf("QuoteCombinedTest succeeded\n");
    } else {
      printf("QuoteCombinedTest failed\n");
    }
  } else if (FLAGS_command == "NvCombinedTest") {
    if (Tpm2_NvCombinedTest(tpm)) {
      printf("NvCombinedTest succeeded\n");
    } else {
      printf("NvCombinedTest failed\n");
    }
  } else if (FLAGS_command == "NvCombinedSessionTest") {
    if (Tpm2_NvCombinedSessionTest(tpm)) {
      printf("NvCombinedSessionTest succeeded\n");
    } else {
      printf("NvCombinedSessionTest failed\n");
    }
  } else if (FLAGS_command == "ContextCombinedTest") {
    if (Tpm2_ContextCombinedTest(tpm)) {
      printf("ContextCombinedTest succeeded\n");
    } else {
      printf("ContextCombinedTest failed\n");
    }
  } else if (FLAGS_command == "EndorsementCombinedTest") {
    if (Tpm2_EndorsementCombinedTest(tpm)) {
      printf("EndorsementCombinedTest succeeded\n");
    } else {
      printf("EndorsementCombinedTest failed\n");
    }
  } else if (FLAGS_command == "DictionaryAttackLockReset") {
    if (Tpm2_DictionaryAttackLockReset(tpm)) {
      printf("Tpm2_DictionaryAttackLockReset succeeded\n");
    } else {
      printf("Tpm2_DictionaryAttackLockReset failed\n");
    }
  } else {
    printf("Invalid command\n");
    PrintOptions();
  }
done:
  tpm.CloseTpm();
}

// Combined tests

bool Tpm2_EndorsementCombinedTest(LocalTpm& tpm) {
  string authString("01020304");
  string parentAuth("01020304");
  string emptyAuth;

  TPM_HANDLE ekHandle;
  TPM2B_PUBLIC pub_out;
  TPM2B_NAME pub_name;
  TPM2B_NAME qualified_pub_name;
  uint16_t pub_blob_size = 1024;
  byte pub_blob[1024];

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

  if (Tpm2_CreatePrimary(tpm, TPM_RH_ENDORSEMENT, emptyAuth, pcrSelect,
                         TPM_ALG_RSA, TPM_ALG_SHA256, primary_flags,
                         TPM_ALG_AES, 128, TPM_ALG_CFB, TPM_ALG_NULL,
                         2048, 0x010001, &ekHandle, &pub_out)) {
    printf("CreatePrimary succeeded parent: %08x\n", ekHandle);
  } else {
    printf("CreatePrimary failed\n");
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
  printf("Name: ");
  PrintBytes(pub_name.size, pub_name.name);
  printf("\n");
  printf("Qualified name: ");
  PrintBytes(qualified_pub_name.size, qualified_pub_name.name);
  printf("\n");

  TPM_HANDLE parentHandle;
  TPM_HANDLE activeHandle;
  TPM2B_PUBLIC parent_pub_out;
  TPML_PCR_SELECTION parent_pcrSelect;
  InitSinglePcrSelection(7, TPM_ALG_SHA1, &parent_pcrSelect);

  TPMA_OBJECT parent_flags;
  *(uint32_t*)(&parent_flags) = 0;
  parent_flags.fixedTPM = 1;
  parent_flags.fixedParent = 1;
  parent_flags.sensitiveDataOrigin = 1;
  parent_flags.userWithAuth = 1;
  parent_flags.decrypt = 1;
  parent_flags.restricted = 1;

  if (Tpm2_CreatePrimary(tpm, TPM_RH_OWNER, authString, parent_pcrSelect,
                         TPM_ALG_RSA, TPM_ALG_SHA256, parent_flags,
                         TPM_ALG_AES, 128, TPM_ALG_CFB, TPM_ALG_NULL,
                         1024, 0x010001,
                         &parentHandle, &parent_pub_out)) {
    printf("CreatePrimary succeeded\n");
  } else {
    printf("CreatePrimary failed\n");
    return false;
  }
  TPM2B_CREATION_DATA creation_out;
  TPM2B_DIGEST digest_out;
  TPMT_TK_CREATION creation_ticket;
  int size_public = MAX_SIZE_PARAMS;
  byte out_public[MAX_SIZE_PARAMS];
  int size_private = MAX_SIZE_PARAMS;
  byte out_private[MAX_SIZE_PARAMS];

  memset((void*)&pub_out, 0, sizeof(TPM2B_PUBLIC));

  TPMA_OBJECT active_flags;
  *(uint32_t*)(&active_flags) = 0;
  active_flags.fixedTPM = 1;
  active_flags.fixedParent = 1;
  active_flags.sensitiveDataOrigin = 1;
  active_flags.userWithAuth = 1;
  active_flags.sign = 1;

  if (Tpm2_CreateKey(tpm, parentHandle, parentAuth, authString,
                     parent_pcrSelect,
                     TPM_ALG_RSA, TPM_ALG_SHA256, active_flags, TPM_ALG_NULL,
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

  if (Tpm2_Load(tpm, parentHandle, parentAuth, size_public, out_public,
               size_private, out_private, &activeHandle, &pub_name)) {
    printf("Load succeeded, handle: %08x\n", activeHandle);
  } else {
    Tpm2_FlushContext(tpm, ekHandle);
    Tpm2_FlushContext(tpm, parentHandle);
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
  credential.size = 20;
  for (int i = 0; i < 20; i++)
    credential.buffer[i] = i + 1;

  TPM2B_PUBLIC active_pub_out;
  TPM2B_NAME active_pub_name;
  TPM2B_NAME active_qualified_pub_name;
  uint16_t active_pub_blob_size = 1024;
  byte active_pub_blob[1024];

  memset((void*)&active_pub_out, 0, sizeof(TPM2B_PUBLIC));

  if (Tpm2_ReadPublic(tpm, activeHandle,
                      &active_pub_blob_size, active_pub_blob,
                      &active_pub_out, &active_pub_name,
                      &active_qualified_pub_name)) {
    printf("ReadPublic succeeded\n");
  } else {
    printf("ReadPublic failed\n");
    return false;
  }
  printf("Active Name (%d): ", active_pub_name.size);
  PrintBytes(active_pub_name.size, active_pub_name.name);
  printf("\n");

  if (Tpm2_MakeCredential(tpm, ekHandle, credential, active_pub_name,
                          &credentialBlob, &secret)) {
    printf("MakeCredential succeeded\n");
  } else {
    Tpm2_FlushContext(tpm, parentHandle);
    printf("MakeCredential failed\n");
    Tpm2_FlushContext(tpm, activeHandle);
    Tpm2_FlushContext(tpm, parentHandle);
    Tpm2_FlushContext(tpm, ekHandle);
    return false;
  }
  printf("credBlob size: %d\n", credentialBlob.size);
  printf("secret size: %d\n", secret.size);
  if (Tpm2_ActivateCredential(tpm, activeHandle, ekHandle,
                              parentAuth, emptyAuth,
                              credentialBlob, secret,
                              &recovered_credential)) {
    printf("ActivateCredential succeeded\n");
    printf("Recovered credential (%d): ", recovered_credential.size);
    PrintBytes(recovered_credential.size, recovered_credential.buffer);
    printf("\n");
  } else {
    Tpm2_FlushContext(tpm, parentHandle);
    printf("ActivateCredential failed\n");
    Tpm2_FlushContext(tpm, activeHandle);
    Tpm2_FlushContext(tpm, parentHandle);
    Tpm2_FlushContext(tpm, ekHandle);
    return false;
  }
  Tpm2_FlushContext(tpm, activeHandle);
  Tpm2_FlushContext(tpm, parentHandle);
  Tpm2_FlushContext(tpm, ekHandle);
  return true;
}

bool Tpm2_ContextCombinedTest(LocalTpm& tpm) {
  TPM_HANDLE handle;
  uint16_t size = 4096;
  byte saveArea[4096];
  string authString("01020304");

  TPM2B_PUBLIC pub_out;
  TPML_PCR_SELECTION pcrSelect;
  InitSinglePcrSelection(7, TPM_ALG_SHA1, &pcrSelect);

  TPMA_OBJECT primary_flags;
  *(uint32_t*)(&primary_flags) = 0;
  primary_flags.fixedTPM = 1;
  primary_flags.fixedParent = 1;
  primary_flags.sensitiveDataOrigin = 1;
  primary_flags.userWithAuth = 1;
  primary_flags.sign = 1;

  if (Tpm2_CreatePrimary(tpm, TPM_RH_OWNER, authString, pcrSelect,
                         TPM_ALG_RSA, TPM_ALG_SHA1, primary_flags, TPM_ALG_NULL,
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

bool Tpm2_NvCombinedTest(LocalTpm& tpm) {
  int slot = 1000;
  string authString("01020304");
  uint16_t size_data = 16;
  byte data_in[512] = {
    0x9, 0x8, 0x7, 0x6,
    0x9, 0x8, 0x7, 0x6,
    0x9, 0x8, 0x7, 0x6,
    0x9, 0x8, 0x7, 0x6
  };
  uint16_t size_out = 512;
  byte data_out[512];
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

bool Tpm2_KeyCombinedTest(LocalTpm& tpm, int pcr_num) {
  string authString("01020304");
  string parentAuth("01020304");
  string emptyAuth;

  TPM_HANDLE parent_handle;
  TPM2B_PUBLIC pub_out;
  TPML_PCR_SELECTION pcrSelect;
  InitSinglePcrSelection(pcr_num, TPM_ALG_SHA1, &pcrSelect);

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
  byte out_public[MAX_SIZE_PARAMS];
  int size_private = MAX_SIZE_PARAMS;
  byte out_private[MAX_SIZE_PARAMS];

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


bool Tpm2_SealCombinedTest(LocalTpm& tpm, int pcr_num) {
  string authString("01020304");
  string parentAuth("01020304");
  string emptyAuth;

  TPM_HANDLE parent_handle;
  TPM2B_PUBLIC pub_out;
  TPML_PCR_SELECTION pcrSelect;
  InitSinglePcrSelection(pcr_num, TPM_ALG_SHA1, &pcrSelect);

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
  TPM2B_DIGEST secret;
  secret.size = 16;
  for  (int i = 0; i < 16; i++)
    secret.buffer[i] = (byte)(i + 1);

  TPM2B_CREATION_DATA creation_out;
  TPMT_TK_CREATION creation_ticket;
  int size_public = MAX_SIZE_PARAMS;
  byte out_public[MAX_SIZE_PARAMS];
  int size_private = MAX_SIZE_PARAMS;
  byte out_private[MAX_SIZE_PARAMS];

  TPM2B_DIGEST digest_out;
  TPM2B_NONCE initial_nonce;
  TPM2B_ENCRYPTED_SECRET salt;
  TPMT_SYM_DEF symmetric;
  TPM_HANDLE session_handle;
  TPM2B_NONCE nonce_obj;

  initial_nonce.size = 16;
  memset(initial_nonce.buffer, 0, 16);
  salt.size = 0;
  symmetric.algorithm = TPM_ALG_NULL;
  
  // Start auth session
  if (Tpm2_StartAuthSession(tpm, TPM_RH_NULL, TPM_RH_NULL,
                            initial_nonce, salt, TPM_SE_POLICY,
                            symmetric, TPM_ALG_SHA1, &session_handle,
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

  if (Tpm2_CreateSealed(tpm, parent_handle, policy_digest.size,
                        policy_digest.buffer, parentAuth, secret.size,
                        secret.buffer, pcrSelect, TPM_ALG_SHA1, create_flags,
                        TPM_ALG_NULL, (TPMI_AES_KEY_BITS)0, TPM_ALG_ECB,
                        TPM_ALG_RSASSA, 1024, 0x010001,
                        &size_public, out_public, &size_private, out_private,
                        &creation_out, &digest_out, &creation_ticket)) {
    printf("Create with digest succeeded private size: %d, public size: %d\n",
           size_private, size_public);
  } else {
    printf("Create with digest failed\n");
    Tpm2_FlushContext(tpm, session_handle);
    return false;
  }

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
  byte unsealed[MAX_SIZE_PARAMS];
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
  Tpm2_FlushContext(tpm, session_handle);
  Tpm2_FlushContext(tpm, load_handle);
  return true;
}

bool Tpm2_QuoteCombinedTest(LocalTpm& tpm, int pcr_num) {
  string authString("01020304");
  string parentAuth("01020304");
  string emptyAuth;

  TPM_HANDLE parent_handle;
  TPM2B_PUBLIC pub_out;
  TPML_PCR_SELECTION pcr_selection;
  InitSinglePcrSelection(pcr_num, TPM_ALG_SHA1, &pcr_selection);

  TPMA_OBJECT primary_flags;
  *(uint32_t*)(&primary_flags) = 0;
  primary_flags.fixedTPM = 1;
  primary_flags.fixedParent = 1;
  primary_flags.sensitiveDataOrigin = 1;
  primary_flags.userWithAuth = 1;
  primary_flags.decrypt = 1;
  primary_flags.restricted = 1;

  if (Tpm2_CreatePrimary(tpm, TPM_RH_OWNER, authString, pcr_selection, 
                         TPM_ALG_RSA, TPM_ALG_SHA1, primary_flags,
                         TPM_ALG_AES, 128, TPM_ALG_CFB, TPM_ALG_NULL,
                         1024, 0x010001,
                         &parent_handle, &pub_out)) {
    printf("CreatePrimary succeeded\n");
  } else {
    printf("CreatePrimary failed\n");
    return false;
  }

  if (pcr_num >= 0) {
    uint16_t size_eventData = 3;
    byte eventData[3] = {1, 2, 3};
    if (Tpm2_PCR_Event(tpm, pcr_num, size_eventData, eventData)) {
      printf("Tpm2_PCR_Event succeeded\n");
    } else {
      printf("Tpm2_PCR_Event failed\n");
    }
  }

  TPM2B_CREATION_DATA creation_out;
  TPMT_TK_CREATION creation_ticket;
  int size_public = MAX_SIZE_PARAMS;
  byte out_public[MAX_SIZE_PARAMS];
  int size_private = MAX_SIZE_PARAMS;
  byte out_private[MAX_SIZE_PARAMS];
  TPM2B_DIGEST digest_out;

  TPMA_OBJECT create_flags;
  *(uint32_t*)(&create_flags) = 0;
  create_flags.fixedTPM = 1;
  create_flags.fixedParent = 1;
  create_flags.sensitiveDataOrigin = 1;
  create_flags.userWithAuth = 1;
  create_flags.sign = 1;
  create_flags.restricted = 1;

  if (Tpm2_CreateKey(tpm, parent_handle, parentAuth, authString, pcr_selection,
                     TPM_ALG_RSA, TPM_ALG_SHA1, create_flags, TPM_ALG_NULL,
                     (TPMI_AES_KEY_BITS)0, TPM_ALG_ECB, TPM_ALG_RSASSA,
                     1024, 0x010001,
                     &size_public, out_public, &size_private, out_private,
                     &creation_out, &digest_out, &creation_ticket)) {
    printf("Create succeeded, private size: %d, public size: %d\n",
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
  to_quote.size = 16;
  for  (int i = 0; i < 16; i++)
    to_quote.buffer[i] = (byte)(i + 1);
  TPMT_SIG_SCHEME scheme;

  int quote_size = MAX_SIZE_PARAMS;
  byte quoted[MAX_SIZE_PARAMS];
  int sig_size = MAX_SIZE_PARAMS;
  byte sig[MAX_SIZE_PARAMS];
  if (!Tpm2_Quote(tpm, load_handle, parentAuth,
                  to_quote.size, to_quote.buffer,
                  scheme, pcr_selection, TPM_ALG_RSA, TPM_ALG_SHA1,
                  &quote_size, quoted, &sig_size, sig)) {
    printf("Quote failed\n");
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
  memcpy(secret.buffer, (byte*)"12345678901234567890", secret.size);

// Encrypt salt
  printf("\nencrypting salt\n");
  int size_padded_secret= 256;
  byte padded_secret[256];
  RSA_padding_add_PKCS1_OAEP(padded_secret, 256, secret.buffer, secret.size,
      (byte*)"SECRET", strlen("SECRET")+1);
  int n = RSA_public_encrypt(size_padded_secret, padded_secret, salt.secret,
                             rsa_key, RSA_NO_PADDING);
  salt.size = n;

  byte decrypted_with_pad[512];
  byte recovered_secret[512];
  memset(recovered_secret, 0, 512);
  memset(decrypted_with_pad, 0, 512);

  printf("\nEncrypted salt (%d): ", n);
  PrintBytes(n, salt.secret); printf("\n");
  int m = RSA_private_decrypt(n, (byte*) salt.secret,
               (byte*)decrypted_with_pad, rsa_key,
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
      (byte*)"SECRET", strlen("SECRET")+1);
}

// For Jethro
bool Tpm2_NvCombinedSessionTest(LocalTpm& tpm) {
  printf("Tpm2_NvCombinedSessionTest\n\n");
  extern int CreatePasswordAuthArea(string& password, int size, byte* buf);

  int slot = 1000;
  string authString("01020304");
  uint16_t size_data = 8;
  uint16_t size_out = 512;
  byte data_out[512];
  TPM_HANDLE nv_handle = GetNvHandle(slot);
  bool ret = true;

  TPM2B_ENCRYPTED_SECRET salt;
  TPM_HANDLE sessionHandle = 0;
  TPML_PCR_SELECTION pcrSelect;
  memset((void*)&pcrSelect, 0, sizeof(TPML_PCR_SELECTION));

  TPM2B_DIGEST secret;
  ProtectedSessionAuthInfo authInfo;
  TPMT_SYM_DEF symmetric;

  authInfo.hash_alg_ = TPM_ALG_SHA1;
  int hashSize = SizeHash(authInfo.hash_alg_);

  // If encryption.
  symmetric.algorithm = TPM_ALG_AES;
  symmetric.keyBits.aes = 128;
  symmetric.mode.aes = TPM_ALG_CFB;

  authInfo.targetAuthValue_.size = authString.size();
  memset(authInfo.targetAuthValue_.buffer, 0, authString.size());

  authInfo.newNonce_.size = hashSize;
  authInfo.oldNonce_.size = hashSize;
  memset(authInfo.newNonce_.buffer, 0, hashSize);
  memset(authInfo.oldNonce_.buffer, 0, hashSize);
  RAND_bytes(authInfo.oldNonce_.buffer, authInfo.oldNonce_.size);

  memset(secret.buffer, 0, 32);
  secret.size = 20;
  RAND_bytes(secret.buffer, secret.size);

#if 1
  printf("newNonce: ");
  PrintBytes(authInfo.newNonce_.size, authInfo.newNonce_.buffer); printf("\n");
  printf("oldNonce: ");
  PrintBytes(authInfo.oldNonce_.size, authInfo.oldNonce_.buffer); printf("\n");
  printf("Secret:   "); PrintBytes(secret.size, secret.buffer); printf("\n");
#endif

  // Get endorsement key handle
  string emptyAuth;
  TPM_HANDLE ekHandle;
  TPM2B_PUBLIC pub_out;

  // TPM_RH_ENDORSEMENT
  TPMA_OBJECT primary_flags;
  *(uint32_t*)(&primary_flags) = 0;
  primary_flags.fixedTPM = 1;
  primary_flags.fixedParent = 1;
  primary_flags.sensitiveDataOrigin = 1;
  primary_flags.userWithAuth = 1;
  primary_flags.decrypt = 1;
  primary_flags.restricted = 1;

  // Get rid of the old counter.
  if (Tpm2_UndefineSpace(tpm, TPM_RH_OWNER, nv_handle)) {
    printf("Tpm2_UndefineSpace %d succeeds\n", slot);
  } else {
    printf("Tpm2_UndefineSpace fails (but that's OK usually)\n");
  }
  if (Tpm2_DefineSpace(tpm, TPM_RH_OWNER, nv_handle, authString,
                        0, nullptr, NV_COUNTER | NV_AUTHWRITE | NV_AUTHREAD,
                        size_data)) {
     printf("DefineSpace succeeded\n");
   } else {
     printf("DefineSpace failed\n");
     return false;
   }
  if (Tpm2_IncrementNv(tpm, nv_handle, authString)) {
    printf("Initial Tpm2_IncrementNv succeeds\n");
  } else {
    printf("Initial Tpm2_IncrementNv fails\n");
     return false;
  }

  // Get endorsement key.
  if (Tpm2_CreatePrimary(tpm, TPM_RH_ENDORSEMENT, emptyAuth, pcrSelect,
                         TPM_ALG_RSA, TPM_ALG_SHA1, primary_flags,
                         TPM_ALG_AES, 128, TPM_ALG_CFB, TPM_ALG_NULL,
                         2048, 0x010001, &ekHandle, &pub_out)) {
    printf("CreatePrimary succeeded: %08x\n", ekHandle);
  } else {
    printf("CreatePrimary failed\n");
    return false;
  }

  TPM2B_NAME pub_name;
  TPM2B_NAME qualified_pub_name;
  uint16_t pub_blob_size = 2048;
  byte pub_blob[2048];

  if (Tpm2_ReadPublic(tpm, ekHandle, &pub_blob_size, pub_blob, &pub_out,
                      &pub_name, &qualified_pub_name)) {
    printf("ReadPublic succeeded\n");
  } else {
    printf("ReadPublic failed\n");
    return false;
  }

  // Normally, the caller would get the key from the endorsement certificate
  EVP_PKEY* tpmKey = EVP_PKEY_new();
  RSA* rsa_tpmKey = RSA_new();
  rsa_tpmKey->n = bin_to_BN((int)pub_out.publicArea.unique.rsa.size,
                            pub_out.publicArea.unique.rsa.buffer);
  uint64_t exp = 0x010001ULL;
  byte b_exp[16];
  ChangeEndian64((uint64_t*)&exp, (uint64_t*)b_exp);
  rsa_tpmKey->e = bin_to_BN(sizeof(uint64_t), b_exp);
  EVP_PKEY_assign_RSA(tpmKey, rsa_tpmKey);

  // Encrypt salt
  byte padded_secret[1024];
  memset(padded_secret, 0, 1024);
  RSA_padding_add_PKCS1_OAEP(padded_secret, 256,
      secret.buffer, secret.size,
      (byte*)"SECRET", strlen("SECRET")+1);
  int n = RSA_public_encrypt(256, padded_secret, salt.secret,
                             rsa_tpmKey, RSA_NO_PADDING);
  salt.size = n;

#if 1
  printf("\nEncrypted salt (%d): ", n);
  PrintBytes(n, salt.secret); printf("\n");
#endif

  authInfo.protectedHandle_ = nv_handle;
  authInfo.protectedAttributes_ = NV_COUNTER | NV_AUTHWRITE | NV_AUTHREAD;
  authInfo.protectedSize_ = size_data;
  authInfo.hash_alg_ = TPM_ALG_SHA1;
  authInfo.tpmSessionAttributes_ = CONTINUESESSION;
  extern int SetPasswordData(string& password, int size, byte* buf);
  byte tbuf[128];
  int l = SetPasswordData(authString, 128, tbuf);
  authInfo.targetAuthValue_.size = l - 2;
  memcpy(authInfo.targetAuthValue_.buffer, &tbuf[2], l - 2);
  
  // Start auth session.
    if (Tpm2_StartProtectedAuthSession(tpm, ekHandle, TPM_RH_NULL, authInfo,
         salt, TPM_SE_HMAC, symmetric, authInfo.hash_alg_, &sessionHandle)) {
    printf("Tpm2_StartProtectedAuthSession succeeds handle: %08x\n",
           sessionHandle);
  } else {
    printf("Tpm2_StartProtectedAuthSession fails\n");
    ret = false;
    goto done;
  }
  authInfo.sessionHandle_ = sessionHandle;

#if 1
  printf("\nAfterStartProtectedAuthSession\n");
  printf("newNonce: ");
  PrintBytes(authInfo.newNonce_.size, authInfo.newNonce_.buffer); printf("\n");
  printf("oldNonce: ");
  PrintBytes(authInfo.oldNonce_.size, authInfo.oldNonce_.buffer); printf("\n");
#endif

  // Calculate session key.
  if (!CalculateSessionKey(authInfo, secret)) {
    printf("Can't calculate HMac session key\n");
    ret = false;
    goto done;
  }

#if 1
  printf("After CalculateSessionKey before IncrementProtected\n");
  printf("newNonce: ");
  PrintBytes(authInfo.newNonce_.size, authInfo.newNonce_.buffer); printf("\n");
  printf("oldNonce: ");
  PrintBytes(authInfo.oldNonce_.size, authInfo.oldNonce_.buffer); printf("\n");
#endif

  if (Tpm2_IncrementProtectedNv(tpm, nv_handle, authInfo)) {
    printf("Tpm2_IncrementProtectedNv %d succeeds\n", nv_handle);
  } else {
    printf("Tpm2_IncrementProtectedNv fails\n");
    ret = false;
    goto done;
  }

#if 1
  printf("Read Protected\n");
#endif

  size_out = 8;
  if (Tpm2_ReadProtectedNv(tpm, nv_handle, authInfo, &size_out, data_out)) {
    printf("Tpm2_ReadProtectedNv %d succeeds: ", nv_handle);
    PrintBytes(size_out, data_out);
    printf("\n");
  } else {
    printf("Tpm2_ReadProtectedNv fails\n");
    ret = false;
    goto done;
  }

done:
  if (sessionHandle != 0) {
    Tpm2_FlushContext(tpm, sessionHandle);
  }
  if (ekHandle != 0) {
    Tpm2_FlushContext(tpm, ekHandle);
  }
  return ret;
}
