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
// Copyright 2025 John L Manferdelli, All Rights Reserved.
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

DEFINE_string(command, "", "command");
DEFINE_string(password, "password", "password");
DEFINE_int32(pcr_num, -1, "integer parameter");
DEFINE_int32(index, -1, "nv index");
DEFINE_int32(nv_slot, 1000, "nv slot");
DEFINE_int32(nv_size, -1, "nv size");
DEFINE_string(tpm_device, "/dev/tpm0", "tpm device");
DEFINE_string(seal_hierearchy_name, "seal_hierarchy.bin",
              "seal hierarch save file name");
DEFINE_string(quote_hierearchy_name, "quote_hierarchy.bin",
              "quote hierarch save file namec");

#ifndef GFLAGS_NS
#define GFLAGS_NS google
#endif


// ----------------------------------------------------------


bool endorsement_test(local_tpm& tpm) {
  return true;
}

bool seal_test(local_tpm& tpm, int pcr_num) {
  return true;
}

bool quote_test(local_tpm& tpm, int pcr_num) {
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

// ------------------------------------------------------------------------


int main(int an, char** av) {
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
  if (!tpm.open_tpm(FLAGS_tpm_device.c_str())) {
    printf("Can't open tpm: %s\n", FLAGS_tpm_device.c_str());
    return 1;
  } else {
    printf("Opened tpm: %s %d\n", FLAGS_tpm_device.c_str(), tpm.tpm_fd_);
  }

done:
  tpm.close_tpm();
}
