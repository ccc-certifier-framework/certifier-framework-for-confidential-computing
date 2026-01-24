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
// File: RestoreCloudProxyKeyHierarchy.cc

// This program reloads primary key, signing key (for quotes) and
// sealing key under the owner hierarchy from nv ram.  It optionally
// unseals sealed file contents and verifies quoted file contents.

// Calling sequence
//   RestoreCloudProxyKeyHierarchy.exe 
//      --slot_primary=int32 --slot_seal=int32 --slot_quote=int32
//      --seal_value=value-string --quote_value=value-string
//      --pcr_hash_alg_name=[sha1 | sha256]
//      --pcr_list="int, int, ..." --seal_output_file=output-file-name
//      --quote_output_file= output-file-name --pcr_file=output-file-name

using std::string;

#define CALLING_SEQUENCE "RestoreCloudProxyKeyHierarchy.exe " \
"--slot_primary=int32 --slot_seal=int32 " \
"--slot_quote=int32" \
"--seal_value=value-string --quote_value=value-string " \
"--pcr_hash_alg_name=[sha1 | sha256]" \
"--pcr_list=\"int, int, ...\" --seal_output_file=output-file-name" \
"--quote_output_file= output-file-name --pcr_file=output-file-name\n"

void PrintOptions() {
  printf("Calling sequence: %s", CALLING_SEQUENCE);
}

DEFINE_int32(slot_primary, 0, "");
DEFINE_int32(slot_seal, 1, "");
DEFINE_int32(slot_quote, 2, "");
DEFINE_string(seal_value, "", "test seal value");
DEFINE_string(quote_value, "", "test quote value");
DEFINE_string(pcr_hash_alg_name, "", "hash alg (sha1 or sha256");
DEFINE_string(pcr_list, "", "comma separated pcr list");
DEFINE_string(seal_output_file, "", "output-file-name");
DEFINE_string(quote_output_file, "", "output-file-name");
DEFINE_string(pcr_file, "", "output-file-name");
DEFINE_string(hash_alg, "sha1", "hash alg");

#ifndef GFLAGS_NS
#define GFLAGS_NS google
#endif

#define MAX_SIZE_PARAMS 4096

int main(int an, char** av) {
  LocalTpm tpm;
  int ret_val = 0;

  printf("\nRestoreCloudProxyKeyHierarchy\n\n");

  GFLAGS_NS::ParseCommandLineFlags(&an, &av, true);
  if (!tpm.OpenTpm("/dev/tpm0")) {
    printf("Can't open tpm\n");
    return 1;
  }

  TPM_ALG_ID hash_alg_id;
  if (FLAGS_hash_alg == "sha1") {
    hash_alg_id = TPM_ALG_SHA1;
  } else if (FLAGS_hash_alg == "sha256") {
    hash_alg_id = TPM_ALG_SHA256;
  } else {
    printf("Unknown hash algorithm\n");
    return 1;
  }


  string authString("01020304");
  string parentAuth("01020304");
  string emptyAuth;

  TPML_PCR_SELECTION pcrSelect;

  TPM_HANDLE root_handle = 0; 
  TPM_HANDLE seal_handle = 0;
  TPM_HANDLE quote_handle = 0;
  TPM_HANDLE nv_handle = 0;
  byte context_save_area[MAX_SIZE_PARAMS];
  uint16_t context_data_size = 924;

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
  printf("context_save_area: ");
  PrintBytes(context_data_size, context_save_area);
  printf("\n");
  if (!Tpm2_LoadContext(tpm, context_data_size, context_save_area,
                        &seal_handle)) {
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

  tpm.CloseTpm();
  return ret_val;
}

