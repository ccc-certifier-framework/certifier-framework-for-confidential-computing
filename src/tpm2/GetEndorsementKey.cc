#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include <tpm20.h>
#include <tpm2_lib.h>
#include <tpm2.pb.h>
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
// File: GetEndorsementKey.cc


// Calling sequence
//   GetEndorsementKey.exe --endorsement_info_file=output-file

using std::string;

// This program creates the endorsement key and produces a file containing
// a protobuf consisting of the TPM2B_PUBLIC blob and other information.
// TODO: include machine identifier?

DEFINE_string(endorsement_info_file, "", "output file");
DEFINE_string(machine_identifier, "", "text to identify endorsement");
DEFINE_string(hash_alg, "sha1", "hash");

#ifndef GFLAGS_NS
#define GFLAGS_NS google
#endif
#define DEBUG

void PrintOptions() {
  printf("Calling sequence: GetEndorsementKey.exe " \
          "-- machine_identifier= name --endorsement_info_file=output-file\n");
}

int main(int an, char** av) {
  LocalTpm tpm;
  TPM_HANDLE ekHandle;
  TPM2B_PUBLIC pub_out;
  TPM2B_NAME pub_name;
  TPM2B_NAME qualified_pub_name;
  uint16_t pub_blob_size = 1024;
  byte pub_blob[1024];
  string emptyAuth;
  TPML_PCR_SELECTION pcrSelect;
  TPMA_OBJECT primary_flags;
  *(uint32_t*)(&primary_flags) = 0;

  int ret_val = 0;
  endorsement_key_message message;
  string output;

  printf("\nGetEndorsementKey\n\n");

  TPM_ALG_ID hash_alg_id;
  if (FLAGS_hash_alg == "sha1") {
    hash_alg_id = TPM_ALG_SHA1;
  } else if (FLAGS_hash_alg == "sha256") {
    hash_alg_id = TPM_ALG_SHA256;
  } else {
    printf("Unknown hash algorithm\n");
    return 1;
  }

  GFLAGS_NS::ParseCommandLineFlags(&an, &av, true);
  if (FLAGS_endorsement_info_file == "") {
    printf("You must specify an endorsement output file\n");
    PrintOptions();
    return 1;
  }

  if (!tpm.OpenTpm("/dev/tpm0")) {
    printf("Can't open tpm\n");
    return 1;
  }

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
                         2048, 0x010001, &ekHandle, &pub_out)) {
    printf("CreatePrimary succeeded parent: %08x\n", ekHandle);
  } else {
    printf("CreatePrimary failed\n");
    ret_val = 1;
    goto done;
  }
  if (Tpm2_ReadPublic(tpm, ekHandle, &pub_blob_size, pub_blob,
                      &pub_out, &pub_name, &qualified_pub_name)) {
    printf("ReadPublic succeeded\n");
  } else {
    printf("ReadPublic failed\n");
    ret_val = 1;
    Tpm2_FlushContext(tpm, ekHandle);
    goto done;
  }
  Tpm2_FlushContext(tpm, ekHandle);

#ifdef DEBUG
  printf("Public blob: ");
  PrintBytes(pub_blob_size, pub_blob);
  printf("\n");
  printf("Name: ");
  PrintBytes(pub_name.size, pub_name.name);
  printf("\n");
  printf("Qualified name: ");
  PrintBytes(qualified_pub_name.size, qualified_pub_name.name);
  printf("\n");
#endif

  message.set_machine_identifier(FLAGS_machine_identifier);
  message.set_tpm2b_blob((const char*)pub_blob, (int)pub_blob_size);
  message.set_tpm2_name((const char*)pub_name.name, (int)pub_name.size);

  if (!message.SerializeToString(&output)) {
    printf("Can't serialize output\n");
    ret_val = 1;
    goto done;
  }
  if (!WriteFileFromBlock(FLAGS_endorsement_info_file, output.size(),
                          (byte*)output.data())) {
    printf("Can't write output file\n");
    ret_val = 1;
  }

done:
  tpm.CloseTpm();
  return ret_val;
}

