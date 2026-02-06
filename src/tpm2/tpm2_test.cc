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
DEFINE_string(seal_hierearchy_name, "seal_hierarchy.bin",
              "seal hierarch save file name");
DEFINE_string(quote_hierearchy_name, "quote_hierarchy.bin",
              "quote hierarch save file namec");

#ifndef GFLAGS_NS
#define GFLAGS_NS google
#endif

// ----------------------------------------------------------

bool endorsement_test(local_tpm& tpm) {
  TPM_HANDLE ek_handle;

  if  (!get_endorsement_key(tpm, &ek_handle)) {
    printf("%s() error, line %d, get_endorsement_key failed\n", __func__, __LINE__);
    return false;
  }

  TPM2B_PUBLIC pub_out;
  TPM2B_NAME pub_name;
  TPM2B_NAME qualified_pub_name;
  uint16_t pub_blob_size = 4096;
  byte_t pub_blob[pub_blob_size];
  if (!Tpm2_ReadPublic(tpm, ek_handle, &pub_blob_size, pub_blob,
                      &pub_out, &pub_name, &qualified_pub_name)) {
    printf("%s() error, line %d, ReadPublic failed\n", __func__, __LINE__);
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
             (byte_t*)pub_out.publicArea.unique.rsa.buffer);
  printf("\n");
  printf("Exponent: %d\n", pub_out.publicArea.parameters.rsaDetail.exponent);
  printf("\n");

  string cert_out;
  if (!get_endorsement_cert(tpm, &cert_out)) {
    printf("%s() error, line %d, get_endorsement_cert failed\n", __func__, __LINE__);
    return false;
  }

  Tpm2_FlushContext(tpm, ek_handle);
  return true;
}

bool seal_test(local_tpm& tpm, int pcr_num, const string& seal_file) {

  int num_pcrs = 1;
  byte_t pcrs[1] = { 7 };

  if (!create_seal_hierarchy_and_secret(tpm, num_pcrs, pcrs, seal_file)) {
    printf("%s() error, line %d, create_seal_hierarchy_and_secret failed\n",
	   __func__, __LINE__);
    return false;
  }

  string seal_secret;
  if (!recover_sealing_secret(tpm, num_pcrs, pcrs,
                             FLAGS_seal_hierearchy_name, &seal_secret)) {
    printf("%s() error, line %d, recover_sealing_secret failed\n",
            __func__, __LINE__);
    return false;
  }
#ifdef DEBUG
  printf("Recovered seal secret: ");
  print_bytes(seal_secret.size(), (byte_t*)seal_secret.data());
  printf("\n");
#endif

  return true;
}

bool quote_test(local_tpm& tpm, const string& quote_file) {
  int num_pcrs = 1;
  byte_t pcrs[1] = { 7 };

  TPM_HANDLE srk_handle;
  TPM_HANDLE quote_handle;

  if (!create_quote_hierarchy(tpm, num_pcrs, pcrs, quote_file) ) {
    printf("%s() error, line %d, create_quote_hierarchy failed\n",
            __func__, __LINE__);
    return false;
  }

  if (!recover_and_load_quote_hierarchy(tpm, num_pcrs, pcrs, quote_file,
        &srk_handle, &quote_handle)) {
    printf("%s() error, line %d, recover_sealing_secret failed\n",
           __func__, __LINE__);
    Tpm2_FlushContext(tpm, quote_handle);
    Tpm2_FlushContext(tpm, srk_handle);
    return false;
  }

  string to_quote("I am being quoted");
  string quote_sig;

  if (!do_quote(tpm, srk_handle, num_pcrs, pcrs,
                quote_handle, to_quote, &quote_sig)) {
    printf("%s() error, line %d, recover_sealing_secret failed\n",
           __func__, __LINE__);
    Tpm2_FlushContext(tpm, quote_handle);
    Tpm2_FlushContext(tpm, srk_handle);
    return false;
  }

  // Verify it
  if (!verify_credential(tpm, to_quote, quote_sig)) {
    printf("%s() error, line %d, verify_credential failed\n",
            __func__, __LINE__);
    return false;
  }

  Tpm2_FlushContext(tpm, quote_handle);
  Tpm2_FlushContext(tpm, srk_handle);
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
    printf("%s() error, line %d, CreatePrimary failed\n",
           __func__, __LINE__);
    return false;
  }
#ifdef DEBUG
  printf("CreatePrimary succeeded\n");
#endif

  string in;
  string out;

  if (!save_context(tpm, handle, &out)) {
    printf("%s() error, line %d, save_context failed\n",
           __func__, __LINE__);
    Tpm2_FlushContext(tpm, handle);
    return false;
  }
  if (!load_context(tpm, handle, in)) {
    printf("%s() error, line %d, load_context failed\n",
           __func__, __LINE__);
    Tpm2_FlushContext(tpm, handle);
    return false;
  }

  Tpm2_FlushContext(tpm, handle);
  return true;
}

bool nv_test(local_tpm& tpm) {
  int slot = 1000;

  uint16_t size_data = 16;
  byte_t data_in[512] = {
    0x9, 0x8, 0x7, 0x6,
    0x9, 0x8, 0x7, 0x6,
    0x9, 0x8, 0x7, 0x6,
    0x9, 0x8, 0x7, 0x6
  };
  uint16_t size_out = 512;
  byte_t data_out[512];

  string in;
  string out;
  in.assign((char*)data_in, size_data);

  if (!write_nv_slot(tpm, slot, in)) {
    printf("%s() error, line %d, write_nv_slot failed\n",
            __func__, __LINE__);
    return false;
  }
  if (!read_nv_slot(tpm, slot, &out)) {
    printf("%s() error, line %d, read_nv_slot failed\n",
            __func__, __LINE__);
    return false;
  }

  if (memcmp(in.data(), out.data(), out.size()) != 0) {
    printf("%s() error, line %d, written and read values don't match\n",
           __func__, __LINE__);
    return false;
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

  if (FLAGS_operation == "") {
    printf("operations:\n");
    printf("  EndorsementTest\n");
    printf("  SealTest\n");
    printf("  QuoteTest\n");
    printf("  ContextTest\n");
    printf("  NvTest\n");
    return 1;
  }

  if (!tpm.open_tpm(FLAGS_tpm_device.c_str())) {
    printf("Can't open tpm: %s\n", FLAGS_tpm_device.c_str());
    return 1;
  } else {
    printf("Opened tpm: %s %d\n", FLAGS_tpm_device.c_str(), tpm.tpm_fd_);
  }

  if (FLAGS_operation == "EndorsementTest") {
    if (endorsement_test(tpm)) {
      printf("endorsement test succeeded\n");
    } else {
      printf("endorsement test failed\n");
    }
  } else if (FLAGS_operation == "SealTest") {
    if(seal_test(tpm, 7, FLAGS_seal_hierearchy_name)) {
      printf("seal test succeeded\n");
    } else {
      printf("seal test failed\n");
    }
  } else if (FLAGS_operation == "QuoteTest") {
    if(quote_test(tpm, FLAGS_quote_hierearchy_name)) {
      printf("quote test succeeded\n");
    } else {
      printf("quote test failed\n");
    }
  } else if (FLAGS_operation == "ContextTest") {
    if(context_test(tpm)) {
      printf("context test succeeded\n");
    } else {
      printf("context test failed\n");
    }
  } else if (FLAGS_operation == "NvTest") {
    if(nv_test(tpm)) {
      printf("nv test succeeded\n");
    } else {
      printf("nv test failed\n");
    }
  } else {
    printf("No such operation (%s)\n", FLAGS_operation.c_str());
  }

  tpm.close_tpm();
}
