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
// File: tpm2_set_pcrs.cc


// Calling sequence
// tpm2_set_pcrs.exe --pcr_num=7 --tpm_device=/dev/tpm0 -num_pcrs=1

using std::string;
using namespace certifier::framework;
using namespace certifier::utilities;

DEFINE_int32(pcr_num, 7, "integer parameter");
DEFINE_string(tpm_device, "/dev/tpm0", "tpm device");
DEFINE_int32(num_pcrs, 1, "number of pcrs");

#ifndef GFLAGS_NS
#  define GFLAGS_NS google
#endif

#define DEBUG

// ----------------------------------------------------------

int main(int an, char **av) {

  GFLAGS_NS::ParseCommandLineFlags(&an, &av, true);

  if (!init_tpm(FLAGS_tpm_device)) {
    printf("%s() error, line %d, tpm_init failed\n", __func__, __LINE__);
    return false;
  }

  extern local_tpm g_tpm;
  int              num_pcrs = FLAGS_num_pcrs;
  byte_t           pcrs[10];
  pcrs[0] = FLAGS_pcr_num;

  printf("PCR's at entry:\n");
  print_pcrs(g_tpm, num_pcrs, pcrs);

  if (!extend_pcrs(g_tpm, FLAGS_pcr_num)) {
    printf("%s() error, line %d, extend_pcrs failed\n", __func__, __LINE__);
    return false;
  }

  printf("PCR's at exit:\n");
  print_pcrs(g_tpm, num_pcrs, pcrs);

#if 0
  // print all the pcrs
  pcrs[0] = 0xff;
  pcrs[1] = 0xff;
  pcrs[2] = 0xff;
  printf("All pcrs:\n");
  print_pcrs(g_tpm, 8, pcrs);
#endif

  close_tpm();
  return 0;
}

// ----------------------------------------------------------
