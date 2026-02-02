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

int main(int an, char** av) {
  local_tpm tpm;

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
