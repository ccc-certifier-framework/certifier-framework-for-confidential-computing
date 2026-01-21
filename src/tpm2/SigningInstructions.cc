#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include <openssl/rsa.h>

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
// File: SigningInstructions.cc


// This program initializes the signing instructions.

// Calling sequence
//   SigningInstructions.exe 
//     --issuer=name
//     --purpose=purpose
//     --hash_alg=[sha1|sha256]
//     --duration=duration-in-seconds
//     --instructions_file=output-file
//     --can_sign=[true|false]
using std::string;

#define DEBUG

#define CALLING_SEQUENCE "SigningInstructions.exe "\
"--issuer=name " \
"--purpose=purpose " \
"--isCA=[true|false]" \
"--hash_alg=[sha1|sha256] " \
"--duration=duration-in-seconds " \
"--can_sign=[true|false] " \
"--instructions_file=output-file\n"

void PrintOptions() {
  printf(CALLING_SEQUENCE);
}

DEFINE_string(issuer, "", "issuer name");
DEFINE_string(purpose, "critical: DigitalSignature, KeyEncipherment", "purpose");
DEFINE_string(hash_alg, "sha1", "hash alg");
DEFINE_int64(duration, 31536000, "duration (in seconds)");
DEFINE_string(instructions_file, "signing_instructions", "output-file-name");
DEFINE_bool(isCA, false, "is CA");
DEFINE_bool(can_sign, true, "can sign");

#ifndef GFLAGS_NS
#define GFLAGS_NS google
#endif

#define MAXKEY_BUF 8192

int main(int an, char** av) {
  signing_instructions_message message;
  int ret_val = 0;

  printf("\nSigningInstructions\n\n");

  GFLAGS_NS::ParseCommandLineFlags(&an, &av, true);

  message.set_issuer(FLAGS_issuer);
  message.set_duration(FLAGS_duration);
  message.set_purpose(FLAGS_purpose);
  message.set_hash_alg(FLAGS_hash_alg);
  message.set_can_sign(true);
  message.set_isca(FLAGS_isCA);
  string output;
  if (!message.SerializeToString(&output)) {
    printf("Can't serialize output\n");
    ret_val = 1;
    goto done;
  }
#ifdef DEBUG
  printf("Signinginstructions: %s\n", message.DebugString().c_str());
#endif
  if (!WriteFileFromBlock(FLAGS_instructions_file, output.size(),
                          (byte*)output.data())) {
    printf("Can't write output file\n");
    ret_val = 1;
  }
done:
  return ret_val;
}

