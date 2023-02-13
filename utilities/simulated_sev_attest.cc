#include <gflags/gflags.h>
#include "certifier.h"
#include "support.h"
#include "attestation.h"

//  Copyright (c) 2021-22, VMware Inc, and the Certifier Authors.  All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.


DEFINE_bool(print_all, false,  "verbose");
DEFINE_string(key_file, "../key.pem",  "key file name");
DEFINE_string(output, "signed_sev_attest.bin",  "test key file");


// This generates an sev attestation signed by the key in key_file
int main(int an, char** av) {
  gflags::ParseCommandLineFlags(&an, &av, true);

  printf("simulated_sev_attest.exe.exe --key_file=ecc-384-private.pem --output=test_sev_attest.bin\n");

  // get key
  // form attestation
  // sign it

  return 0;
}
