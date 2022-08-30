#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <string>
#include <memory>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <cmath>
#include <string>

#include "certifier.pb.h"

#ifndef byte
typedef unsigned char byte;
#endif

#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include "certifier.pb.h" 
#include "certifier.h" 

using std::string;

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


#ifndef _SIMULATED_ENCLAVE_H__
#define _SIMULATED_ENCLAVE_H__

bool simulated_Init(const string& policy_cert, const string& attest_key_file,
    const string& measurement_file, const string& attest_key_signed_claim_file);
bool simulated_Getmeasurement(int* size_out, byte* out);
bool simulated_Seal(const string& enclave_type, const string& enclave_id,
  int in_size, byte* in, int* size_out, byte* out);
bool simulated_Unseal(const string& enclave_type, const string& enclave_id,
  int in_size, byte* in, int* size_out, byte* out);
bool simulated_Attest(const string& enclave_type,
  int what_to_say_size, byte* what_to_say,
  int* size_out, byte* out);
bool simulated_GetParentEvidence(string* out);
bool simulated_Verify(string& serialized_report);

bool simulated_GetAttestClaim(signed_claim_message* out);
bool simulated_GetPlatformClaim(signed_claim_message* out);

#endif
