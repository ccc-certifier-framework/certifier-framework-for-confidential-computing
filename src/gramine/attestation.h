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

#include <iostream>

#ifndef _GRAMINE_ATTESTATION_H_
#define _GRAMINE_ATTESTATION_H_

typedef unsigned char byte;

#ifdef GRAMINE_CERTIFIER
extern bool gramine_Init(const char *measurement_file, const char *cert_file);
extern bool gramine_Attest(int claims_size, byte* claims, int* size_out, byte* out);
extern bool gramine_Verify(int claims_size, byte* claims, int *user_data_out_size,
                  byte *user_data_out, int* size_out, byte* out);
extern bool gramine_Seal(int in_size, byte* in, int* size_out, byte* out);
extern bool gramine_Unseal(int in_size, byte* in, int* size_out, byte* out);
#endif

#endif // #ifdef _GRAMINE_ATTESTATION_H_
