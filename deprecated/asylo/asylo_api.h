//  Copyright (c) 2021-22, VMware Inc, and the Certifier Authors.  All rights
//  reserved.
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

#ifndef _ASYLO_API_H_
#  define _ASYLO_API_H_

typedef struct AsyloCertifierFunctions {
  bool (*Attest)(int claims_size, byte *claims, int *size_out, byte *out);
  bool (*Verify)(int   user_data_size,
                 byte *user_data,
                 int   assertion_size,
                 byte *assertion,
                 int * size_out,
                 byte *out);
  bool (*Seal)(int in_size, byte *in, int *size_out, byte *out);
  bool (*Unseal)(int in_size, byte *in, int *size_out, byte *out);
} AsyloCertifierFunctions;

void setFuncs(AsyloCertifierFunctions funcs);

#endif  // #ifdef _ASYLO_API_H_
