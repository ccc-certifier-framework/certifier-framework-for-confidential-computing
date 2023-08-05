//  Copyright (c) 2021-23, VMware Inc, and the Certifier Authors.  All rights
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

#ifndef __ISLET_API_H__

#  include <iostream>
#  include <sys/types.h>
#  include <sys/stat.h>
#  include <stdint.h>

#  include <unistd.h>
#  include <stdlib.h>
#  include <dlfcn.h>
#  include <fcntl.h>
#  include <string.h>

#  ifndef byte
typedef unsigned char byte;
#  endif

bool islet_Init(const int cert_size, byte *cert);

bool islet_Attest(const int what_to_say_size,
                  byte *    what_to_say,
                  int *     attestation_size_out,
                  byte *    attestation_out);

bool islet_Verify(const int what_to_say_size,
                  byte *    what_to_say,
                  const int attestation_size,
                  byte *    attestation,
                  int *     measurement_out_size,
                  byte *    measurement_out);

bool islet_Seal(int in_size, byte *in, int *size_out, byte *out);

bool islet_Unseal(int in_size, byte *in, int *size_out, byte *out);

#endif  //  __ISLET_API_H__
