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

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <cmath>
#include <memory>
#include <string>

#include "certifier.pb.h"

#ifndef byte
typedef unsigned char byte;
#endif

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "certifier.h"
#include "certifier.pb.h"

using std::string;

#ifndef _APPLICATION_ENCLAVE_H__
#define _APPLICATION_ENCLAVE_H__

bool
application_Init(const string &parent_enclave_type, int read_fd, int write_fd);
bool
application_Seal(int in_size, byte *in, int *size_out, byte *out);
bool
application_Unseal(int in_size, byte *in, int *size_out, byte *out);
bool
application_Attest(int   what_to_say_size,
                   byte *what_to_say,
                   int * size_out,
                   byte *out);
bool
application_GetParentEvidence(string *out);
bool
application_GetPlatformStatement(int *size_out, byte *out);

#endif
