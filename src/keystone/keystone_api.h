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

// Special thanks to Evgeny Pobachienko, UCB.

#include <iostream>
// #include <sys/types.h>
// #include <sys/stat.h>
// #include <stdint.h>

#include <unistd.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <string.h>

#ifndef byte
typedef unsigned char byte;
#endif

#ifndef __KEYSTONE_API__
#define __KEYSTONE_API__
bool keystone_Init(const int cert_size, byte *cert);
bool keystone_Attest(const int what_to_say_size, byte* what_to_say, int* attestation_size_out, byte* attestation_out);
bool keystone_Verify(const int what_to_say_size, byte* what_to_say, const int attestation_size, byte* attestation, int* measurement_out_size, byte* measurement_out);
bool keystone_Seal(int in_size, byte* in, int* size_out, byte* out);
bool keystone_Unseal(int in_size, byte* in, int* size_out, byte* out);

#ifdef KEYSTONE_PRESENT
#include "verifier/report.h"
#else
// BEGIN copied Keys.hpp
#define ATTEST_DATA_MAXLEN 1024
#define MDSIZE 64
#define SIGNATURE_SIZE 144
// it was #define SIGNATURE_SIZE 64
#define PUBLIC_KEY_SIZE 64
// END copied Keys.hpp

// BEGIN copied Report.hpp

// The enclave.hash in enclave_report_t is the measurement
// of the runtime + application -- the customizable os-like
// runtime and the actual user application.
// The hash, datalen and data (which is the "what was said")
// is hashed and signed  --- that's the signature below.
struct enclave_report_t {
  byte hash[MDSIZE];
  uint64_t data_len;
  byte data[32];  // this was ATTEST_DATA_MAXLEN
  byte signature[SIGNATURE_SIZE];
  int size_sig;  // Remove?
};

// The hash in sm_report_t is the hash of the cpu embedded
// security code/Monitor that provides the trusted primitives.
struct sm_report_t {
  byte hash[MDSIZE];
  byte public_key[PUBLIC_KEY_SIZE];
  byte signature[SIGNATURE_SIZE];
};

// Usually the dev_public_key int report_t below
// and the public_key in sm_report_t are the
// same trusted key of the manufacturer and will
// come with a cert chain in Init.
struct report_t {
  struct enclave_report_t enclave;
  struct sm_report_t sm;
  byte dev_public_key[PUBLIC_KEY_SIZE];
};
// END copied Report.hpp
#endif

#endif
