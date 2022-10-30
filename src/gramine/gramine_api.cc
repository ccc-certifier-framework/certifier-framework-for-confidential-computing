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
#include <stdlib.h>

#include "support.h"
#include "certifier.h"
#include "simulated_enclave.h"
#include "application_enclave.h"
#include "cc_helpers.h"
#include "gramine_api.h"

#define MAX_ASSERTION_SIZE 512

GramineCertifierFunctions gramineFuncs;

void setFuncs(GramineCertifierFunctions funcs) {
  gramineFuncs.Attest = funcs.Attest;
  gramineFuncs.Verify = funcs.Verify;
  gramineFuncs.Seal = funcs.Seal;
  gramineFuncs.Unseal = funcs.Unseal;
}

bool gramine_Attest(int claims_size, byte* claims, int* size_out, byte* out) {
  byte assertion[MAX_ASSERTION_SIZE];
  memset(assertion, 0, MAX_ASSERTION_SIZE);
  int assertion_size = 0;
  bool result = false;

  printf("Invoking Gramine Attest %d\n", claims_size);
#if 0
  print_bytes(claims_size, claims);
  printf("\n");

  result = (*gramineFuncs.Attest)
           (claims_size, claims, &assertion_size, assertion);
  if (!result) {
    printf("Gramine attest failed\n");
    return false;
  }

  int total_size = assertion_size + claims_size + (sizeof(int) * 2);

  int i, j = 0;
  for (i = 0; i < sizeof(int); i++, j++) {
    out[j] = ((byte*)&assertion_size)[i];
  }

  for (i = 0; i < assertion_size; i++, j++) {
    out[j] = assertion[i];
  }

  for (i = 0; i < sizeof(int); i++, j++) {
    out[j] = ((byte*)&claims_size)[i];
  }

  for (i = 0; i < claims_size; i++, j++) {
    out[j] = claims[i];
  }

  *size_out = j;
#endif
  printf("Done Gramine Attest assertion size %d:\n", *size_out);
  print_bytes(*size_out, out);

  return true;
}

bool gramine_Verify(int claims_size, byte* claims, int *user_data_out_size,
                  byte *user_data_out, int* size_out, byte* out) {
  byte assertion[MAX_ASSERTION_SIZE];
  memset(assertion, 0, MAX_ASSERTION_SIZE);
  int assertion_size = 0;
  bool result = false;

  printf("\nInput claims sent to gramine_Verify:\n");
  print_bytes(claims_size, claims);

  int i, j = 0;
  for (i = 0; i < sizeof(int); i++, j++) {
    ((byte*)&assertion_size)[i] = claims[j];
  }

  for (i = 0; i < assertion_size; i++, j++) {
    assertion[i] = claims[j];
  }
  printf("\nAssertion:\n");
  print_bytes(assertion_size, assertion);

  for (i = 0; i < sizeof(int); i++, j++) {
    ((byte*)user_data_out_size)[i] = claims[j];
  }

  for (i = 0; i < *user_data_out_size; i++, j++) {
    user_data_out[i] = claims[j];
  }

  printf("\nuser_data_out:\n");
  print_bytes(*user_data_out_size, user_data_out);

  printf("Invoking Gramine Verify %d\n", claims_size);
  result = (*gramineFuncs.Verify)
           (*user_data_out_size, user_data_out, assertion_size,
             assertion, size_out, out);
  if (!result) {
    printf("Gramine verify failed\n");
    return false;
  }

  printf("Done Gramine Verify %d\n", *size_out);

  return true;
}

bool gramine_Seal(int in_size, byte* in, int* size_out, byte* out) {
  bool result = false;
  printf("Invoking Gramine Seal %d\n", in_size);

  result = (*gramineFuncs.Seal)(in_size, in, size_out, out);
  if (!result) {
    printf("Gramine seal failed\n");
    return false;
  }

  printf("Done Gramine Seal %d\n", *size_out);
  return true;
}

bool gramine_Unseal(int in_size, byte* in, int* size_out, byte* out) {
  bool result = false;
  printf("Invoking Gramine Unseal %d\n", in_size);

  result = (*gramineFuncs.Unseal)(in_size, in, size_out, out);
  if (!result) {
    printf("Gramine unseal failed\n");
    return false;
  }

  printf("Done Gramine Unseal %d\n", *size_out);
  return true;
}
