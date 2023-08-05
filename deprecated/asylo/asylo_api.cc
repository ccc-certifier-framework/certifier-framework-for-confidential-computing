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
#include <stdlib.h>

#include "support.h"
#include "certifier.h"
#include "simulated_enclave.h"
#include "application_enclave.h"
#include "cc_helpers.h"
#include "asylo_api.h"

#define MAX_ASSERTION_SIZE 512

AsyloCertifierFunctions asyloFuncs;

void setFuncs(AsyloCertifierFunctions funcs) {
  asyloFuncs.Attest = funcs.Attest;
  asyloFuncs.Verify = funcs.Verify;
  asyloFuncs.Seal = funcs.Seal;
  asyloFuncs.Unseal = funcs.Unseal;
}

bool asylo_Attest(int claims_size, byte *claims, int *size_out, byte *out) {
  byte assertion[MAX_ASSERTION_SIZE];
  memset(assertion, 0, MAX_ASSERTION_SIZE);
  int  assertion_size = 0;
  bool result = false;

  printf("Invoking Asylo Attest %d\n", claims_size);
  print_bytes(claims_size, claims);
  printf("\n");

  result =
      (*asyloFuncs.Attest)(claims_size, claims, &assertion_size, assertion);
  if (!result) {
    printf("Asylo attest failed\n");
    return false;
  }

  int total_size = assertion_size + claims_size + (sizeof(int) * 2);

  int i, j = 0;
  for (i = 0; i < sizeof(int); i++, j++) {
    out[j] = ((byte *)&assertion_size)[i];
  }

  for (i = 0; i < assertion_size; i++, j++) {
    out[j] = assertion[i];
  }

  for (i = 0; i < sizeof(int); i++, j++) {
    out[j] = ((byte *)&claims_size)[i];
  }

  for (i = 0; i < claims_size; i++, j++) {
    out[j] = claims[i];
  }

  *size_out = j;

  printf("Done Asylo Attest assertion size %d:\n", *size_out);
  print_bytes(*size_out, out);

  return true;
}

bool asylo_Verify(int   claims_size,
                  byte *claims,
                  int * user_data_out_size,
                  byte *user_data_out,
                  int * size_out,
                  byte *out) {
  byte assertion[MAX_ASSERTION_SIZE];
  memset(assertion, 0, MAX_ASSERTION_SIZE);
  int  assertion_size = 0;
  bool result = false;

  printf("\nInput claims sent to asylo_Verify:\n");
  print_bytes(claims_size, claims);

  int i, j = 0;
  for (i = 0; i < sizeof(int); i++, j++) {
    ((byte *)&assertion_size)[i] = claims[j];
  }

  for (i = 0; i < assertion_size; i++, j++) {
    assertion[i] = claims[j];
  }
  printf("\nAssertion:\n");
  print_bytes(assertion_size, assertion);

  for (i = 0; i < sizeof(int); i++, j++) {
    ((byte *)user_data_out_size)[i] = claims[j];
  }

  for (i = 0; i < *user_data_out_size; i++, j++) {
    user_data_out[i] = claims[j];
  }

  printf("\nuser_data_out:\n");
  print_bytes(*user_data_out_size, user_data_out);

  printf("Invoking Asylo Verify %d\n", claims_size);
  result = (*asyloFuncs.Verify)(*user_data_out_size,
                                user_data_out,
                                assertion_size,
                                assertion,
                                size_out,
                                out);
  if (!result) {
    printf("Asylo verify failed\n");
    return false;
  }

  printf("Done Asylo Verify %d\n", *size_out);

  return true;
}

bool asylo_Seal(int in_size, byte *in, int *size_out, byte *out) {
  bool result = false;
  printf("Invoking Asylo Seal %d\n", in_size);

  result = (*asyloFuncs.Seal)(in_size, in, size_out, out);
  if (!result) {
    printf("Asylo seal failed\n");
    return false;
  }

  printf("Done Asylo Seal %d\n", *size_out);
  return true;
}

bool asylo_Unseal(int in_size, byte *in, int *size_out, byte *out) {
  bool result = false;
  printf("Invoking Asylo Unseal %d\n", in_size);

  result = (*asyloFuncs.Unseal)(in_size, in, size_out, out);
  if (!result) {
    printf("Asylo unseal failed\n");
    return false;
  }

  printf("Done Asylo Unseal %d\n", *size_out);
  return true;
}
