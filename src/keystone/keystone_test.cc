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

#include "certifier_framework.h"
#include "certifier_utilities.h"
#include "keystone_api.h"
#include <string.h>


using namespace certifier::utilities;

#define SIZE_WHAT_TO_SAY 256       // <= 1024
#define SIZE_ATTESTATION 1352      // must
#define SIZE_MEASUREMENT (64 * 2)  // must


bool keystone_test(const int cert_size, byte *cert) {
  if (!keystone_Init(cert_size, cert)) {
    printf("keystone_Init fails\n");
    return false;
  }

  int  size_secret = 64;
  byte secret[size_secret];
  int  size_sealed_secret = 128;
  byte sealed_secret[size_sealed_secret];
  int  size_unsealed_secret = 128;
  byte unsealed_secret[size_unsealed_secret];

  for (int i = 0; i < size_secret; i++) {
    secret[i] = (byte)i;
  }

  if (!keystone_Seal(size_secret, secret, &size_sealed_secret, sealed_secret)) {
    printf("keystone_Seal() fails\n");
    return false;
  }
  printf("Seal succeeded %d\n", size_sealed_secret);
  if (!keystone_Unseal(size_sealed_secret,
                       sealed_secret,
                       &size_unsealed_secret,
                       unsealed_secret)) {
    printf("keystone_Unseal() fails\n");
    return false;
  }
  printf("Unseal succeeded %d\n", size_unsealed_secret);
  if ((memcmp(secret, unsealed_secret, size_unsealed_secret)) != 0) {
    printf("Sealed and unsealed secrets do not match\n");
    return false;
  }
  printf("\n");

  int  size_what_to_say = 256;
  byte what_to_say[size_what_to_say];
  for (int i = 0; i < size_what_to_say; i++)
    what_to_say[i] = i;

  int  size_attestation = SIZE_ATTESTATION;
  byte attestation[size_attestation];
  int  size_measurement = SIZE_MEASUREMENT;
  byte measurement[size_measurement];

  for (int i = 0; i < size_what_to_say; i++) {
    what_to_say[i] = (byte)i;
  }

  if (!keystone_Attest(size_what_to_say,
                       what_to_say,
                       &size_attestation,
                       attestation)) {
    printf("keystone_Attest() fails\n");
    return false;
  }
  printf("\nAttest succeeded %d\n", size_attestation);
  print_bytes(size_attestation, attestation);
  printf("\n\n");
  if (!keystone_Verify(size_what_to_say,
                       what_to_say,
                       size_attestation,
                       attestation,
                       &size_measurement,
                       measurement)) {
    printf("keystone_Verify() fails\n");
    return false;
  }
  printf("Verify succeeded\n\n");
  printf("Measurement: ");
  print_bytes(size_measurement, measurement);
  printf("\n");

  return true;
}

// Return 0 if test succeeds; 1 otherwise to indicate failure.
int main(int argc, char **argv) {
  return (keystone_test(0, NULL) == false);
}
