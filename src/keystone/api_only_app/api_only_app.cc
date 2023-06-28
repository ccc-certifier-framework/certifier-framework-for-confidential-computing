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

// TODO: should use src/keystone/keystone_tests instead
#include "keystone_api.h"

#define SIZE_SECRET 32 // any
#define SIZE_WHAT_TO_SAY 256 // <= 1024
#define SIZE_ATTESTATION 1352 // must
#define SIZE_MEASUREMENT (64*2) // must

bool keystone_test(const int cert_size, byte *cert) {
    if (!keystone_Init(cert_size, cert)) {
        printf("keystone_Init fails\n");
        return false;
    }

    bool success = true;
    int size_secret = SIZE_SECRET;
    byte secret[size_secret];
    int size_sealed_secret = SIZE_SECRET;
    byte sealed_secret[size_sealed_secret];
    int size_unsealed_secret = SIZE_SECRET;
    byte unsealed_secret[size_unsealed_secret];

    for (int i = 0; i < size_secret; i++) {
        secret[i] = (byte)i;
    }

    if (!keystone_Seal(size_secret, secret, &size_sealed_secret, sealed_secret)) {
        printf("keystone_Seal() fails\n");
        success = false;
    }
    if (!keystone_Unseal(size_sealed_secret, sealed_secret, &size_unsealed_secret, unsealed_secret)) {
        printf("keystone_Unseal() fails\n");
        success = false;
    }
    int memcmp_rc = 0;
    if (size_unsealed_secret != size_secret) {
        printf("Sealed and unsealed secrets lengths do not match, size_unsealed_secret=%d, size_secret=%d\n",
               size_unsealed_secret, size_secret);
        success = false;
    }
    else if ((memcmp_rc = std::memcmp(secret, unsealed_secret, size_unsealed_secret)) != 0) {
        printf("Sealed and unsealed secrets do not match, memcmp_rc=%d\n", memcmp_rc);
        success = false;
    }

    int size_what_to_say = SIZE_WHAT_TO_SAY;
    byte what_to_say[size_what_to_say];
    int size_attestation = SIZE_ATTESTATION;
    byte attestation[size_attestation];
    int size_measurement = SIZE_MEASUREMENT;
    byte measurement[size_measurement];

    for (int i = 0; i < size_what_to_say; i++) {
        what_to_say[i] = (byte)i;
    }

    if (!keystone_Attest(size_what_to_say, what_to_say,
                         &size_attestation, attestation)) {
        printf("keystone_Attest() fails\n");
        success = false;
    }
    if (!keystone_Verify(size_what_to_say, what_to_say,
                         size_attestation, attestation, &size_measurement, measurement)) {
        printf("keystone_Verify() fails\n");
        success = false;
    }
    printf("Measurement: ");
    for (int i = 0; i < size_measurement; i++) {
        printf("%x", measurement[i]);
    }
    printf("\n");

    return success;
}

int main(int argc, char** argv) {
    return !keystone_test(0, NULL);
}
