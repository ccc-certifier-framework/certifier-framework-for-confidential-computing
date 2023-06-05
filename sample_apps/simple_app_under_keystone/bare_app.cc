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

bool keystone_test() {
    int size_secret = 32;
    byte secret[size_secret];
    int size_sealed_secret = 128;
    byte sealed_secret[size_sealed_secret];
    int size_unsealed_secret = 128;
    byte unsealed_secret[size_unsealed_secret];

    for (int i = 0; i < size_secret; i++) {
        secret[i] = (byte)i;
    }

    if (!keystone_Seal(size_secret, secret, &size_sealed_secret, sealed_secret)) {
        printf("keystone_Seal fails\n");
        return false;
    }
    if (!keystone_Unseal(size_sealed_secret, sealed_secret, &size_unsealed_secret, unsealed_secret)) {
        printf("keystone_Unseal fails\n");
        return false;
    }
    if (size_unsealed_secret != size_secret || memcmp(secret, unsealed_secret, size_unsealed_secret) != 0) {
        printf("Sealed and unsealed secrets do not match\n");
        return false;
    }

    int size_what_to_say = 256;
    byte what_to_say[size_secret];
    int size_attestation = 512;
    byte attestation[size_sealed_secret];
    int size_measurement = 64;
    byte measurement[size_measurement];

    for (int i = 0; i < size_what_to_say; i++) {
        what_to_say[i] = (byte)i;
    }

    if (!keystone_Attest(size_what_to_say, what_to_say,
                         &size_attestation, attestation)) {
        printf("keystone_Attest fails\n");
        return false;
    }
    if (!keystone_Verify(size_what_to_say, what_to_say,
                         size_attestation, attestation, &size_measurement, measurement)) {
        printf("keystone_Verify fails\n");
        return false;
    }
    printf("Measurement: ");
    for (int i = 0; i < size_measurement; i++) {
        printf("%x", measurement[i]);
    }
    printf("\n");

    return true;
}

int main(int argc, char** argv) {
    return keystone_test();
}
