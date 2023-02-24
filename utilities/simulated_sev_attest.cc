#include "certifier.h"
#include "support.h"
#include "attestation.h"
#include <gflags/gflags.h>

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


DEFINE_bool(print_all, false,  "verbose");
DEFINE_string(key_file, "../certifier_service/certlib/test_data/ec-secp384r1-priv-key.pem",  "private key file name");
DEFINE_string(output, "signed_sev_attest.bin",  "simulated attest file");

static struct attestation_report default_report = {
        .version = 1,
        .guest_svn = 1, // Set to 1 for now
        .policy = 0xff,
        .signature_algo = SIG_ALGO_ECDSA_P384_SHA384,
        .platform_info = 0, // SMT disable
        // TODO: Hardcoded mockup measurement
        .measurement = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
};

int read_key_file(const string& filename, EVP_PKEY **key, bool priv) {

  int rc = -EXIT_FAILURE;
  EVP_PKEY *pkey;
  FILE *file = NULL;

  pkey = EVP_PKEY_new();
  file = fopen(filename.c_str(), "r");
  if (!file) {
    rc = EIO;
    goto out;
  }

  if (priv) {
    if (PEM_read_PrivateKey(file, &pkey, NULL, NULL) == NULL) {
      rc = EIO;
      goto out_close;
    }
  } else {
    if (PEM_read_PUBKEY(file, &pkey, NULL, NULL) == NULL) {
      rc = EIO;
      goto out_close;
    }
  }
  *key = pkey;
  rc = EXIT_SUCCESS;

out_close:
  fclose(file);
out:
  return rc;
}


// This generates an sev attestation signed by the key in key_file
int main(int an, char** av) {
  gflags::ParseCommandLineFlags(&an, &av, true);

  printf("simulated_sev_attest.exe.exe --key_file=ecc-384-private.pem --output=test_sev_attest.bin\n");

  EVP_PKEY* pkey = nullptr;
  if (read_key_file(FLAGS_key_file, &pkey, true) < 0) {
    printf("Can't read key from %s\n", FLAGS_key_file.c_str());
    return 1;
  }
  EC_KEY* eck = EVP_PKEY_get1_EC_KEY(pkey);
  if (eck == nullptr) {
    printf("Can't get ec key\n");
    return 1;
  }
  int size_out = sizeof(signature);
  if (!ecc_sign("sha-384", eck, sizeof(attestation_report) - sizeof(signature), (byte*) &default_report,
		&size_out, (byte*)&default_report.signature)) {
    printf("signature failure\n");
    return 1;
  }
  if (!write_file(FLAGS_output, sizeof(attestation_report), (byte*) &default_report)) {
    printf("Can't write %s\n", FLAGS_output.c_str());
    return 1;
  }

  return 0;
}
