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

#include "certifier.h"
#include "support.h"
#include "attestation.h"
#include <gflags/gflags.h>

using namespace certifier::utilities;

DEFINE_bool(print_all, false, "verbose");
DEFINE_string(
    key_file,
    "../certifier_service/certlib/test_data/ec-secp384r1-priv-key.pem",
    "private key file name");
DEFINE_string(output, "signed_sev_attest.bin", "simulated attest file");

/*
  From a real Sev machine

    Version: 2
    Guest SVN: 0
  Policy: 0x30000
    - Debugging Allowed:       No
    - Migration Agent Allowed: No
    - SMT Allowed:             Yes
    - Min. ABI Major:          0
    - Min. ABI Minor:          0
  Family ID:
    00000000000000000000000000000000
  Image ID:
    00000000000000000000000000000000
  VMPL: 0
  Signature Algorithm: 1 (ECDSA P-384 with SHA-384)
  Platform Version: 03000000000008115
    - Boot Loader SVN:   3
    - TEE SVN:           0
    - SNP firmware SVN:  8
    - Microcode SVN:    115
   - Microcode SVN:    115
  Platform Info: 0x3
    - SMT Enabled: Yes
  Author Key Enabled: Yes
    Report Data:
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
  Measurement:
    5c19d5b4a50066c8c991bd920dfa2276e11d3531c91434a7
    34f3b258ab279cd1b3bbe89ef930236af11dc3d28c70f406
  Host Data:
    0000000000000000000000000000000000000000000000000000000000000000
  ID Key Digest:
    000000000000000000000000000000000000000000000000
    000000000000000000000000000000000000000000000000
  Author Key Digest:
    000000000000000000000000000000000000000000000000
    000000000000000000000000000000000000000000000000
  Report ID:
    e2af014dad028f1f2adf3c1b0f896a4e43307596fc75b9242c706764d82e620d
  Migration Agent Report ID:
    ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
  Reported TCB: 03000000000008115
  - Boot Loader SVN:   3
  - TEE SVN:           0
  - SNP firmware SVN:  8
  - Microcode SVN:    115
  Chip ID:
    d30d7b8575881faa90edf4fb4f7a1c52a0beedef9321af3780abd4b4c16cf5c8
    132d9d15d6537f3704de10afe7e8d989c7959654c38be1905cf9506ea737976f
 */
static struct attestation_report default_report = {
    .version = 1,    // should be 2
    .guest_svn = 1,  // Set to 1 for now
    .policy = 0x03,  // 0x30000
    .signature_algo = SIG_ALGO_ECDSA_P384_SHA384,
    .platform_info = 0,  // SMT disable --- should be 0x03?
    // Hardcoded mockup measurement
    .measurement = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02,
                    0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04,
                    0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                    0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
};

int read_key_file(const string &filename, EVP_PKEY **key, bool priv) {

  int       rc = -EXIT_FAILURE;
  EVP_PKEY *pkey;
  FILE *    file = NULL;

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
int main(int an, char **av) {
  gflags::ParseCommandLineFlags(&an, &av, true);

  printf("simulated_sev_attest.exe.exe --key_file=ecc-384-private.pem "
         "--output=test_sev_attest.bin\n");

  default_report.reported_tcb.raw = 0x03000000000008115ULL;
  default_report.platform_version.raw = 0x03000000000008115ULL;

  EVP_PKEY *pkey = nullptr;
  if (read_key_file(FLAGS_key_file, &pkey, true) < 0) {
    printf("Can't read key from %s\n", FLAGS_key_file.c_str());
    return 1;
  }
  EC_KEY *eck = EVP_PKEY_get1_EC_KEY(pkey);
  if (eck == nullptr) {
    printf("Can't get ec key\n");
    return 1;
  }
  int size_out = sizeof(signature);
  if (!ecc_sign(Digest_method_sha_384,
                eck,
                sizeof(attestation_report) - sizeof(signature),
                (byte *)&default_report,
                &size_out,
                (byte *)&default_report.signature)) {
    printf("signature failure\n");
    return 1;
  }
  if (!write_file(FLAGS_output,
                  sizeof(attestation_report),
                  (byte *)&default_report)) {
    printf("Can't write %s\n", FLAGS_output.c_str());
    return 1;
  }

  return 0;
}
