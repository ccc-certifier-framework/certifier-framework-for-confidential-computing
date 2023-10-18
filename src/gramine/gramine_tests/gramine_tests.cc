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

/*
 * Attest/Verify/Seal/Unseal tests
 */

#include "gramine_api.h"

#define cert_file        "gramine_tests.crt"
#define attestation_file "gramine-attestation.bin"
#define BUF_SIZE         128
#define BUF_STORAGE_SIZE 4
#define TAG_SIZE         16
#define MAX_TAG_SIZE     (BUF_STORAGE_SIZE + TAG_SIZE)
#define USER_DATA_SIZE   256
#define MAX_CERT_SIZE    2048

byte cert[MAX_CERT_SIZE];

int main(int argc, char **argv) {
  int    ret = 0;
  size_t len;
  int    mr_size;
  int    attestation_size;
  int    sealed_size;
  int    unsealed_size;

  bool status = false;
  byte attestation[MAX_ATTESTATION_SIZE];
  byte attestation_bin[MAX_ATTESTATION_SIZE];
  byte mr_recd[SGX_HASH_SIZE];

  byte buf[BUF_SIZE];
  byte enc_buf[BUF_SIZE + MAX_TAG_SIZE];
  byte dec_buf[BUF_SIZE];

  GramineSgxAttributes attributes;

  int cert_size = gramine_file_size(cert_file);

  if (cert_size < 0) {
    printf("Error reading file size for certificate\n");
    return false;
  }

  if (cert_size > MAX_CERT_SIZE) {
    printf("Certificate file too large\n");
    return false;
  }

  ret = gramine_rw_file(cert_file, cert, cert_size, false);
  if (ret < 0 && ret != -ENOENT) {
    printf("Can't read cert file\n");
    return false;
  }

  status = gramine_Init(ret, cert);
  if (status != true) {
    printf("gramine_Init failed\n");
    return 1;
  }

  printf("gramine_Attest/gramine_Verify test begin\n");

  /* Attest/Verify with SGX quote verification */
  byte user_data[USER_DATA_SIZE];
  for (int i = 0; i < USER_DATA_SIZE; i++) {
    user_data[i] = (byte)i;
  }

  status =
      gramine_Attest(USER_DATA_SIZE, user_data, &attestation_size, attestation);
  if (status != true) {
    printf("gramine_Attest failed\n");
    return 1;
  }

  ret = gramine_rw_file(attestation_file, attestation, attestation_size, true);
  if (ret < 0 && ret != -ENOENT) {
    printf("Can't write attestation file\n");
    return false;
  }

  ret = gramine_rw_file(attestation_file,
                        attestation_bin,
                        gramine_file_size(attestation_file),
                        false);
  if (ret < 0 && ret != -ENOENT) {
    printf("Can't read attestation file\n");
    return false;
  }

  if (!gramine_get_attributes_from_quote(attestation_bin, &attributes)) {
    printf("Failed to parse SGX attributes\n");
  } else {
    printf("GramineSgxAttributes:\n");
    printf("\tqe_svn = 0x%x\n", attributes.qe_svn);
    printf("\tpce_svn = 0x%x\n", attributes.pce_svn);
    printf("\tcpu_svn = 0x");
    gramine_print_bytes(SGX_CPUSVN_SIZE, attributes.cpu_svn);
    printf("\n");
    printf("\tdebug = %s\n", attributes.debug ? "Yes" : "No");
    printf("\tmode64bit = %s\n", attributes.mode64bit ? "Yes" : "No");
  }

  status = gramine_Verify(USER_DATA_SIZE,
                          user_data,
                          attestation_size,
                          attestation,
                          &mr_size,
                          mr_recd);
  if (status != true) {
    printf("gramine_Verify failed\n");
    return 1;
  }
  printf("gramine_Attest/gramine_Verify test successful\n");

  /* Sealing test with a small buffer */
  for (int i = 0; i < BUF_SIZE; i++) {
    buf[i] = (byte)i;
  }
  memset(enc_buf, 0, sizeof(enc_buf));
  memset(dec_buf, 0, sizeof(dec_buf));

  printf("gramine_Seal/gramine_Unseal test begin\n");

  status = gramine_Seal(BUF_SIZE, buf, &sealed_size, enc_buf);
  if (status != true) {
    printf("gramine_Seal failed\n");
    return 1;
  }

  status =
      gramine_Unseal(BUF_SIZE + MAX_TAG_SIZE, enc_buf, &unsealed_size, dec_buf);
  if (status != true) {
    printf("gramine_Unseal failed\n");
    return 1;
  }

  if (sealed_size != unsealed_size + MAX_TAG_SIZE) {
    printf("Gramine seal/unseal size failed\n");
    return 1;
  }

  ret = memcmp(buf, dec_buf, sizeof(dec_buf));
  if (ret) {
    printf("Gramine comparison of encrypted and decrypted buffers failed\n");
    return 1;
  }

#ifdef DEBUG
  printf("Testing seal interface - input buf:\n");
  gramine_print_bytes(BUF_SIZE, buf);
  printf("\n");
  printf("Testing seal interface - encrypted buf:\n");
  gramine_print_bytes(BUF_SIZE, enc_buf);
  printf("\n");
  printf("\n");
#endif

  printf("gramine_Seal/gramine_Unseal test successful\n");

exit:
  fflush(stdout);

  return ret;
}
