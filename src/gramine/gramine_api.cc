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

#include "gramine_api.h"

#define MAX_ASSERTION_SIZE 5000
#define ATTESTATION_TYPE_SIZE 32
#define MAX_CERT_SIZE 2048

GramineCertifierFunctions gramineFuncs;

uint8_t cert[MAX_CERT_SIZE];
uint8_t measurement[SGX_REPORT_DATA_SIZE];
bool cert_initialized = false;

static ssize_t rw_file(const char* path, uint8_t* buf, size_t len, bool do_write) {
    ssize_t bytes = 0;
    ssize_t ret = 0;

    int fd = open(path, do_write ? O_WRONLY : O_RDONLY);
    if (fd < 0)
        return fd;

    while ((ssize_t)len > bytes) {
        if (do_write)
            ret = write(fd, buf + bytes, len - bytes);
        else
            ret = read(fd, buf + bytes, len - bytes);

        if (ret > 0) {
            bytes += ret;
        } else if (ret == 0) {
            /* end of file */
            break;
        } else {
            if (ret < 0 && (errno == EAGAIN || errno == EINTR))
                continue;
            break;
        }
    }

    close(fd);
    return ret < 0 ? ret : bytes;
}

int file_size(const char *file_name) {
  struct stat file_info;

  if (stat(file_name, &file_info) != 0)
    return false;
  if (!S_ISREG(file_info.st_mode))
    return false;
  return (int)file_info.st_size;
}

bool gramine_Init(const char *measurement_file, const char *cert_file) {
  char attestation_type_str[ATTESTATION_TYPE_SIZE] = {0};
  void* ra_tls_attest_lib;
  size_t ret = 0;

  ret = rw_file("/dev/attestation/attestation_type", (uint8_t*)attestation_type_str,
                sizeof(attestation_type_str) - 1, /*do_write=*/false);
  if (ret < 0 && ret != -ENOENT) {
    printf("User requested SGX attestation but cannot read SGX-specific file "
           "/dev/attestation/attestation_type\n");
    return false;
  }
  printf("Attestation type: %s\n", attestation_type_str);

  if (ret == -ENOENT || !strcmp(attestation_type_str, "none")) {
    ra_tls_attest_lib = NULL;
  } else if (!strcmp(attestation_type_str, "epid") || !strcmp(attestation_type_str, "dcap")) {
   ra_tls_attest_lib = dlopen("libra_tls_attest.so", RTLD_LAZY);
    if (!ra_tls_attest_lib) {
        printf("User requested RA-TLS attestation but cannot find lib\n");
        return false;
    }
  } else {
    printf("Unrecognized remote attestation type: %s\n", attestation_type_str);
    return false;
  }

  /* Setup Gramine specific API calls */
  gramine_setup_certifier_functions(&gramineFuncs);

  int size = file_size(measurement_file);
  if (size < 0) {
    printf("Error reading file size for measurement\n");
    return false;
  }
  ret = rw_file(measurement_file, measurement, size, false);
  if (ret < 0 && ret != -ENOENT) {
    printf("gramine_Init: Can't read measurement file\n");
    return false;
  }

#ifdef DEBUG
  printf("gramine_Init: Setting up measurement: ");
  print_bytes(size, measurement);
  printf("\n");
#endif

  size = file_size(cert_file);
  if (size < 0) {
    printf("Error reading file size for certificate\n");
    return false;
  }
  ret = rw_file(cert_file, cert, size, false);
  if (ret < 0 && ret != -ENOENT) {
    printf("gramine_Init: Can't read cert file\n");
    return false;
  }

#ifdef DEBUG
  printf("gramine_Init: Setting up cert: ");
  print_bytes(size, cert);
  printf("\n");
#endif

  cert_initialized = true;

  return true;
}

bool gramine_Attest(int claims_size, byte* claims, int* size_out, byte* out) {
  byte assertion[MAX_ASSERTION_SIZE];
  memset(assertion, 0, MAX_ASSERTION_SIZE);
  int assertion_size = 0;
  bool result = false;

  printf("Invoking Gramine Attest %d\n", claims_size);

#ifdef DEBUG
  print_bytes(claims_size, claims);
  printf("\n");
#endif

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

  printf("Done Gramine Attest assertion size %d:\n", *size_out);
#ifdef DEBUG
  print_bytes(*size_out, out);
#endif

  return true;
}

bool gramine_Verify(int claims_size, byte* claims, int *user_data_out_size,
                  byte *user_data_out, int* size_out, byte* out) {
  byte assertion[MAX_ASSERTION_SIZE];
  memset(assertion, 0, MAX_ASSERTION_SIZE);
  int assertion_size = 0;
  bool result = false;

  printf("\nInput claims sent to gramine_Verify claims_size %d\n", claims_size);
#ifdef DEBUG
  print_bytes(claims_size, claims);
#endif

  int i, j = 0;
  for (i = 0; i < sizeof(int); i++, j++) {
    ((byte*)&assertion_size)[i] = claims[j];
  }

  for (i = 0; i < assertion_size; i++, j++) {
    assertion[i] = claims[j];
  }

#ifdef DEBUG
  printf("\nAssertion:\n");
  print_bytes(assertion_size, assertion);
#endif

  for (i = 0; i < sizeof(int); i++, j++) {
    ((byte*)user_data_out_size)[i] = claims[j];
  }

  for (i = 0; i < *user_data_out_size; i++, j++) {
    user_data_out[i] = claims[j];
  }

#ifdef DEBUG
  printf("\nuser_data_out:\n");
  print_bytes(*user_data_out_size, user_data_out);
#endif

  printf("Invoking Gramine Verify %d\n", claims_size);
  result = (*gramineFuncs.Verify)
           (*user_data_out_size, user_data_out, assertion_size,
             assertion, size_out, out);
  if (!result) {
    printf("Gramine verify failed\n");
    return false;
  }

  printf("Done Gramine Verification via API\n");

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

int gramine_Getkey(byte *user_report_data, sgx_key_128bit_t* key) {
  return gramine_Sgx_Getkey(user_report_data, key);
}
