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

#include <dlfcn.h>

#include "gramine_api.h"
#include "gramine_verify_dcap.h"

#include "mbedtls/ssl.h"
#include "mbedtls/x509.h"
#include "mbedtls/sha256.h"
#include "mbedtls/aes.h"
#include "mbedtls/gcm.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

#define KEY_SIZE       16
#define SGX_MR_SIZE    32
#define USER_DATA_SIZE 256

enum { SUCCESS = 0, FAILURE = -1 };

ssize_t gramine_rw_file(const char *path,
                        uint8_t *   buf,
                        size_t      len,
                        bool        do_write) {
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

static inline int64_t local_sgx_getkey(sgx_key_request_t *keyrequest,
                                       sgx_key_128bit_t * key) {
  int64_t rax = EGETKEY;
  __asm__ volatile("enclu" : "+a"(rax) : "b"(keyrequest), "c"(key) : "memory");
  return rax;
}

int gramine_Sgx_Getkey(byte *user_report_data, sgx_key_128bit_t *key) {
  ssize_t bytes;

#ifdef DEBUG
  printf("Get key user_report_data size: %ld\n", sizeof(user_report_data));
#endif

  bytes = gramine_rw_file("/dev/attestation/user_report_data",
                          (uint8_t *)&user_report_data,
                          sizeof(user_report_data),
                          /*do_write=*/true);
  if (bytes != sizeof(user_report_data)) {
    printf("Test prep user_data failed %d\n", errno);
    return FAILURE;
  }

  /* read `report` file */
  sgx_report_t report;
  bytes = gramine_rw_file("/dev/attestation/report",
                          (uint8_t *)&report,
                          sizeof(report),
                          false);
  if (bytes != sizeof(report)) {
    /* error is already printed by file_read_f() */
    return FAILURE;
  }

  /* setup key request structure */
  __sgx_mem_aligned sgx_key_request_t key_request;
  memset(&key_request, 0, sizeof(key_request));
  key_request.key_name = SGX_SEAL_KEY;

  key_request.key_policy = SGX_KEYPOLICY_MRENCLAVE;
  key_request.attribute_mask.flags = SGX_FLAGS_MASK_CONST;
  key_request.attribute_mask.xfrm = SGX_XFRM_MASK_CONST;
  key_request.misc_mask = SGX_MISCSELECT_MASK_CONST;

  memcpy(&key_request.key_id, &(report.key_id), sizeof(key_request.key_id));

  /* retrieve key via EGETKEY instruction leaf */
  memset(*key, 0, sizeof(*key));
  local_sgx_getkey(&key_request, key);

#ifdef DEBUG
  printf("Got key:\n");
  gramine_print_bytes(sizeof(*key), (byte *)key);
  printf("\n");
#endif

  return SUCCESS;
}

bool gramine_attest_impl(const int what_to_say_size,
                         byte *    what_to_say,
                         int *     attestation_size_out,
                         byte *    attestation_out) {
  ssize_t bytes;
  uint8_t quote[SGX_QUOTE_MAX_SIZE];

#ifdef DEBUG
  printf("Attest quote interface, what_to_say size: %d\n", what_to_say_size);
  gramine_print_bytes(what_to_say_size, what_to_say);
#endif

  /* 1. write some custom data to `user_report_data` file */
  sgx_report_data_t user_report_data = {0};

  /* Get a SHA256 of user_data/what_to_say */
  mbedtls_sha256(what_to_say, what_to_say_size, user_report_data.d, 0);

#ifdef DEBUG
  printf("Attest quote interface prep user_data size: %ld\n",
         sizeof(user_report_data));
#endif

  bytes = gramine_rw_file("/dev/attestation/user_report_data",
                          (uint8_t *)&user_report_data,
                          sizeof(user_report_data),
                          /*do_write=*/true);

  if (bytes != sizeof(user_report_data)) {
    printf("Attest prep user_data failed %d\n", errno);
    return false;
  }

  /* 2. read `quote` file */
  bytes = gramine_rw_file("/dev/attestation/quote",
                          (uint8_t *)&quote,
                          sizeof(quote),
                          /*do_write=*/false);
  if (bytes < 0) {
    printf("Attest quote interface for user_data failed %d\n", errno);
    return false;
  }

  /* Copy out the attestation/quote */
  memcpy(attestation_out, quote, bytes);
  *attestation_size_out = bytes;

#ifdef DEBUG
  printf("Gramine Attest done\n");
#endif

  return true;
}

int remote_verify_quote(size_t   quote_size,
                        uint8_t *quote,
                        size_t * mr_size,
                        uint8_t *mr) {
  int                ret = -1;
  void *             sgx_verify_lib = NULL;
  uint8_t *          supplemental_data = NULL;
  uint32_t           supplemental_data_size = 0;
  uint32_t           collateral_expiration_status = 1;
  sgx_ql_qv_result_t verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;

  time_t current_time = time(NULL);
  if (current_time == ((time_t)-1)) {
    goto out;
  }

  sgx_verify_lib = dlopen("libsgx_dcap_quoteverify.so", RTLD_LAZY);
  if (!sgx_verify_lib) {
    printf("User requested SGX attestation but cannot find lib\n");
    return false;
  }

  sgx_qv_get_quote_supplemental_data_size =
      (int (*)(uint32_t *))dlsym(sgx_verify_lib,
                                 "sgx_qv_get_quote_supplemental_data_size");

#ifdef DEBUG
  printf("Supplemental data size address to be called: %p\n",
         sgx_qv_get_quote_supplemental_data_size);
#endif

  /* call into libsgx_dcap_quoteverify to get supplemental data size */
  ret = sgx_qv_get_quote_supplemental_data_size(&supplemental_data_size);
  if (ret) {
    ret = -1;
    goto out;
  }

  supplemental_data = (uint8_t *)malloc(supplemental_data_size);
  if (!supplemental_data) {
    ret = -1;
    goto out;
  }

#ifdef DEBUG
  printf("%s: Quote Size: %ld Quote:\n", __FUNCTION__, quote_size);
  gramine_print_bytes(quote_size, (uint8_t *)quote);
  printf("%s: Quote Version: %d\n",
         __FUNCTION__,
         ((sgx_quote_t *)quote)->body.version);
#endif

  sgx_qv_verify_quote =
      (int (*)(const uint8_t *,
               uint32_t,
               void *,
               const time_t,
               uint32_t *,
               sgx_ql_qv_result_t *,
               void *,
               uint32_t,
               uint8_t *))dlsym(sgx_verify_lib, "sgx_qv_verify_quote");
#ifdef DEBUG
  printf("Verify function address to be called: %p with size: %ld\n",
         sgx_qv_verify_quote,
         quote_size);
#endif

  /* call into libsgx_dcap_quoteverify to verify ECDSA-based SGX quote */
  ret = sgx_qv_verify_quote((uint8_t *)quote,
                            (uint32_t)quote_size,
                            NULL,
                            current_time,
                            &collateral_expiration_status,
                            &verification_result,
                            NULL,
                            supplemental_data_size,
                            supplemental_data);
  if (ret) {
    printf("%s: Quote Failed: %d\n", __FUNCTION__, ret);
    ret = -1;
    goto out;
  }

#ifdef DEBUG
  printf("%s: Supplemental size: %d data:\n",
         __FUNCTION__,
         supplemental_data_size);
  gramine_print_bytes(supplemental_data_size, (uint8_t *)supplemental_data);
  printf("%s: Quote verification done with result %d %s\n",
         __FUNCTION__,
         verification_result,
         sgx_ql_qv_result_to_str(verification_result));
#endif

  if (ret != 0) {
    printf("\nRemote verification failed: %d\n", ret);
    goto out;
  }

  /*
   * The out of date config and software hardening are acceptable for now. Users
   * will be given an option to change this behavior in a later patch.
   */
  if (verification_result != SGX_QL_QV_RESULT_OK
      && verification_result != SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED
      && verification_result
             != SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED) {
    printf("\nGramine acceptable verification failed: %d %s\n",
           verification_result,
           sgx_ql_qv_result_to_str(verification_result));
    ret = -1;
    goto out;
  }

  *mr_size = SGX_MR_SIZE;
  memcpy(mr,
         ((sgx_quote_t *)quote)->body.report_body.mr_enclave.m,
         SGX_MR_SIZE);

#ifdef DEBUG
  printf("MR enclave returned: %ld\n", *mr_size);
  gramine_print_bytes(*mr_size, mr);
  printf("\n");
#endif

out:
  free(supplemental_data);

#ifdef DEBUG
  printf("Verify done with result: %d\n", ret);
#endif

  return ret;
}

bool gramine_local_verify_impl(const int what_to_say_size,
                               byte *    what_to_say,
                               const int attestation_size,
                               byte *    attestation,
                               int *     measurement_out_size,
                               byte *    measurement_out) {
  ssize_t bytes;
  int     ret = -1;
  uint8_t quote[SGX_QUOTE_MAX_SIZE];

#ifdef DEBUG
  printf(
      "Gramine Local Verify called what_to_say_size: %d attestation_size: %d\n",
      what_to_say_size,
      attestation_size);
#endif

  /* 1. write some custom data to `user_report_data` file */
  sgx_report_data_t user_report_data = {0};

  /* Get a SHA256 of user_data/what_to_say */
  mbedtls_sha256(what_to_say, what_to_say_size, user_report_data.d, 0);

  bytes = gramine_rw_file("/dev/attestation/user_report_data",
                          (uint8_t *)&user_report_data,
                          sizeof(user_report_data),
                          /*do_write=*/true);
  if (bytes != sizeof(user_report_data)) {
    printf("Verify prep user_report_data failed %d\n", errno);
    return false;
  }

  /* 2. read `quote` file */
  bytes = gramine_rw_file("/dev/attestation/quote",
                          (uint8_t *)&quote,
                          sizeof(quote),
                          /*do_write=*/false);
  if (bytes < 0) {
    printf("Verify quote interface for user_report_data failed %d\n", errno);
    return false;
  }

  sgx_quote_t *quote_expected = (sgx_quote_t *)attestation;
  sgx_quote_t *quote_received = (sgx_quote_t *)quote;

  if (quote_expected->body.version != /*EPID*/ 2
      && quote_received->body.version != /*DCAP*/ 3) {
    printf("Version of SGX quote is not EPID (2) and not ECDSA/DCAP (3)\n");
    return false;
  }

  /* Compare user report and actual report */
#ifdef DEBUG
  printf("Comparing user report data in SGX quote size: %ld\n",
         sizeof(quote_expected->body.report_body.report_data.d));
#endif

  ret = memcmp(quote_received->body.report_body.report_data.d,
               user_report_data.d,
               sizeof(user_report_data));
  if (ret) {
    printf("comparison of user report data in SGX quote failed\n");
    return false;
  }

#ifdef DEBUG
  /* Compare expected and actual report */
  printf("Comparing quote report data in SGX quote size: %ld\n",
         sizeof(quote_expected->body.report_body.report_data.d));
#endif

  ret = memcmp(quote_expected->body.report_body.report_data.d,
               quote_received->body.report_body.report_data.d,
               sizeof(quote_expected->body.report_body.report_data.d));
  if (ret) {
    printf("comparison of quote report data in SGX quote failed\n");
    return false;
  }

#ifdef DEBUG
  printf("\nGramine verify quote interface mr_enclave: ");
  gramine_print_bytes(SGX_MR_SIZE,
                      quote_expected->body.report_body.mr_enclave.m);
#endif

  /* Copy out quote info */
  memcpy(measurement_out,
         quote_expected->body.report_body.mr_enclave.m,
         SGX_MR_SIZE);
  *measurement_out_size = SGX_MR_SIZE;

#ifdef DEBUG
  printf("\nGramine verify quote interface compare done, output: \n");
  gramine_print_bytes(*measurement_out_size, measurement_out);
  printf("\n");
#endif

  return true;
}

bool gramine_remote_verify_impl(const int what_to_say_size,
                                byte *    what_to_say,
                                const int attestation_size,
                                byte *    attestation,
                                int *     measurement_out_size,
                                byte *    measurement_out) {
  ssize_t bytes;
  int     ret = -1;
  uint8_t mr[SGX_MR_SIZE];
  size_t  mr_size;
  uint8_t quote[SGX_QUOTE_MAX_SIZE];

#ifdef DEBUG
  printf("Gramine Remote Verify called what_to_say_size: %d attestation_size: "
         "%d\n",
         what_to_say_size,
         attestation_size);
#endif

  sgx_quote_t *quote_expected = (sgx_quote_t *)attestation;

  /* Invoke remote_verify_quote() in DCAP library */
#ifdef DEBUG
  printf("\nGramine begin remote verify quote with DCAP\n");
#endif

  if (remote_verify_quote(attestation_size,
                          (uint8_t *)quote_expected,
                          &mr_size,
                          mr)
      != 0) {
    printf("\nGramine begin verify quote with DCAP failed\n");
    return false;
  }

  /* Compare user report and actual report */
#ifdef DEBUG
  printf("Comparing user report data in SGX quote size: %ld\n",
         sizeof(quote_expected->body.report_body.report_data.d));
#endif

  sgx_report_data_t user_report_data = {0};

  /* Get a SHA256 of user_data/what_to_say */
  mbedtls_sha256(what_to_say, what_to_say_size, user_report_data.d, 0);

  ret = memcmp(quote_expected->body.report_body.report_data.d,
               user_report_data.d,
               sizeof(user_report_data));
  if (ret) {
    printf("comparison of user report data in SGX quote failed\n");
    return false;
  }

  /* Copy out quote info */
  memcpy(measurement_out,
         quote_expected->body.report_body.mr_enclave.m,
         SGX_MR_SIZE);
  *measurement_out_size = SGX_MR_SIZE;

#ifdef DEBUG
  printf("\nGramine verify quote interface compare done, output: \n");
  gramine_print_bytes(*measurement_out_size, measurement_out);
  printf("\n");
#endif

  return true;
}

bool gramine_get_attributes_from_quote(byte *                attestation,
                                       GramineSgxAttributes *atts) {
  sgx_quote_t *quote = (sgx_quote_t *)attestation;
  uint64_t     flags;

  if (!attestation || !atts) {
    return false;
  }

  /* Quoting Enclave SVN */
  atts->qe_svn = quote->body.qe_svn;
  /* Provisioning Certification Enclave SVN */
  atts->pce_svn = quote->body.pce_svn;
  /* CPU SVN */
  memcpy(atts->cpu_svn, quote->body.report_body.cpu_svn.svn, SGX_CPUSVN_SIZE);

  /* Parse attributes */
  flags = quote->body.report_body.attributes.flags;
  /* Debug enclave */
  atts->debug = flags & SGX_FLAGS_DEBUG;
  /* 64-bit enclave */
  atts->mode64bit = flags & SGX_FLAGS_MODE64BIT;

  return true;
}

bool gramine_get_measurement(byte *measurement) {
  bool status = true;
  byte attestation[MAX_ATTESTATION_SIZE];
  byte user_data[USER_DATA_SIZE];
  int  attestation_size;

  for (int i = 0; i < USER_DATA_SIZE; i++) {
    user_data[i] = (byte)i;
  }

  status = gramine_attest_impl(USER_DATA_SIZE,
                               user_data,
                               &attestation_size,
                               attestation);
  if (status != true) {
    printf("gramine Attest failed\n");
    return status;
  }

  sgx_quote_t *quote = (sgx_quote_t *)attestation;
  memcpy(measurement, quote->body.report_body.mr_enclave.m, SGX_MR_SIZE);

  return status;
}

bool gramine_seal_impl(int in_size, byte *in, int *size_out, byte *out) {
  int                       ret = 0;
  bool                      status = true;
  __sgx_mem_aligned uint8_t key[KEY_SIZE];
  uint8_t                   tag[TAG_SIZE];
  unsigned char             enc_buf[in_size];
  mbedtls_gcm_context       gcm;
  int                       tag_size = TAG_SIZE;
  int                       i, j = 0;
  uint8_t                   measurement[SGX_MR_SIZE];

#ifdef DEBUG
  printf("Seal: Input size: %d \n", in_size);
  gramine_print_bytes(in_size, in);
  printf("\n");
#endif

  memset(enc_buf, 0, sizeof(enc_buf));

  if (gramine_get_measurement(measurement) != true) {
    printf("get_Measurement during Seal failed\n");
    return false;
  }

  /* Get SGX Sealing Key */
  if (gramine_Sgx_Getkey(measurement, (sgx_key_128bit_t *)key) == FAILURE) {
    printf("getkey failed to retrieve SGX Sealing Key\n");
    return false;
  }

  /* Use GCM encrypt/decrypt */
  mbedtls_gcm_init(&gcm);
  ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 128);

  if (ret != 0) {
    printf("mbedtls_gcm_setkey failed: %d\n", ret);
    status = false;
    goto done;
  }

  ret = mbedtls_gcm_crypt_and_tag(&gcm,
                                  MBEDTLS_GCM_ENCRYPT,
                                  in_size,
                                  key,
                                  KEY_SIZE,
                                  NULL,
                                  0,
                                  in,
                                  enc_buf,
                                  TAG_SIZE,
                                  tag);

  if (ret != 0) {
    printf("mbedtls_gcm_crypt_and_tag failed: %d\n", ret);
    status = false;
    goto done;
  }

#ifdef DEBUG
  printf("Testing seal interface - input buf:\n");
  gramine_print_bytes(in_size, in);
  printf("\n");
  printf("Testing seal interface - encrypted buf:\n");
  gramine_print_bytes(sizeof(enc_buf), enc_buf);
  printf("\n");
  printf("Testing seal interface - tag:\n");
  gramine_print_bytes(TAG_SIZE, tag);
  printf("\n");
#endif

  for (i = 0; i < sizeof(int); i++, j++) {
    out[j] = ((byte *)&in_size)[i];
  }
  for (i = 0; i < TAG_SIZE; i++, j++) {
    out[j] = tag[i];
  }
  for (i = 0; i < sizeof(enc_buf); i++, j++) {
    out[j] = enc_buf[i];
  }

  *size_out = j;

#ifdef DEBUG
  printf("Testing seal interface - out:\n");
  gramine_print_bytes(*size_out, out);
  printf("\n");
  printf("Seal: Successfully sealed size: %d\n", *size_out);
#endif

done:
  mbedtls_gcm_free(&gcm);
  return status;
}

bool gramine_unseal_impl(int in_size, byte *in, int *size_out, byte *out) {
  int                       ret = 0;
  bool                      status = true;
  __sgx_mem_aligned uint8_t key[KEY_SIZE];
  uint8_t                   tag[TAG_SIZE];
  mbedtls_gcm_context       gcm;
  int                       tag_size = TAG_SIZE;
  int                       enc_size = 0;
  int                       i, j = 0;
  uint8_t                   measurement[SGX_MR_SIZE];

#ifdef DEBUG
  printf("Preparing Unseal size: %d \n", in_size);
  gramine_print_bytes(in_size, in);
  printf("\n");
#endif

  for (i = 0; i < sizeof(int); i++, j++) {
    ((byte *)&enc_size)[i] = in[j];
  }

  for (i = 0; i < TAG_SIZE; i++, j++) {
    tag[i] = in[j];
  }

  unsigned char enc_buf[enc_size];
  unsigned char dec_buf[enc_size];

  memset(enc_buf, 0, enc_size);
  memset(dec_buf, 0, enc_size);

  for (i = 0; i < enc_size; i++, j++) {
    enc_buf[i] = in[j];
  }

#ifdef DEBUG
  printf("Testing unseal interface - encrypted buf: size: %d\n", enc_size);
  gramine_print_bytes(enc_size, enc_buf);
  printf("\n");
  printf("Testing unseal interface - tag:\n");
  gramine_print_bytes(TAG_SIZE, tag);
  printf("\n");
#endif

  if (gramine_get_measurement(measurement) != true) {
    printf("get_Measurement during Seal failed\n");
    return false;
  }

  /* Get SGX Sealing Key */
  if (gramine_Sgx_Getkey(measurement, (sgx_key_128bit_t *)key) == FAILURE) {
    printf("getkey failed to retrieve SGX Sealing Key\n");
    return false;
  }

  /* Use GCM encrypt/decrypt */
  mbedtls_gcm_init(&gcm);
  ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 128);

  if (ret != 0) {
    printf("mbedtls_gcm_setkey failed: %d\n", ret);
    status = false;
    goto done;
  }

  /* Invoke unseal */
  ret = mbedtls_gcm_auth_decrypt(&gcm,
                                 enc_size,
                                 key,
                                 KEY_SIZE,
                                 NULL,
                                 0,
                                 tag,
                                 TAG_SIZE,
                                 enc_buf,
                                 dec_buf);
  if (ret != 0) {
    printf("mbedtls_gcm_auth_decrypt failed: %d\n", ret);
    status = false;
    goto done;
  }

#ifdef DEBUG
  printf("Testing seal interface - decrypted buf:\n");
  gramine_print_bytes(enc_size, dec_buf);
  printf("\n");
#endif

  /* Set size */
  *size_out = enc_size;
  for (i = 0; i < enc_size; i++) {
    out[i] = dec_buf[i];
  }

#ifdef DEBUG
  printf("Successfully unsealed size: %d\n", *size_out);
#endif

done:
  mbedtls_gcm_free(&gcm);
  return status;
}

void gramine_setup_functions(GramineFunctions *gramineFuncs) {
  gramineFuncs->Attest = &gramine_attest_impl;
#ifdef GRAMINE_LOCAL_VERIFY
  gramineFuncs->Verify = &gramine_local_verify_impl;
#else
  gramineFuncs->Verify = &gramine_remote_verify_impl;
#endif
  gramineFuncs->Seal = &gramine_seal_impl;
  gramineFuncs->Unseal = &gramine_unseal_impl;
}
