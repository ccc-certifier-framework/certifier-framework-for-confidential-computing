/* Portions of this file are Copyright (C) 2021 Advanced Micro Devices, Inc. */

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

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <attestation.h>
#include <sev-guest.h>
#include <sev-ecdsa.h>
#include <report.h>
#include <snp-derive-key.h>

#define SEV_GUEST_DEVICE "/dev/sev-guest"
#define SEV_DUMMY_GUEST
#define SEV_ECDSA_PRIV_KEY "/etc/certifier-snp-sim/ec-secp384r1-priv-key.pem"
#define SEV_ECDSA_PUB_KEY  "/etc/certifier-snp-sim/ec-secp384r1-pub-key.pem"

struct key_options {
  union tcb_version tcb;

  const char *key_filename;

  uint64_t fields;
  uint32_t svn;

  bool do_help;
  bool do_root_key;
};

int request_key(struct key_options *options, uint8_t *key, size_t size) {
  int                            rc = EXIT_FAILURE;
  int                            fd = -1;
  struct snp_derived_key_req     req;
  struct snp_derived_key_resp    resp;
  struct snp_guest_request_ioctl guest_req;
  struct msg_key_resp *          key_resp = (struct msg_key_resp *)&resp.data;

  if (!options || !key || size < sizeof(key_resp->derived_key)) {
    rc = EINVAL;
    goto out;
  }

  /* Initialize data structures */
  memset(&req, 0, sizeof(req));
  req.root_key_select =
      options->do_root_key ? MSG_KEY_REQ_ROOT_KEY_SELECT_MASK : 0;
  req.guest_field_select = options->fields;
  req.guest_svn = options->svn;
  memcpy(&req.tcb_version, &options->tcb, sizeof(req.tcb_version));

  memset(&resp, 0, sizeof(resp));

  memset(&guest_req, 0, sizeof(guest_req));
  guest_req.msg_version = 1;
  guest_req.req_data = (__u64)&req;
  guest_req.resp_data = (__u64)&resp;

  /* Open the sev-guest device */
  errno = 0;
  fd = open(SEV_GUEST_DEVICE, O_RDWR);
  if (fd == -1) {
    rc = errno;
    perror("open");
    goto out;
  }

  /* Issue the guest request IOCTL */
  errno = 0;
  rc = ioctl(fd, SNP_GET_DERIVED_KEY, &guest_req);
  if (rc == -1) {
    rc = errno;
    perror("ioctl");
    fprintf(stderr, "firmware error %llu\n", guest_req.fw_err);
    goto out_close;
  }

  /* Check that the key was successfully derived */
  if (key_resp->status != 0) {
    fprintf(stderr, "firmware error %#x\n", key_resp->status);
    rc = key_resp->status;
    goto out_close;
  }

  memcpy(key, &key_resp->derived_key, size);
  rc = EXIT_SUCCESS;

out_close:
  if (fd > 0) {
    close(fd);
    fd = -1;
  }
out:
  return rc;
}

#ifdef SEV_DUMMY_GUEST
int read_key_file(const char *filename, EVP_PKEY **key, bool priv) {
  int       rc = -EXIT_FAILURE;
  EVP_PKEY *pkey;
  FILE *    file = NULL;

  pkey = EVP_PKEY_new();
  file = fopen(filename, "r");
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

int sign_report(struct attestation_report *report) {
  int       rc = -EXIT_FAILURE;
  EVP_PKEY *key = NULL;
  rc = read_key_file(SEV_ECDSA_PRIV_KEY, &key, true);
  if (rc != EXIT_SUCCESS) {
    errno = rc;
    perror("read_key_file");
    goto exit;
  }
  rc = sev_ecdsa_sign(
      report,
      sizeof(struct attestation_report) - sizeof(struct signature),
      key,
      (union sev_ecdsa_sig *)&report->signature);
  if (rc != EXIT_SUCCESS) {
    errno = rc;
    perror("sev_ecdsa_sign");
    goto exit;
  }

exit:
  if (key) {
    EVP_PKEY_free(key);
    key = NULL;
  }
  return rc;
}

static bool digest_sha384(const void *msg,
                          size_t      msg_len,
                          uint8_t *   digest,
                          size_t      digest_len) {
  bool ret = false;

  do {
    SHA512_CTX context;

    if (SHA384_Init(&context) != 1)
      break;
    if (SHA384_Update(&context, (void *)msg, msg_len) != 1)
      break;
    if (SHA384_Final(digest, &context) != 1)
      break;

    ret = true;
  } while (0);

  return ret;
}

int verify_report(struct attestation_report *report) {
  int           rc = -EXIT_FAILURE;
  EVP_PKEY *    key = NULL;
  unsigned char sha_digest_384[SHA384_DIGEST_LENGTH];
  rc = read_key_file(SEV_ECDSA_PUB_KEY, &key, false);
  if (rc != EXIT_SUCCESS) {
    errno = rc;
    perror("read_key_file");
    goto exit;
  }
  if (!digest_sha384(
          report,
          sizeof(struct attestation_report) - sizeof(struct signature),
          sha_digest_384,
          sizeof(sha_digest_384))) {
    rc = -EXIT_FAILURE;
    perror("sha_digest_384");
    goto exit;
  }
  rc = sev_ecdsa_verify(sha_digest_384,
                        sizeof(sha_digest_384),
                        key,
                        (union sev_ecdsa_sig *)&report->signature);
  if (rc != EXIT_SUCCESS) {
    errno = rc;
    perror("sev_ecdsa_verify");
    goto exit;
  }
  printf("Report verified successfully!\n");

exit:
  if (key) {
    EVP_PKEY_free(key);
    key = NULL;
  }
  return rc;
}
#endif

int get_report(const uint8_t *            data,
               size_t                     data_size,
               struct attestation_report *report) {
  int                            rc = EXIT_FAILURE;
  int                            fd = -1;
  struct snp_report_req          req;
  struct snp_report_resp         resp;
  struct snp_guest_request_ioctl guest_req;
  struct msg_report_resp *report_resp = (struct msg_report_resp *)&resp.data;

  if (!report) {
    rc = EINVAL;
    goto out;
  }

  if (data && (data_size > sizeof(req.user_data) || data_size == 0)) {
    rc = EINVAL;
    goto out;
  }

  /* Initialize data structures */
  memset(&req, 0, sizeof(req));
  if (data)
    memcpy(&req.user_data, data, data_size);

  memset(&resp, 0, sizeof(resp));

  memset(&guest_req, 0, sizeof(guest_req));
  guest_req.msg_version = 1;
  guest_req.req_data = (__u64)&req;
  guest_req.resp_data = (__u64)&resp;

  /* Open the sev-guest device */
  errno = 0;
  fd = open(SEV_GUEST_DEVICE, O_RDWR);
  if (fd == -1) {
    rc = errno;
    perror("open");
    goto out;
  }

  /* Issue the guest request IOCTL */
  errno = 0;
  rc = ioctl(fd, SNP_GET_REPORT, &guest_req);
  if (rc == -1) {
    rc = errno;
    perror("ioctl");
    fprintf(stderr, "firmware error %llu\n", guest_req.fw_err);
    goto out_close;
  }

  /* Check that the report was successfully generated */
  if (report_resp->status != 0) {
    fprintf(stderr, "firmware error %#x\n", report_resp->status);
    rc = report_resp->status;
    goto out_close;
  } else if (report_resp->report_size > sizeof(*report)) {
    fprintf(stderr,
            "report size is %u bytes (expected %lu)!\n",
            report_resp->report_size,
            sizeof(*report));
    rc = EFBIG;
    goto out_close;
  }

#ifdef SEV_DUMMY_GUEST
  rc = sign_report(&report_resp->report);
  if (rc != EXIT_SUCCESS) {
    fprintf(stderr, "Report signing failed!\n");
    goto out_close;
  }
#endif

  memcpy(report, &report_resp->report, report_resp->report_size);
  rc = EXIT_SUCCESS;

out_close:
  if (fd > 0) {
    close(fd);
    fd = -1;
  }
out:
  return rc;
}

int write_report(const char *file_name, struct attestation_report *report) {
  int   rc = EXIT_FAILURE;
  FILE *report_file = NULL;

  /* Open the output report file */
  errno = 0;
  report_file = fopen(file_name, "w+");
  if (!report_file) {
    rc = errno;
    perror("fopen");
    goto out;
  }

  /* Write the report to the output */
  int count = fwrite(report, sizeof(char), sizeof(*report), report_file);
  if (count != sizeof(*report)) {
    rc = EIO;
    fprintf(stderr, "fwrite failed.\n");
    goto out_close;
  }

  printf("wrote %s\n", file_name);
  rc = EXIT_SUCCESS;

out_close:
  if (report_file) {
    fclose(report_file);
    report_file = NULL;
  }
out:
  return rc;
}

int main(int argc, char *argv[]) {
  int                       rc = EXIT_FAILURE, i;
  struct attestation_report report;
  uint8_t                   hash[EVP_MAX_MD_SIZE] = {0};
  size_t                    hash_size = sizeof(hash);
  uint8_t *                 certs = NULL;
  struct key_options        opt = {0};
  uint8_t                   key[MSG_KEY_RSP_DERIVED_KEY_SIZE] = {0};

  memset(&report, 0, sizeof(report));
  memset(&certs, 0, sizeof(certs));

  rc = get_report(hash, hash_size, &report);
  if (rc != EXIT_SUCCESS) {
    errno = rc;
    perror("get_report");
    goto exit;
  }
  rc = verify_report(&report);
  if (rc != EXIT_SUCCESS) {
    errno = rc;
    perror("verify_report");
    goto exit;
  }

  print_report(&report);

  if (argc >= 2) {
    const char *report_filename = argv[1];
    printf("Writing report file to: %s\n", report_filename);
    rc = write_report(report_filename, &report);
    if (rc != EXIT_SUCCESS) {
      errno = rc;
      perror("write_report");
      goto exit;
    }
  }

  opt.do_root_key = true;
  opt.svn = 1;
  opt.fields = FIELD_POLICY_MASK | FIELD_IMAGE_ID_MASK | FIELD_FAMILY_ID_MASK
               | FIELD_MEASUREMENT_MASK | FIELD_GUEST_SVN_MASK
               | FIELD_TCB_VERSION_MASK;

  rc = request_key(&opt, key, sizeof(key));
  if (rc != EXIT_SUCCESS) {
    errno = rc;
    perror("request_key");
    goto exit;
  }
  printf("\nMaking firmware key derivision request...\n");
  printf("Derived key: ");
  for (i = 0; i < MSG_KEY_RSP_DERIVED_KEY_SIZE; i++) {
    printf("%.2X", key[i]);
  }
  printf("\n");

exit:
  exit(rc);
}
