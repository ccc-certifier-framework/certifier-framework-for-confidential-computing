// Portions of this are  from AMD's SEV support code.  Those portions are:
//  Copyright (C) 2021 Advanced Micro Devices, Inc.
//  Licensed under Apache 2.0
// The remainder are:

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


#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <sys/ioctl.h>

#include <secg_sec1.h>
#include <sev_support.h>
#include <sev_report.h>
#include <attestation.h>
#include <sev_guest.h>
#include <snp_derive_key.h>
#include <sev_cert_table.h>

#include "certifier.h"
#include "support.h"

using namespace certifier::framework;
using namespace certifier::utilities;

#define SEV_GUEST_DEVICE      "/dev/sev-guest"
#define SEV_IOCTL_MAX_RETRY   10
#define SEV_IOCTL_RETRY_SLEEP 1

#ifdef SEV_DUMMY_GUEST
#  define SEV_ECDSA_PRIV_KEY "/etc/certifier-snp-sim/ec-secp384r1-priv-key.pem"
#  define SEV_ECDSA_PUB_KEY  "/etc/certifier-snp-sim/ec-secp384r1-pub-key.pem"
#endif

using namespace certifier::framework;
using namespace certifier::utilities;

static void reverse_bytes(uint8_t *buffer, size_t size) {
  if (!buffer || size == 0)
    return;
  for (uint8_t *start = buffer, *end = buffer + size - 1; start < end;
       start++, end--) {
    uint8_t temp = *start;
    *start = *end;
    *end = temp;
  }
}

#define ioctl_with_retry(fd, request, ret, ...)                                \
  do {                                                                         \
    __label__ retry;                                                           \
    int tries = 0;                                                             \
retry:                                                                         \
    rc = ioctl(fd, request, __VA_ARGS__);                                      \
    if (rc == -1) {                                                            \
      if (guest_req.fw_err == SEV_HV_STATUS_GUEST_MSG_RATE_LIMITED             \
          && tries < SEV_IOCTL_MAX_RETRY) {                                    \
        sleep(SEV_IOCTL_RETRY_SLEEP);                                          \
        tries++;                                                               \
        goto retry;                                                            \
      }                                                                        \
    }                                                                          \
    *(ret) = rc;                                                               \
  } while (0);

// Extract r and s from an ecdsa signature.
// Based on get_ecdsa_sig_rs_bytes() in test/acvp_test.c from OpenSSL.
static int get_ecdsa_sig_rs_bytes(const unsigned char *sig,
                                  size_t               sig_len,
                                  unsigned char *      r,
                                  unsigned char *      s,
                                  size_t *             rlen,
                                  size_t *             slen) {
  int            rc = -EXIT_FAILURE;
  unsigned char *rbuf = NULL, *sbuf = NULL;
  size_t         r1_len, s1_len;
  const BIGNUM * r1, *s1;
  ECDSA_SIG *    sign = d2i_ECDSA_SIG(NULL, &sig, sig_len);

  if (sign == NULL || !r || !s || !rlen || !slen) {
    rc = EINVAL;
    goto out;
  }

  r1 = ECDSA_SIG_get0_r(sign);
  s1 = ECDSA_SIG_get0_s(sign);
  if (r1 == NULL || s1 == NULL) {
    rc = EINVAL;
    goto err_sign;
  }

  r1_len = BN_num_bytes(r1);
  s1_len = BN_num_bytes(s1);
  if (r1_len > *rlen || s1_len > *slen) {
    rc = ENOBUFS;
    goto err_sign;
  }

  rbuf = (byte *)OPENSSL_zalloc(r1_len);
  sbuf = (byte *)OPENSSL_zalloc(s1_len);
  if (rbuf == NULL || sbuf == NULL) {
    rc = ENOMEM;
    goto err_buf;
  }
  if (BN_bn2binpad(r1, rbuf, r1_len) <= 0) {
    rc = EINVAL;
    goto err_buf;
  }
  if (BN_bn2binpad(s1, sbuf, s1_len) <= 0) {
    rc = EINVAL;
    goto err_buf;
  }

  memcpy(r, rbuf, r1_len);
  memcpy(s, sbuf, s1_len);
  *rlen = r1_len;
  *slen = s1_len;

  rc = EXIT_SUCCESS;

err_buf:
  if (rbuf) {
    OPENSSL_free(rbuf);
    rbuf = NULL;
  }
  if (sbuf) {
    OPENSSL_free(sbuf);
    sbuf = NULL;
  }

err_sign:
  if (sign) {
    ECDSA_SIG_free(sign);
    sign = NULL;
  }
out:
  return rc;
}

int sev_ecdsa_sign(const void *         msg,
                   size_t               msg_size,
                   EVP_PKEY *           key,
                   union sev_ecdsa_sig *sig) {
  int           rc = -EXIT_FAILURE;
  EVP_MD_CTX *  md_ctx = NULL;
  EVP_PKEY_CTX *sign_ctx = NULL;
  uint8_t *     ossl_sig = NULL;
  size_t        expected_size = 0, sig_size = 0;
  size_t        r_size = sizeof(sig->r);
  size_t        s_size = sizeof(sig->s);

  if (!msg || msg_size == 0 || !key || !sig) {
    rc = EINVAL;
    goto out;
  }

  md_ctx = EVP_MD_CTX_new();
  if (!md_ctx) {
    ERR_print_errors_fp(stderr);
    rc = ENOMEM;
    goto out;
  }

  if (!EVP_DigestSignInit(md_ctx, &sign_ctx, EVP_sha384(), NULL, key)) {
    ERR_print_errors_fp(stderr);
    rc = -EXIT_FAILURE;
    goto out_md_ctx;
  }

  if (!EVP_DigestSign(md_ctx, NULL, &expected_size, (byte *)msg, msg_size)) {
    ERR_print_errors_fp(stderr);
    rc = -EXIT_FAILURE;
    goto out_md_ctx;
  }

  ossl_sig = (uint8_t *)OPENSSL_zalloc(expected_size);
  if (!sig) {
    rc = ENOMEM;
    goto out_md_ctx;
  }

  sig_size = expected_size;

  if (!EVP_DigestSign(md_ctx, ossl_sig, &sig_size, (byte *)msg, msg_size)) {
    ERR_print_errors_fp(stderr);
    fprintf(stderr, "sig_size = %lu (was %lu)\n", sig_size, expected_size);
    fprintf(stderr, "DRBG status: %s\n", RAND_status() ? "good" : "bad");
    rc = -EXIT_FAILURE;
    goto out_sig;
  }

  if (sig_size > expected_size) {
    fprintf(stderr,
            "%s: signature requires %lu bytes! (%lu allocated)\n",
            __func__,
            sig_size,
            expected_size);
    rc = ENOBUFS;
    goto out_sig;
  }

  /* Store the R & S components of the ID block signature */
  rc = get_ecdsa_sig_rs_bytes(ossl_sig,
                              sig_size,
                              sig->r,
                              sig->s,
                              &r_size,
                              &s_size);
  if (rc != EXIT_SUCCESS)
    goto out_sig;

  reverse_bytes(sig->r, r_size);
  reverse_bytes(sig->s, s_size);

  rc = EXIT_SUCCESS;

out_sig:
  if (ossl_sig) {
    OPENSSL_free(ossl_sig);
    ossl_sig = NULL;
  }

out_md_ctx:
  if (md_ctx) {
    EVP_MD_CTX_free(md_ctx);
    md_ctx = NULL;
  }
out:
  return rc;
}

int sev_ecdsa_verify(const void *         digest,
                     size_t               digest_size,
                     EVP_PKEY *           key,
                     union sev_ecdsa_sig *sig) {
  int        rc = -EXIT_FAILURE;
  bool       is_valid = false;
  EC_KEY *   pub_ec_key = NULL;
  BIGNUM *   r = NULL;
  BIGNUM *   s = NULL;
  ECDSA_SIG *ecdsa_sig = NULL;

  do {
    pub_ec_key = EVP_PKEY_get1_EC_KEY(key);
    if (!pub_ec_key) {
      printf("Failed to get EC public key!\n");
      break;
    }

    // Store the x and y components as separate BIGNUM objects. The values in
    // the SEV certificate are little-endian, must reverse bytes before storing
    // in BIGNUM
    r = BN_lebin2bn(sig->r, sizeof(sig->r), NULL);  // New's up BigNum
    s = BN_lebin2bn(sig->s, sizeof(sig->s), NULL);

    // Create a ecdsa_sig from the bignums and store in sig
    ecdsa_sig = ECDSA_SIG_new();
    ECDSA_SIG_set0(ecdsa_sig, r, s);

    // Validation will also be done by the FW
    if (ECDSA_do_verify((byte *)digest,
                        (uint32_t)digest_size,
                        ecdsa_sig,
                        pub_ec_key)
        != 1) {
      printf("ECDSA_do_verify failed\n");
      ECDSA_SIG_free(ecdsa_sig);
      break;
    }
    ECDSA_SIG_free(ecdsa_sig);

    is_valid = true;
  } while (0);

  if (is_valid) {
    rc = EXIT_SUCCESS;
  }

  // Free memory
  EC_KEY_free(pub_ec_key);

  return rc;
}

struct sev_key_options {
  union tcb_version tcb;
  const char *      key_filename;
  uint64_t          fields;
  uint32_t          svn;
  bool              do_help;
  bool              do_root_key;
};

int sev_request_key(struct sev_key_options *options,
                    uint8_t *               key,
                    size_t                  size) {
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

  errno = 0;
  fd = open(SEV_GUEST_DEVICE, O_RDWR);
  if (fd == -1) {
    rc = errno;
    char error[64];
    snprintf(error,
             sizeof(error),
             "[%d] open %s, errno=%d",
             __LINE__,
             SEV_GUEST_DEVICE,
             rc);
    perror(error);
    goto out;
  }

  errno = 0;
  ioctl_with_retry(fd, SNP_GET_DERIVED_KEY, &rc, &guest_req);
  if (rc == -1) {
    rc = errno;
    perror("ioctl");
    fprintf(stderr,
            "[%s:%d] ioctl key=%lu, firmware error %llu\n",
            __func__,
            __LINE__,
            SNP_GET_DERIVED_KEY,
            guest_req.fw_err);
    goto out_close;
  }

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
  printf("opening %s\n", filename);
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

int sev_sign_report(struct attestation_report *report) {
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

EVP_PKEY *get_simulated_vcek_key() {
  EVP_PKEY *key = NULL;
  int       rc = read_key_file(SEV_ECDSA_PUB_KEY, &key, false);
  if (rc != EXIT_SUCCESS)
    return nullptr;
  return key;
}
#endif  // SEV_DUMMY_GUEST

bool sev_verify_report(EVP_PKEY *key, struct attestation_report *report) {
  unsigned int size_digest = 48;
  byte         digest[size_digest];

  if (!digest_message(
          Digest_method_sha_384,
          (const byte *)report,
          sizeof(struct attestation_report) - sizeof(struct signature),
          digest,
          size_digest)) {
    printf("sev_verify_report: digest_message failed\n");
    return false;
  }

  int rc = sev_ecdsa_verify(digest,
                            48,
                            key,
                            (union sev_ecdsa_sig *)&report->signature);
  if (rc != EXIT_SUCCESS) {
    printf("sev_verify_report: sev_ecdsa_verify failed\n");
    return false;
  }
  return true;
}

int sev_get_report(const uint8_t *            data,
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

  memset(&req, 0, sizeof(req));
  if (data)
    memcpy(&req.user_data, data, data_size);

  memset(&resp, 0, sizeof(resp));
  memset(&guest_req, 0, sizeof(guest_req));
  guest_req.msg_version = 1;
  guest_req.req_data = (__u64)&req;
  guest_req.resp_data = (__u64)&resp;

  errno = 0;
  fd = open(SEV_GUEST_DEVICE, O_RDWR);
  if (fd == -1) {
    rc = errno;
    char error[64];
    snprintf(error,
             sizeof(error),
             "[%d] open %s, errno=%d",
             __LINE__,
             SEV_GUEST_DEVICE,
             rc);
    perror(error);
    goto out;
  }

  errno = 0;
  ioctl_with_retry(fd, SNP_GET_REPORT, &rc, &guest_req);
  if (rc == -1) {
    rc = errno;
    perror("ioctl");
    fprintf(stderr, "firmware error %llu\n", guest_req.fw_err);
    goto out_close;
  }

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
  rc = sev_sign_report(&report_resp->report);
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

int sev_get_extended_report(const uint8_t *            data,
                            size_t                     data_size,
                            struct attestation_report *report,
                            uint8_t **                 certs,
                            size_t *                   certs_size) {
  int                            rc = EXIT_FAILURE;
  int                            fd = -1;
  struct snp_ext_report_req      req;
  struct snp_report_resp         resp;
  struct snp_guest_request_ioctl guest_req;
  struct msg_report_resp *report_resp = (struct msg_report_resp *)&resp.data;
  struct cert_table       certs_data;
  size_t                  page_size = 0, nr_pages = 0;

  if (!report || !certs || !certs_size) {
    rc = EINVAL;
    goto out;
  }

  if (data && (data_size > sizeof(req.data.user_data) || data_size == 0)) {
    rc = EINVAL;
    goto out;
  }

  /* Initialize data structures */
  memset(&req, 0, sizeof(req));
#if 1
  req.certs_address = (__u64)-1; /* Invalid, non-zero address */
#endif
  if (data)
    memcpy(&req.data.user_data, data, data_size);

  memset(&resp, 0, sizeof(resp));

  memset(&guest_req, 0, sizeof(guest_req));
  guest_req.msg_version = 1;
  guest_req.req_data = (__u64)&req;
  guest_req.resp_data = (__u64)&resp;

  memset(&certs_data, 0, sizeof(certs_data));

  /* Open the sev-guest device */
  errno = 0;
  fd = open(SEV_GUEST_DEVICE, O_RDWR);
  if (fd == -1) {
    rc = errno;
    perror("open");
    goto out;
  }

  /* Query the size of the stored certificates */
  errno = 0;
  ioctl_with_retry(fd, SNP_GET_EXT_REPORT, &rc, &guest_req);
  if (rc == -1 && guest_req.fw_err != 0x100000000) {
    rc = errno;
    perror("ioctl");
    fprintf(stderr, "firmware error %#llx\n", guest_req.fw_err);
    fprintf(stderr, "report error %#x\n", report_resp->status);
    fprintf(stderr, "certs_len %#x\n", req.certs_len);
    goto out_close;
  }

  if (req.certs_len == 0) {
    fprintf(stderr, "The cert chain storage is empty.\n");
    rc = ENODATA;
    goto out_close;
  }

  /* The certificate storage is always page-aligned */
  page_size = sysconf(_SC_PAGESIZE);
  nr_pages = req.certs_len / page_size;
  if (req.certs_len % page_size != 0)
    nr_pages++; /* Just to be safe */

  certs_data.entry = (struct cert_table_entry *)calloc(page_size, nr_pages);
  if (!certs_data.entry) {
    rc = ENOMEM;
    errno = rc;
    perror("calloc");
    goto out_close;
  }

  /* Retrieve the cert chain */
  req.certs_address = (__u64)certs_data.entry;
  errno = 0;
  ioctl_with_retry(fd, SNP_GET_EXT_REPORT, &rc, &guest_req);
  if (rc == -1) {
    rc = errno;
    perror("ioctl");
    fprintf(stderr, "errno is %u\n", errno);
    fprintf(stderr, "firmware error %#llx\n", guest_req.fw_err);
    fprintf(stderr, "report error %x\n", report_resp->status);
    goto out_free;
  }

  /* Check that the report was successfully generated */
  if (report_resp->status != 0) {
    fprintf(stderr, "firmware error %x\n", report_resp->status);
    rc = report_resp->status;
    goto out_free;
  } else if (report_resp->report_size > sizeof(*report)) {
    fprintf(stderr,
            "report size is %u bytes (expected %lu)!\n",
            report_resp->report_size,
            sizeof(*report));
    rc = EFBIG;
    goto out_free;
  }

#ifdef SEV_DUMMY_GUEST
  rc = sev_sign_report(&report_resp->report);
  if (rc != EXIT_SUCCESS) {
    fprintf(stderr, "Report signing failed!\n");
    goto out_free;
  }
#endif

  memcpy(report, &report_resp->report, report_resp->report_size);
  *certs = (uint8_t *)certs_data.entry;
  *certs_size = req.certs_len;
  rc = EXIT_SUCCESS;

out_free:
  if (rc != EXIT_SUCCESS && certs_data.entry) {
    free(certs_data.entry);
    certs_data.entry = NULL;
  }

out_close:
  if (fd > 0) {
    close(fd);
    fd = -1;
  }
out:
  return rc;
}

static int sev_export_cert(const struct cert_table_entry *entry,
                           const uint8_t *                buffer,
                           size_t                         size,
                           string *                       cstr) {
  int   rc = EXIT_FAILURE, len;
  X509 *cert = NULL;
  BIO * cbio =
      BIO_new_mem_buf((void *)(buffer + entry->offset), (int)entry->length);
  unsigned char *buf = NULL;
  cert = PEM_read_bio_X509(cbio, NULL, 0, NULL);
  if (!cert) {
    // We don't assume platform provides PEM
    const unsigned char *in = buffer + entry->offset;
    cert = d2i_X509(NULL, &in, entry->length);
    if (!cert) {
      rc = EXIT_FAILURE;
      errno = rc;
      perror("d2i_X509_bio");
      goto err;
    }
  }

  // Convert cert to DER
  len = i2d_X509(cert, &buf);
  if (len < 0) {
    rc = EXIT_FAILURE;
    errno = rc;
    perror("i2d_X509");
    goto err;
  }

  cstr->assign((char *)buf, len);
  rc = EXIT_SUCCESS;

err:
  if (buf) {
    OPENSSL_free(buf);
  }
  BIO_free(cbio);
  return rc;
}

static int sev_parse_certs(const uint8_t *certs,
                           size_t         size,
                           string *       vcek,
                           string *       ask,
                           string *       ark) {
  int                     rc = EXIT_FAILURE;
  const struct cert_table table = {
      .entry = (struct cert_table_entry *)certs,
  };
  size_t table_size = 0, certs_size = 0, total_size = 0;

  if (!certs || size == 0) {
    rc = EINVAL;
    goto out;
  }

  /* Determine the size of the certificate chain including the cert table */
  table_size = cert_table_get_size(&table);
  if (table_size == 0) {
    rc = ENODATA;
    errno = rc;
    perror("cert_table_get_size");
    goto out;
  }

  rc = cert_table_get_certs_size(&table, &certs_size);
  if (rc != EXIT_SUCCESS) {
    errno = rc;
    perror("cert_table_get_certs");
    goto out;
  }

  total_size = certs_size + table_size;
  if (total_size < table_size || total_size < certs_size) {
    rc = EOVERFLOW;
    goto out;
  }

  if (total_size > size) {
    rc = ENOBUFS;
    goto out;
  }

  for (size_t i = 0; table.entry[i].length > 0; i++) {
    struct cert_table_entry *entry = table.entry + i;
    char                     uuid_str[UUID_STR_LEN] = {0};

    /* Get the GUID as a character string */
    uuid_unparse(entry->guid, uuid_str);

    rc = ENODATA;
    if (memcmp(uuid_str, vcek_guid, sizeof(uuid_str)) == 0) {
      rc = sev_export_cert(entry, certs, size, vcek);
    } else if (memcmp(uuid_str, ask_guid, sizeof(uuid_str)) == 0) {
      rc = sev_export_cert(entry, certs, size, ask);
    } else if (memcmp(uuid_str, ark_guid, sizeof(uuid_str)) == 0) {
      rc = sev_export_cert(entry, certs, size, ark);
    }
    if (rc != EXIT_SUCCESS) {
      printf("Failed to parse entry %ld\n", i);
    }
  }

  rc = EXIT_SUCCESS;
out:
  return rc;
}

int sev_get_platform_certs(string *vcek, string *ask, string *ark) {
  int                       rc = EXIT_FAILURE;
  struct attestation_report report;
  uint8_t                   hash[EVP_MAX_MD_SIZE] = {0};
  size_t                    hash_size = sizeof(hash), certs_size = 0;
  uint8_t *                 certs = NULL;

  rc = sev_get_extended_report(hash, hash_size, &report, &certs, &certs_size);
  if (rc != EXIT_SUCCESS) {
    errno = rc;
    perror("get_extended_report");
    goto exit;
  }

  rc = sev_parse_certs(certs, certs_size, vcek, ask, ark);

exit:
  return rc;
}


// DK = T1 + T2 + ⋯ + Tdklen/hlen
//  PRF(Password, Salt + INT_32_BE(i))
// Ti = F(Password, Salt, c, i)
// F(Password, Salt, c, i) = U1 ^ U2 ^ ⋯ ^ Uc
//    where:
//      U1 = PRF(Password, Salt + INT_32_BE(i))
//      U2 = PRF(Password, U1)
//      ...
//      Uc = PRF(Password, Uc−1)
void xor_in(int size, byte *result, byte *in) {
  for (int i = 0; i < size; i++)
    result[i] ^= in[i];
}

const int hmac_size = 32;
bool      kdf(int key_len, byte *key, int iter, int out_size, byte *out) {

  memset(out, 0, out_size);
  byte salt[hmac_size] = {0x07, 0x01, 0x08, 0x02, 0x08, 0x33, 0x11, 0x44,
                          0x07, 0x01, 0x08, 0x02, 0x08, 0x33, 0x11, 0x44,
                          0x07, 0x01, 0x08, 0x02, 0x08, 0x33, 0x11, 0x44,
                          0x07, 0x01, 0x08, 0x02, 0x08, 0x33, 0x11, 0x44};
  byte t_in[hmac_size];
  byte u[hmac_size];
  byte t[hmac_size];
  unsigned int size;

  int num_blks = (out_size + hmac_size - 1) / hmac_size;
  memcpy(t_in, salt, hmac_size - sizeof(int));

  for (int j = 1; j <= num_blks; j++) {
    memset(t, 0, hmac_size);
    memcpy(&t_in[hmac_size - sizeof(int)], (byte *)&j, sizeof(int));
    memset(u, 0, hmac_size);
    size = hmac_size;
    HMAC(EVP_sha256(), key, key_len, t_in, hmac_size, u, &size);
    xor_in(hmac_size, t, u);
    for (int i = 1; i < iter; i++) {
      size = hmac_size;
      HMAC(EVP_sha256(), key, key_len, u, hmac_size, u, &size);
      xor_in(hmac_size, t, u);
    }
    if (j == num_blks) {
      memcpy(&out[hmac_size * (j - 1)],
             t,
             out_size - (num_blks - 1) * hmac_size);
    } else {
      memcpy(&out[hmac_size * (j - 1)], t, hmac_size);
    }
  }

  return true;
}

/*
 * Derive sealing keys by issuing guest requests. By default, the Certifier ties
 * sealing keys to the platform and the application identity. As a result, the
 * default sealing key is derived from VCEK and the policy includes:
 *   - FIELD_MEASUREMENT_MASK: Application identity
 *   - FIELD_POLICY_MASK: DEBUG, MIGRATE_MA, etc.
 *
 * Specify root_key and fields explicitly otherwise. Fields that can be mixed
 * into the key:
 *
 *   FIELD_POLICY_MASK    | FIELD_IMAGE_ID_MASK
 *   FIELD_FAMILY_ID_MASK | FIELD_MEASUREMENT_MASK
 *   FIELD_GUEST_SVN_MASK | FIELD_TCB_VERSION_MASK
 */
bool sev_get_final_keys(int      final_key_size,
                        byte *   final_key,
                        bool     root_key = false,
                        uint64_t fields = FIELD_MEASUREMENT_MASK
                                          | FIELD_POLICY_MASK) {
  struct sev_key_options opt = {0};
  byte                   key[MSG_KEY_RSP_DERIVED_KEY_SIZE] = {0};
  int                    size = MSG_KEY_RSP_DERIVED_KEY_SIZE;
  opt.do_root_key = root_key;
  opt.fields = fields;

  if (EXIT_SUCCESS != sev_request_key(&opt, key, size))
    return false;

  if (!kdf(size, key, 100, final_key_size, final_key))
    return false;
  return true;
}

bool sev_Seal(int in_size, byte *in, int *size_out, byte *out) {

  int  final_key_size = 64;
  byte final_key[final_key_size];
  if (!sev_get_final_keys(final_key_size, final_key)) {
    return false;
  }
#if 0
  printf("Seal final keys: ");print_bytes(final_key_size, final_key);
#endif

  byte iv[32];
  if (!get_random(256, iv))
    return false;

  // Encrypt and integrity protect
  if (!authenticated_encrypt(Enc_method_aes_256_cbc_hmac_sha256,
                             in,
                             in_size,
                             final_key,
                             final_key_size,
                             iv,
                             32,
                             out,
                             size_out))
    return false;
  return true;
}

bool sev_Unseal(int in_size, byte *in, int *size_out, byte *out) {
  int  final_key_size = 64;
  byte final_key[final_key_size];
  if (!sev_get_final_keys(final_key_size, final_key)) {
    return false;
  }
#if 0
  printf("Unseal final keys: ");print_bytes(final_key_size, final_key);
#endif

  // decrypt and integity check
  if (!authenticated_decrypt(Enc_method_aes_256_cbc_hmac_sha256,
                             in,
                             in_size,
                             final_key,
                             final_key_size,
                             out,
                             size_out))
    return false;
  return true;
}

bool sev_Attest(int   what_to_say_size,
                byte *what_to_say,
                int * size_out,
                byte *out) {
  struct attestation_report report;

  // hash what to say
  int  hash_len = 48;
  byte hash[hash_len];

  sev_attestation_message the_attestation;
  the_attestation.set_what_was_said(what_to_say, what_to_say_size);

  if (!digest_message(Digest_method_sha_384,
                      what_to_say,
                      what_to_say_size,
                      hash,
                      hash_len)) {
    printf("digest_message failed\n");
    return false;
  }

  int rc = sev_get_report(hash, hash_len, &report);
  if (rc != EXIT_SUCCESS) {
    printf("sev_get_report failed\n");
    return false;
  }
  the_attestation.set_reported_attestation((byte *)(&report), sizeof(report));
  string serialized_sev_attestation;
  if (!the_attestation.SerializeToString(&serialized_sev_attestation)) {
    printf("serialized_sev_attestation serialize failed\n");
    return false;
  }
  if (out == nullptr) {
    *size_out = serialized_sev_attestation.size();
    return true;
  }
  if (*size_out < (int)serialized_sev_attestation.size()) {
    printf("output buffer too small\n");
    return false;
  }
  *size_out = serialized_sev_attestation.size();
  memcpy(out, (byte *)serialized_sev_attestation.data(), *size_out);
  return true;
}

bool verify_sev_Attest(EVP_PKEY *key,
                       int       size_sev_attestation,
                       byte *    the_attestation,
                       int *     size_measurement,
                       byte *    measurement) {

  string at_str;
  at_str.assign((char *)the_attestation, size_sev_attestation);
  sev_attestation_message sev_att;
  if (!sev_att.ParseFromString(at_str)) {
    printf("verify_sev_Attest: can't parse attestation\n");
    return false;
  }

  // hash what was said
  unsigned int digest_size = 64;
  byte         digest[digest_size];
  memset(digest, 0, digest_size);
  if (!digest_message(Digest_method_sha_384,
                      (byte *)sev_att.what_was_said().data(),
                      sev_att.what_was_said().size(),
                      digest,
                      digest_size)) {
    printf("verify_sev_Attest: digest_message fails\n");
    return false;
  }

  struct attestation_report *report =
      (struct attestation_report *)sev_att.reported_attestation().data();
  if (report->signature_algo != SIG_ALGO_ECDSA_P384_SHA384) {
    printf("verify_sev_Attest: Not SIG_ALGO_ECDSA_P384_SHA384 %08x %08x\n",
           report->signature_algo,
           SIG_ALGO_ECDSA_P384_SHA384);
    return false;
  }

  if (memcmp(report->report_data, digest, 48) != 0) {
    return false;
  }

  if (*size_measurement < 48) {
    printf("verify_sev_Attest: measurement too small\n");
    return false;
  }
  if (memcmp(report->report_data, digest, 48) != 0) {
    printf("verify_sev_Attest: memcpy failed\n");
    return false;
  }

  // doesn't verify
  if (!sev_verify_report(key, report)) {
    printf("verify_sev_Attest: sev_verify_report failed\n");
    return false;
  }

  *size_measurement = 48;
  memcpy(measurement, report->measurement, *size_measurement);
  return true;
}

//  Platform certs
bool   plat_certs_initialized = false;
string serialized_ark_cert;
string serialized_ask_cert;
string serialized_vcek_cert;

bool sev_Init(const string &ark_der,
              const string &ask_der,
              const string &vcek_der) {

  serialized_ark_cert = ark_der;
  serialized_ask_cert = ask_der;
  serialized_vcek_cert = vcek_der;

  certifier_parent_enclave_type = "hardware";
  certifier_parent_enclave_type_intitalized = true;
  plat_certs_initialized = true;
  return true;
}

bool sev_GetParentEvidence(string *out) {
  if (!plat_certs_initialized) {
    printf("sev_GetParentEvidence: platform cert not initialized\n");
    return false;
  }
  // Todo: fix this
  return false;
  // return true;
}

// ------------------------------------------------------------------

// Not needed

// Todo: suggest renaming this to sev_verify_report
int verify_report(struct attestation_report *report) {
  int           rc = -EXIT_FAILURE;
  EVP_PKEY *    key = NULL;
  unsigned char sha_digest_384[SHA384_DIGEST_LENGTH];

#ifdef SEV_DUMMY_GUEST
  rc = read_key_file(SEV_ECDSA_PUB_KEY, &key, false);
  if (rc != EXIT_SUCCESS) {
    errno = rc;
    perror("read_key_file");
    goto exit;
  }
#else
  X509 *x509_vcek = NULL;
  X509 *x509_ask = NULL;
  X509 *x509_ark = NULL;

#  define SEV_ARK_CERT  "Ark.cer"
#  define SEV_ASK_CERT  "Ask.cer"
#  define SEV_VCEK_CERT "Vcek.cer"

  if (!sev_read_pem_into_x509(SEV_ARK_CERT, &x509_ark)) {
    rc = EXIT_FAILURE;
    perror("Failed to load ARK Cert!");
    goto exit;
  }

  if (!sev_read_pem_into_x509(SEV_ASK_CERT, &x509_ask)) {
    rc = EXIT_FAILURE;
    perror("Failed to load ASK Cert!");
    goto exit;
  }

  if (!sev_read_pem_into_x509(SEV_VCEK_CERT, &x509_ask)) {
    rc = EXIT_FAILURE;
    perror("Failed to load VCEK Cert!");
    goto exit;
  }

  rc = sev_validate_vcek_cert_chain(x509_vcek, x509_ask, x509_ark);
  if (rc != EXIT_SUCCESS) {
    errno = rc;
    perror("sev_validate_vcek_cert_chain");
    goto exit;
  }
  printf("Certificate chain validated!\n");

  key = sev_get_vcek_pubkey(x509_vcek);
  if (!key) {
    errno = EXIT_FAILURE;
    perror("sev_get_vcek_pubkey");
    goto exit;
  }
#endif

  if (!digest_message(
          Digest_method_sha_384,
          (byte *)report,
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

exit:
  if (key) {
    EVP_PKEY_free(key);
    key = NULL;
  }
  return rc;
}

int sev_read_pem_into_x509(const char *file_name, X509 **x509_cert) {
  FILE *pFile = NULL;
  pFile = fopen(file_name, "re");
  if (!pFile)
    return EXIT_FAILURE;

  // printf("Reading from file: %s\n", file_name.c_str());
  *x509_cert = PEM_read_X509(pFile, NULL, NULL, NULL);
  if (!*x509_cert) {
    printf("Error reading x509 from file: %s\n", file_name);
    fclose(pFile);
    return EXIT_FAILURE;
  }
  fclose(pFile);
  return EXIT_SUCCESS;
}

static bool x509_validate_signature(X509 *child_cert,
                                    X509 *intermediate_cert,
                                    X509 *parent_cert) {
  bool            ret = false;
  X509_STORE *    store = NULL;
  X509_STORE_CTX *store_ctx = NULL;

  do {
    // Create the store
    store = X509_STORE_new();
    if (!store)
      break;

    // Add the parent cert to the store
    if (X509_STORE_add_cert(store, parent_cert) != 1) {
      printf("Error adding parent_cert to x509_store\n");
      break;
    }

    // Add the intermediate cert to the store
    if (intermediate_cert) {
      if (X509_STORE_add_cert(store, intermediate_cert) != 1) {
        printf("Error adding intermediate_cert to x509_store\n");
        break;
      }
    }

    // Create the store context
    store_ctx = X509_STORE_CTX_new();
    if (!store_ctx) {
      printf("Error creating x509_store_context\n");
      break;
    }

    // Pass the store (parent and intermediate cert) and child cert (that we
    // want to verify) into the store context
    if (X509_STORE_CTX_init(store_ctx, store, child_cert, NULL) != 1) {
      printf("Error initializing 509_store_context\n");
      break;
    }

    // Specify which cert to validate
    X509_STORE_CTX_set_cert(store_ctx, child_cert);

    // Verify the certificate
    ret = X509_verify_cert(store_ctx);

    // Print out error code
    if (ret == 0)
      printf(
          "Error verifying cert: %s\n",
          X509_verify_cert_error_string(X509_STORE_CTX_get_error(store_ctx)));

    if (ret != 1)
      break;

    ret = true;
  } while (0);

  // Cleanup
  if (store_ctx)
    X509_STORE_CTX_free(store_ctx);
  if (store)
    X509_STORE_free(store);

  return ret;
}

int sev_validate_vcek_cert_chain(X509 *x509_vcek,
                                 X509 *x509_ask,
                                 X509 *x509_ark) {
  EVP_PKEY *vcek_pub_key = NULL;
  int       ret = EXIT_FAILURE;

  if (!x509_vcek || !x509_ask || !x509_ark) {
    printf("Invalid certificate\n");
    return EXIT_FAILURE;
  }

  vcek_pub_key = X509_get_pubkey(x509_vcek);
  if (!vcek_pub_key) {
    goto err;
  }

  if (!x509_validate_signature(x509_ark, NULL, x509_ark)) {
    printf("Error validating signature of ARK Cert\n");
    goto err;
    ;
  }

  if (!x509_validate_signature(x509_ask, NULL, x509_ark)) {
    printf("Error validating signature of ASK Cert\n");
    goto err;
    ;
  }

  if (!x509_validate_signature(x509_vcek, x509_ask, x509_ark)) {
    printf("Error validating signature of VCEK Cert\n");
    goto err;
    ;
  }

  ret = EXIT_SUCCESS;

err:
  if (vcek_pub_key) {
    EVP_PKEY_free(vcek_pub_key);
  }
  return ret;
}

EVP_PKEY *sev_get_vcek_pubkey(X509 *x509_vcek) {
  EVP_PKEY *vcek_pub_key = NULL;

  if (!x509_vcek) {
    printf("Invalid certificate\n");
    return NULL;
  }

  vcek_pub_key = X509_get_pubkey(x509_vcek);
  if (!vcek_pub_key) {
    printf("Failed to get VCEK public key from certificate\n");
    return NULL;
  }

  return vcek_pub_key;
}

// ------------------------------------------------------------------


// Todo: suggest renaming this to sev_write_report
int write_report(const char *file_name, struct attestation_report *report) {
  int   rc = EXIT_FAILURE;
  FILE *report_file = NULL;
  int   count;

  errno = 0;
  report_file = fopen(file_name, "w+");
  if (!report_file) {
    rc = errno;
    perror("fopen");
    goto out;
  }

  count = fwrite(report, sizeof(char), sizeof(*report), report_file);
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
