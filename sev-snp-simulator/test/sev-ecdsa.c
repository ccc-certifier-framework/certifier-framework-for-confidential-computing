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

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ecdsa.h>
#include <sev-ecdsa.h>
#include <secg-sec1.h>


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

/*
 * Extract r and s from an ecdsa signature.
 *
 * Based on get_ecdsa_sig_rs_bytes() in test/acvp_test.c from OpenSSL.
 */
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

  rbuf = OPENSSL_zalloc(r1_len);
  sbuf = OPENSSL_zalloc(s1_len);
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

  /* Get the expected size of the signature */
  if (!EVP_DigestSign(md_ctx, NULL, &expected_size, msg, msg_size)) {
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

  if (!EVP_DigestSign(md_ctx, ossl_sig, &sig_size, msg, msg_size)) {
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
    if (ECDSA_do_verify(digest, (uint32_t)digest_size, ecdsa_sig, pub_ec_key)
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
