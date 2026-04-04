#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

extern "C" {

bool tpm_host_verify_attest(int      serialized_cert_size,
                            uint8_t *serialized_cert,
                            int      serialized_attest_size,
                            uint8_t *serialized_attest,
                            int     *measurement_size,
                            uint8_t *measurement_out,
                            int     *pcr_size,
                            uint8_t *pcr_out);
}

extern "C" {

bool certifier_make_a_credential(const char *quote_hash_alg,
                                 int         quote_key_name_size,
                                 uint8_t    *quote_key_name_buf,
                                 int         endoresment_cert_size,
                                 uint8_t    *endoresment_cert_buf,
                                 int         credential_size,
                                 uint8_t    *credential_buf,
                                 int        *cred_blob_size,
                                 uint8_t    *cred_blob_buf,
                                 int        *encrypted_secret_size,
                                 uint8_t    *encrypted_secret_buf);
}
