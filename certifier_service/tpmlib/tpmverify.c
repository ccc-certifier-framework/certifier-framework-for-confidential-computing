#include "certifier.pb.h"
#include "tpm2.pb.h"
#include "certifier_framework.h"
#include "tpm2_support.h"
#include "tpmverify.h"


static bool tpm_verifier_initialized = false;

bool tpm_host_verify_attest(int      serialized_cert_size,
                            uint8_t *serialized_cert,
                            int      serialized_attest_size,
                            uint8_t *serialized_attest,
                            int     *measurement_size,
                            uint8_t *measurement_out,
                            int     *pcr_size,
                            uint8_t *pcr_out) {

  return tpm_verify_attest_with_measurement(serialized_cert_size,
                                            serialized_cert,
                                            serialized_attest_size,
                                            serialized_attest,
                                            measurement_size,
                                            measurement_out,
                                            pcr_size,
                                            pcr_out);
}

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
                                 uint8_t    *encrypted_secret_buf) {

  return make_credential_from_certifier(quote_hash_alg,
                                        quote_key_name_size,
                                        quote_key_name_buf,
                                        endoresment_cert_size,
                                        endoresment_cert_buf,
                                        credential_size,
                                        credential_buf,
                                        cred_blob_size,
                                        cred_blob_buf,
                                        encrypted_secret_size,
                                        encrypted_secret_buf);
}
