#include "tpmverify.h"

bool tpm_host_verify_attest(int      serialized_cert_cert_size,
                            uint8_t *serialized_cert_cert,
                            int      serialized_attest_size,
                            uint8_t *serialized_attest,
                            int     *measurement_size,
                            uint8_t *measurement_out,
                            int     *pcr_size,
                            uint8_t *pcr_out) {
  fprintf(stderr, "Dummy tpm_host_verify_attest call.\n");
  return false;
}
