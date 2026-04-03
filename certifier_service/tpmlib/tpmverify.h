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
