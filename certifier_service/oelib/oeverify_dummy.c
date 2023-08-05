#include "oeverify.h"

bool oe_host_verify_evidence(uint8_t *evidence,
                             size_t   evidence_size,
                             uint8_t *endorsements,
                             size_t   endorsements_size,
                             uint8_t *custom_claim_out,
                             size_t * custom_claim_size,
                             uint8_t *measurement_out,
                             size_t * measurement_size,
                             bool     check_tcb) {
  fprintf(stderr, "Dummy oe_host_verify_evidence call.\n");
  return false;
}
