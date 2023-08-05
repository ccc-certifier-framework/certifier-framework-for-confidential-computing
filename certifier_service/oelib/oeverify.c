#include "oeverify.h"
#include <openenclave/attestation/sgx/evidence.h>
#include <openenclave/attestation/verifier.h>
#include <openenclave/attestation/custom_claims.h>

static bool oe_verifier_initialized = false;

static const oe_claim_t *_find_claim(const oe_claim_t *claims,
                                     size_t            claims_size,
                                     const char *      name) {
  for (size_t i = 0; i < claims_size; i++) {
    if (strcmp(claims[i].name, name) == 0)
      return &(claims[i]);
  }
  return NULL;
}

bool oe_host_verify_evidence(uint8_t *evidence,
                             size_t   evidence_size,
                             uint8_t *endorsements,
                             size_t   endorsements_size,
                             uint8_t *custom_claim_out,
                             size_t * custom_claim_size,
                             uint8_t *measurement_out,
                             size_t * measurement_size,
                             bool     check_tcb) {
  bool                   result = false;
  oe_result_t            oe_res;
  static const oe_uuid_t _uuid = {OE_FORMAT_UUID_SGX_ECDSA};
  const oe_policy_t *    policies = NULL;
  size_t                 policies_size = 0;
  oe_claim_t *           claims = NULL;
  size_t                 claims_length = 0;
  const oe_claim_t *     claim;
  oe_claim_t *           custom_claims = NULL;
  size_t                 custom_claims_length = 0;

  if (!custom_claim_out || !measurement_out || !evidence) {
    return false;
  }

  if (!endorsements != !endorsements_size) {
    return false;
  }

  if (!oe_verifier_initialized) {
    if (oe_verifier_initialize() != OE_OK) {
      fprintf(stderr, "Failed to initialize oe verifier\n");
      return false;
    }
  }

  oe_res = oe_verify_evidence(&_uuid,
                              evidence,
                              evidence_size,
                              endorsements,
                              endorsements_size,
                              policies,
                              policies_size,
                              &claims,
                              &claims_length);

  result = (check_tcb ? oe_res == OE_OK
                      : (oe_res == OE_OK || oe_res == OE_TCB_LEVEL_INVALID));

  if (result) {
    // Extract the measurement
    if ((claim = _find_claim(claims, claims_length, OE_CLAIM_UNIQUE_ID))
        == NULL) {
      fprintf(stderr, "Could not find claim.\n");
      result = false;
      goto err;
    };
    if (claim->value_size > *measurement_size) {
      fprintf(stderr,
              "Measurement buffer too small. Need %lu bytes.\n",
              claim->value_size);
      result = false;
      goto err;
    }

    memcpy(measurement_out, claim->value, claim->value_size);
    *measurement_size = claim->value_size;

    // Extract the custom claim buffer
    if ((claim =
             _find_claim(claims, claims_length, OE_CLAIM_CUSTOM_CLAIMS_BUFFER))
        == NULL) {
      fprintf(stderr, "Could not find claim.\n");
      result = false;
      goto err;
    };

    if (oe_deserialize_custom_claims(claim->value,
                                     claim->value_size,
                                     &custom_claims,
                                     &custom_claims_length)
        != OE_OK) {
      fprintf(stderr, "oe_deserialize_custom_claims failed.\n");
      result = false;
      goto err;
    }

    if (custom_claims[0].value_size > *custom_claim_size) {
      fprintf(stderr,
              "Custom claim buffer too small. Need %lu bytes.\n",
              custom_claims[0].value_size);
      result = false;
      goto err;
    }
    memcpy(custom_claim_out,
           custom_claims[0].value,
           custom_claims[0].value_size);
    *custom_claim_size = custom_claims[0].value_size;
  }

err:
  if (claims)
    oe_free_claims(claims, claims_length);
  return result;
}
