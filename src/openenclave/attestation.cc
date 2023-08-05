#include "attestation.h"
#include <openenclave/enclave.h>
#include <openenclave/attestation/attester.h>
#include <openenclave/attestation/custom_claims.h>
#include <openenclave/attestation/verifier.h>
#include <openenclave/attestation/sgx/evidence.h>
#include <openenclave/bits/report.h>

// SGX Attestation Format UUID.
static oe_uuid_t vse_format_uuid = {OE_FORMAT_UUID_SGX_ECDSA};

bool oe_Attest(int   what_to_say_size,
               byte *what_to_say,
               int * size_out,
               byte *out) {
  bool        ret = false;
  oe_result_t result = OE_OK;
  oe_uuid_t * format_id = &vse_format_uuid;
  uint8_t *   format_settings = nullptr;
  size_t      format_settings_size = 0;
  uint8_t *   custom_claims_buffer = nullptr;
  size_t      custom_claims_buffer_size = 0;
  uint8_t *   evidence = nullptr;
  size_t      evidence_size = 0;
  char        custom_claim_name[] = "Certifier Attestation";

  if (!size_out || !out) {
    return false;
  }

  // Wrap the whole certifier attestation report into one custom claim.
  oe_claim_t custom_claims = {
      .name = custom_claim_name,
      .value = (uint8_t *)what_to_say,
      .value_size = (size_t)what_to_say_size,
  };

  // Serialize the custom claim
  if (oe_serialize_custom_claims(&custom_claims,
                                 1,
                                 &custom_claims_buffer,
                                 &custom_claims_buffer_size)
      != OE_OK) {
    printf("oe_serialize_custom_claims failed.\n");
    goto exit;
  }
  OE_DEBUG_PRINTF("serialized custom claims buffer size: %lu\n",
                  custom_claims_buffer_size);

  // Get the format settings from the Verifier. Should be null for VSE.
  if (oe_verifier_get_format_settings(format_id,
                                      &format_settings,
                                      &format_settings_size)
      != OE_OK) {
    printf("oe_verifier_get_format_settings failed\n");
    goto exit;
  }
  OE_DEBUG_PRINTF("format settings size: %lu\n", format_settings_size);

  // Generate evidence based on the format selected by the attester.
  result = oe_get_evidence(format_id,
                           0,
                           custom_claims_buffer,
                           custom_claims_buffer_size,
                           format_settings,
                           format_settings_size,
                           &evidence,
                           &evidence_size,
                           nullptr,
                           0);
  if (result != OE_OK) {
    printf("oe_get_evidence failed.(%s)\n", oe_result_str(result));
    goto exit;
  }
  OE_DEBUG_PRINTF("evidence size: %lu\n", evidence_size);
  if (out == nullptr) {
    *size_out = (int)evidence_size;
    ret = true;
    goto exit;
  }
  if (*size_out < evidence_size) {
    printf("Output buffer too small.\n");
    goto exit;
  }
  memcpy(out, evidence, evidence_size);
  *size_out = evidence_size;
  ret = true;

exit:
  if (format_settings != nullptr)
    free(format_settings);
  if (custom_claims_buffer != nullptr)
    free(custom_claims_buffer);
  if (evidence != nullptr)
    free(evidence);
  return ret;
}

static const oe_claim_t *_find_claim(const oe_claim_t *claims,
                                     size_t            claims_size,
                                     const char *      name) {
  for (size_t i = 0; i < claims_size; i++) {
    if (strcmp(claims[i].name, name) == 0)
      return &(claims[i]);
  }
  return nullptr;
}

#ifdef OE_DEBUG
static void _print_hex(const uint8_t *data, size_t size) {
  int i;
  for (i = 0; i < size; i++)
    printf("%02x", data[i]);
}
#endif

bool oe_Verify(const uint8_t *evidence,
               size_t         evidence_size,
               uint8_t *      custom_claim_out,
               size_t *       custom_claim_size,
               uint8_t *      measurement_out,
               size_t *       measurement_size) {
  bool              ret = false;
  oe_result_t       result = OE_OK;
  oe_uuid_t *       format_id = &vse_format_uuid;
  oe_claim_t *      claims = nullptr;
  size_t            claims_length = 0;
  const oe_claim_t *claim;
  oe_claim_t *      custom_claims = nullptr;
  size_t            custom_claims_length = 0;

  if (!evidence || evidence_size == 0 || !custom_claim_out
      || !measurement_out) {
    return false;
  }

  // Validate the evidence's trustworthiness
  // Verify the evidence to ensure its authenticity.
  result = oe_verify_evidence(format_id,
                              evidence,
                              evidence_size,
                              nullptr,
                              0,
                              nullptr,
                              0,
                              &claims,
                              &claims_length);
  if (result != OE_OK) {
    printf("oe_verify_evidence failed (%s).\n", oe_result_str(result));
    goto exit;
  }

  OE_DEBUG_PRINTF("oe_verify_evidence succeeded\n");
  OE_DEBUG_PRINTF("oe_verify_evidence evaluate all supported claims:\n"
                  "   [OE_CLAIM_ID_VERSION]\n"
                  "   [OE_CLAIM_SECURITY_VERSION]\n"
                  "   [OE_CLAIM_ATTRIBUTES]\n"
                  "   [OE_CLAIM_UNIQUE_ID] (Measurement)\n"
                  "   [OE_CLAIM_SIGNER_ID] (Not used on VSE)\n"
                  "   [OE_CLAIM_PRODUCT_ID] (Fixed on VSE)\n"
                  "   [OE_CLAIM_FORMAT_UUID]\n"
                  "   [OE_CLAIM_CUSTOM_CLAIMS_BUFFER] (User data)\n");

  // Go over the claims
  if ((claim = _find_claim(claims, claims_length, OE_CLAIM_ID_VERSION))
      == nullptr) {
    printf("Could not find claim.\n");
    goto exit;
  };

  OE_DEBUG_PRINTF("%s: %u\n", OE_CLAIM_ID_VERSION, *((uint32_t *)claim->value));

  if ((claim = _find_claim(claims, claims_length, OE_CLAIM_SECURITY_VERSION))
      == nullptr) {
    printf("Could not find claim.\n");
    goto exit;
  };

  OE_DEBUG_PRINTF("%s: %u\n",
                  OE_CLAIM_SECURITY_VERSION,
                  *((uint32_t *)claim->value));

  if ((claim = _find_claim(claims, claims_length, OE_CLAIM_ATTRIBUTES))
      == nullptr) {
    printf("Could not find claim.\n");
    goto exit;
  };

  OE_DEBUG_PRINTF("%s: %lu\n",
                  OE_CLAIM_ATTRIBUTES,
                  *((uint64_t *)claim->value));

  if ((claim = _find_claim(claims, claims_length, OE_CLAIM_UNIQUE_ID))
      == nullptr) {
    printf("Could not find claim.\n");
    goto exit;
  };

#ifdef OE_DEBUG
  printf("%s: ", OE_CLAIM_UNIQUE_ID);
  _print_hex(claim->value, claim->value_size);
  printf("\n");
#endif

  if (claim->value_size > *measurement_size) {
    printf("Measurement buffer too small. Need %lu bytes.\n",
           claim->value_size);
    goto exit;
  }

  memcpy(measurement_out, claim->value, claim->value_size);
  *measurement_size = claim->value_size;

  if ((claim = _find_claim(claims, claims_length, OE_CLAIM_SIGNER_ID))
      == nullptr) {
    printf("Could not find claim.\n");
    goto exit;
  };

  if (claim->value_size != OE_SIGNER_ID_SIZE) {
    printf("signer_id size(%lu) checking failed\n", claim->value_size);
    goto exit;
  }

#ifdef OE_DEBUG
  printf("%s: ", OE_CLAIM_SIGNER_ID);
  _print_hex(claim->value, claim->value_size);
  printf("\n");
#endif

  if ((claim = _find_claim(claims, claims_length, OE_CLAIM_PRODUCT_ID))
      == nullptr) {
    printf("Could not find claim.\n");
    goto exit;
  };

  if (claim->value_size != OE_PRODUCT_ID_SIZE) {
    printf("product_id size(%lu) checking failed\n", claim->value_size);
    goto exit;
  }

#ifdef OE_DEBUG
  printf("%s: ", OE_CLAIM_PRODUCT_ID);
  _print_hex(claim->value, claim->value_size);
  printf("\n");
#endif

  if ((claim = _find_claim(claims, claims_length, OE_CLAIM_FORMAT_UUID))
      == nullptr) {
    printf("Could not find claim.\n");
    goto exit;
  };

#ifdef OE_DEBUG
  printf("%s: ", OE_CLAIM_FORMAT_UUID);
  _print_hex(claim->value, claim->value_size);
  printf("\n");
#endif

  // Extract the custom claim buffer
  if ((claim =
           _find_claim(claims, claims_length, OE_CLAIM_CUSTOM_CLAIMS_BUFFER))
      == nullptr) {
    printf("Could not find claim.\n");
    goto exit;
  };
  OE_DEBUG_PRINTF("Custom claims buffer length: %lu\n", claim->value_size);

  if (oe_deserialize_custom_claims(claim->value,
                                   claim->value_size,
                                   &custom_claims,
                                   &custom_claims_length)
      != OE_OK) {
    printf("oe_deserialize_custom_claims failed.\n");
    goto exit;
  }

  OE_DEBUG_PRINTF("custom claim (%s)\n", custom_claims[0].name);
  if (custom_claims[0].value_size > *custom_claim_size) {
    printf("Custom claim buffer too small. Need %lu bytes.\n",
           custom_claims[0].value_size);
    goto exit;
  }
  memcpy(custom_claim_out, custom_claims[0].value, custom_claims[0].value_size);
  *custom_claim_size = custom_claims[0].value_size;

  ret = true;

exit:
  if (claims != nullptr)
    oe_free_claims(claims, claims_length);
  return ret;
}
