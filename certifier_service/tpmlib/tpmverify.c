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
