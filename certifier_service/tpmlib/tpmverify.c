#include "tpmverify.h"
#include "certifier.pb.h"
#include "tpm2.pb.h"
#include "certifier_framework.h"
#include "tpm2_support.h"


static bool tpm_verifier_initialized = false;

bool tpm_host_verify_attest(int      serialized_cert_size,
                            uint8_t *serialized_cert,
                            int      serialized_attest_size,
                            uint8_t *serialized_attest,
                            int     *measurement_size,
                            uint8_t *measurement_out,
                            int     *pcr_size,
                            uint8_t *pcr_out) {
  string cert;
  string attest;
  string to_quote;
  string quoted;
  string signature;

  cert.assign((char *)serialized_cert, serialized_cert_size);
  attest.assign((char *)serialized_attest, serialized_attest_size);

  // get to_quote and signature
  tpm_attestation_message att;
  if (!att.ParseFromString(attest)) {
    printf("%s() error, line %d, Can't parse attestation\n",
           __func__,
           __LINE__);
    return false;
  }
  to_quote.assign((char *)att.what_was_said().data(),
                  att.what_was_said().size());
  quoted.assign((char *)att.the_quote().data(), att.the_quote().size());
  signature.assign((char *)att.signature().data(), att.signature().size());

  bool ret = tpm_Verify(cert, to_quote, quoted, signature);
  if (!ret) {
    printf("%s() error, line %d, attestation does not verify\n",
           __func__,
           __LINE__);
    return false;
  }

  // get measurement; pcrs
  uint32_t           magic;
  uint16_t           type;
  string             signer;
  string             extra_data;
  TPML_PCR_SELECTION pcrSelect;
  string             pcr_digest;
  if (!decode_quoted(quoted.size(),
                     (byte_t *)quoted.data(),
                     &magic,
                     &type,
                     &signer,
                     &extra_data,
                     &pcrSelect,
                     &pcr_digest)) {
    printf("%s() error, line %d, decode quoted failed\n", __func__, __LINE__);
    return false;
  }
  *measurement_size = pcr_digest.size();
  memcpy(measurement_out, pcr_digest.data(), *measurement_size);
  int    num_pcrs = 24;
  byte_t pcrs[24];
  if (!get_pcr_from_select(&pcrSelect, &num_pcrs, pcrs)) {
    printf("%s() error, line %d, get_pcr_from_select failed\n",
           __func__,
           __LINE__);
    return false;
  }

  *pcr_size = num_pcrs;
  memcpy(pcr_out, pcrs, num_pcrs);

  return true;
}
