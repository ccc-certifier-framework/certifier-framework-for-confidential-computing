#include "keystone_api.h"
#include <string.h>
#define assert(x)                                                              \
  do {                                                                         \
    if (!(x)) {                                                                \
      printf("Custom assert failed.\n");                                       \
      exit(17);                                                                \
    }                                                                          \
  } while (false)  // TODO: replace

#ifdef KEYSTONE_PRESENT
#  include "verifier/report.h"
#else
// BEGIN copied Keys.hpp
#  define ATTEST_DATA_MAXLEN 1024
#  define MDSIZE             64
#  define SIGNATURE_SIZE     64
#  define PUBLIC_KEY_SIZE    32
// END copied Keys.hpp

// BEGIN copied Report.hpp
struct _enclave_report_t {
  byte     hash[MDSIZE];
  uint64_t data_len;
  byte     data[ATTEST_DATA_MAXLEN];
  byte     signature[SIGNATURE_SIZE];
};

struct _sm_report_t {
  byte hash[MDSIZE];
  byte public_key[PUBLIC_KEY_SIZE];
  byte signature[SIGNATURE_SIZE];
};

struct _report_t {
  struct _enclave_report_t enclave;
  struct _sm_report_t      sm;
  byte                     dev_public_key[PUBLIC_KEY_SIZE];
};
// END copied Report.hpp
#endif

bool keystone_Init(const int cert_size, byte *cert) {
  return true;
}

bool keystone_Attest(const int what_to_say_size,
                     byte *    what_to_say,
                     int *     attestation_size_out,
                     byte *    attestation_out) {
  assert(what_to_say_size <= ATTEST_DATA_MAXLEN);
  *attestation_size_out = sizeof(struct _report_t);
  // unique-ify un-faked fields to avoid accidentally passing tests
  for (unsigned int i = 0; i < sizeof(struct _report_t); i++) {
    attestation_out[i] = i ^ 17;
  }
  struct _report_t &report =
      *reinterpret_cast<struct _report_t *>(attestation_out);
  report.enclave.data_len = what_to_say_size;
  memcpy(report.enclave.data, what_to_say, what_to_say_size);
  // TODO: input default measurement
  return true;
}

// true = different
static bool nonhash_report_cmp(struct _report_t &a, struct _report_t &b) {
  return (a.enclave.data_len != b.enclave.data_len)
         || memcmp(a.enclave.data, b.enclave.data, ATTEST_DATA_MAXLEN)
         || memcmp(a.enclave.signature, b.enclave.signature, SIGNATURE_SIZE)
         || memcmp(a.sm.public_key, b.sm.public_key, PUBLIC_KEY_SIZE)
         || memcmp(a.sm.signature, b.sm.signature, SIGNATURE_SIZE)
         || memcmp(a.dev_public_key, b.dev_public_key, PUBLIC_KEY_SIZE);
}

bool keystone_Verify(const int what_to_say_size,
                     byte *    what_to_say,
                     const int attestation_size,
                     byte *    attestation,
                     int *     measurement_out_size,
                     byte *    measurement_out) {
  assert(attestation_size == sizeof(struct _report_t));
  struct _report_t &report = *reinterpret_cast<struct _report_t *>(attestation);

  int              gold_attestation_size = 0;
  struct _report_t gold_report;
  keystone_Attest(what_to_say_size,
                  what_to_say,
                  &gold_attestation_size,
                  (byte *)&gold_report);

  if (nonhash_report_cmp(gold_report, report) != 0) {
    return false;
  }

  *measurement_out_size = MDSIZE * 2;
  memcpy(measurement_out, report.sm.hash, MDSIZE);
  memcpy(measurement_out + MDSIZE, report.enclave.hash, MDSIZE);

  return true;
}

bool keystone_Seal(int in_size, byte *in, int *size_out, byte *out) {
  memcpy(out, in, in_size);
  *size_out = in_size;
  return true;
}

bool keystone_Unseal(int in_size, byte *in, int *size_out, byte *out) {
  memcpy(out, in, in_size);
  *size_out = in_size;
  return true;
}
