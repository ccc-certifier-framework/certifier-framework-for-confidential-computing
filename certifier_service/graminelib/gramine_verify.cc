#include "gramineverify.h"

extern bool gramine_remote_verify_impl(const int what_to_say_size, byte* what_to_say, const int attestation_size, byte* attestation, int* measurement_out_size, byte* measurement_out);

bool gramine_Verify(const int what_to_say_size, byte* what_to_say,
    const int attestation_size, byte* attestation,
    int* measurement_out_size, byte* measurement_out) {
  bool result = false;

  result = gramine_remote_verify_impl
           (what_to_say_size, what_to_say, attestation_size,
            attestation, measurement_out_size, measurement_out);
  if (!result) {
    printf("Gramine verify failed\n");
    return false;
  }

  return true;

}
