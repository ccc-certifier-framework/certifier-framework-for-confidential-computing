#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

typedef unsigned char byte;

#ifdef __cplusplus
extern "C" {
#endif

bool gramine_Verify(const int what_to_say_size, byte* what_to_say,
    const int attestation_size, byte* attestation,
    int* measurement_out_size, byte* measurement_out);

#ifdef __cplusplus
}
#endif
