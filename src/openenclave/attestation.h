#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <string>
#include <memory>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <cmath>
#include <string>
#include "oe_common.h"

using std::string;

#ifndef _ATTESTATION_H__
#  define _ATTESTATION_H__

bool oe_Attest(int   what_to_say_size,
               byte *what_to_say,
               int * size_out,
               byte *out);
bool oe_Verify(const uint8_t *evidence,
               size_t         evidence_size,
               uint8_t *      custom_claim_out,
               size_t *       custom_claim_size,
               uint8_t *      measurement_out,
               size_t *       measurement_size);
#endif
