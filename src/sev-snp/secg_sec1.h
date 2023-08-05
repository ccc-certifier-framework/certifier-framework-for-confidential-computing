/* Copyright (C) 2021 Advanced Micro Devices, Inc. */

#ifndef SECG_SEC1_H
#define SECG_SEC1_H

#include <stdint.h>

#define BITS_PER_BYTE (8)

#define SECG_EC_P384_POINT_SIZE_BITS (384)
#define SECG_EC_P384_POINT_SIZE                                                \
  ((SECG_EC_P384_POINT_SIZE_BITS) / (BITS_PER_BYTE))

struct ec_point_384 {
  uint8_t w;
  uint8_t x[SECG_EC_P384_POINT_SIZE];
  uint8_t y[SECG_EC_P384_POINT_SIZE];
};

union secg_ec_point_384 {
  struct ec_point_384 point;
  uint8_t             bytes[sizeof(struct ec_point_384)];
};

#endif /* SECG_SEC1_H */
