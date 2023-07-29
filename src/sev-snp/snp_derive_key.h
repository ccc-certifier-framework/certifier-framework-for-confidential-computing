/* Copyright (C) 2021 Advanced Micro Devices, Inc. */

#ifndef SNP_KEY_REQ_H
#define SNP_KEY_REQ_H

#if 1
#  include <linux/types.h>
#else
typedef unsigned char      uint8_t;
typedef unsigned short     uint16_t;
typedef unsigned           uint32_t;
typedef long long unsigned uint64_t;
#endif

#define FIELD_POLICY_SHIFT      (0)
#define FIELD_IMAGE_ID_SHIFT    (1)
#define FIELD_FAMILY_ID_SHIFT   (2)
#define FIELD_MEASUREMENT_SHIFT (3)
#define FIELD_GUEST_SVN_SHIFT   (4)
#define FIELD_TCB_VERSION_SHIFT (5)

#define FIELD_POLICY_MASK      (1ull << (FIELD_POLICY_SHIFT))
#define FIELD_IMAGE_ID_MASK    (1ull << (FIELD_IMAGE_ID_SHIFT))
#define FIELD_FAMILY_ID_MASK   (1ull << (FIELD_FAMILY_ID_SHIFT))
#define FIELD_MEASUREMENT_MASK (1ull << (FIELD_MEASUREMENT_SHIFT))
#define FIELD_GUEST_SVN_MASK   (1ull << (FIELD_GUEST_SVN_SHIFT))
#define FIELD_TCB_VERSION_MASK (1ull << (FIELD_TCB_VERSION_SHIFT))

#define SNP_KEY_REQ_LABEL "gmsg-keyreq"

#define MSG_KEY_REQ_ROOT_KEY_SELECT_SHIFT (0)
#define MSG_KEY_REQ_ROOT_KEY_SELECT_MASK                                       \
  (1ull << (MSG_KEY_REQ_ROOT_KEY_SELECT_SHIFT))

#define MSG_KEY_RSP_RESERVED_SIZE    (0x1F - 0x04 + 1)
#define MSG_KEY_RSP_DERIVED_KEY_SIZE (32)

struct msg_key_resp {
  uint32_t status;
  uint8_t  reserved[MSG_KEY_RSP_RESERVED_SIZE];
  uint8_t  derived_key[MSG_KEY_RSP_DERIVED_KEY_SIZE];
};

#endif /* SNP_KEY_REQ_H */
