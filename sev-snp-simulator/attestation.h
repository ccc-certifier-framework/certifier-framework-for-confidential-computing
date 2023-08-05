/* Copyright (C) 2021 Advanced Micro Devices, Inc. */
// Licensed inder Apache 2.0 License

#ifndef ATTESTATION_H
#define ATTESTATION_H

#include <linux/types.h>

#define POLICY_DEBUG_SHIFT      19
#define POLICY_MIGRATE_MA_SHIFT 18
#define POLICY_SMT_SHIFT        16
#define POLICY_ABI_MAJOR_SHIFT  8
#define POLICY_ABI_MINOR_SHIFT  0

#define POLICY_DEBUG_MASK      (1UL << (POLICY_DEBUG_SHIFT))
#define POLICY_MIGRATE_MA_MASK (1UL << (POLICY_MIGRATE_MA_SHIFT))
#define POLICY_SMT_MASK        (1UL << (POLICY_SMT_SHIFT))
#define POLICY_ABI_MAJOR_MASK  (0xFFUL << (POLICY_ABI_MAJOR_SHIFT))
#define POLICY_ABI_MINOR_MASK  (0xFFUL << (POLICY_ABI_MINOR_SHIFT))

#define SIG_ALGO_ECDSA_P384_SHA384 0x1

#define PLATFORM_INFO_SMT_EN_SHIFT 0
#define PLATFORM_INFO_SMT_EN_MASK  (1UL << (PLATFORM_INFO_SMT_EN_SHIFT))

#define AUTHOR_KEY_EN_SHIFT 0
#define AUTHOR_KEY_EN_MASK  (1UL << (AUTHOR_KEY_EN_SHIFT))

union tcb_version {
  struct {
    uint8_t boot_loader;
    uint8_t tee;
    uint8_t reserved[4];
    uint8_t snp;
    uint8_t microcode;
  };
  uint64_t raw;
};

struct signature {
  uint8_t r[72];
  uint8_t s[72];
  uint8_t reserved[512 - 144];
};

struct attestation_report {
  uint32_t          version;               /* 0x000 */
  uint32_t          guest_svn;             /* 0x004 */
  uint64_t          policy;                /* 0x008 */
  uint8_t           family_id[16];         /* 0x010 */
  uint8_t           image_id[16];          /* 0x020 */
  uint32_t          vmpl;                  /* 0x030 */
  uint32_t          signature_algo;        /* 0x034 */
  union tcb_version platform_version;      /* 0x038 */
  uint64_t          platform_info;         /* 0x040 */
  uint32_t          flags;                 /* 0x048 */
  uint32_t          reserved0;             /* 0x04C */
  uint8_t           report_data[64];       /* 0x050 */
  uint8_t           measurement[48];       /* 0x090 */
  uint8_t           host_data[32];         /* 0x0C0 */
  uint8_t           id_key_digest[48];     /* 0x0E0 */
  uint8_t           author_key_digest[48]; /* 0x110 */
  uint8_t           report_id[32];         /* 0x140 */
  uint8_t           report_id_ma[32];      /* 0x160 */
  union tcb_version reported_tcb;          /* 0x180 */
  uint8_t           reserved1[24];         /* 0x188 */
  uint8_t           chip_id[64];           /* 0x1A0 */
  uint8_t           reserved2[192];        /* 0x1E0 */
  struct signature  signature;             /* 0x2A0 */
};

struct msg_report_resp {
  uint32_t                  status;
  uint32_t                  report_size;
  uint8_t                   reserved[0x20 - 0x8];
  struct attestation_report report;
};

#endif /* ATTESTATION_H */
