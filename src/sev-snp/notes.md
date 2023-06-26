# SEV attestation report

```
struct attestation_report {
  uint32_t    version;                  /* 0x000 */
  uint32_t    guest_svn;                /* 0x004 */
  uint64_t    policy;                   /* 0x008 */
  uint8_t     family_id[16];            /* 0x010 */
  uint8_t     image_id[16];             /* 0x020 */
  uint32_t    vmpl;                     /* 0x030 */
  uint32_t    signature_algo;           /* 0x034 */
  union tcb_version platform_version;   /* 0x038 */
  uint64_t    platform_info;            /* 0x040 */
  uint32_t    flags;                    /* 0x048 */
  uint32_t    reserved0;                /* 0x04C */
  uint8_t     report_data[64];          /* 0x050 */
  uint8_t     measurement[48];          /* 0x090 */
  uint8_t     host_data[32];            /* 0x0C0 */
  uint8_t     id_key_digest[48];        /* 0x0E0 */
  uint8_t     author_key_digest[48];    /* 0x110 */
  uint8_t     report_id[32];            /* 0x140 */
  uint8_t     report_id_ma[32];         /* 0x160 */
  union tcb_version reported_tcb;       /* 0x180 */
  uint8_t     reserved1[24];            /* 0x188 */
  uint8_t     chip_id[64];              /* 0x1A0 */
  uint8_t     reserved2[192];           /* 0x1E0 */
  struct signature  signature;          /* 0x2A0 */
};
```

## SEV platform policy
```
  Policy bits
  Byte 0
    0 NODBG
    1 NOKS (key share)
    3 NOSEND
  Byte 2
    API_MAJOR
    API_MINOR

Attestation report buffer

  0x00 (127:0)  Nonce
  0x10 (255:0)  Launch measurement
  0x30 (31:0)   Policy

---------------------------------------------------------------------------------------------------

Old types
  entity(key or measurement)

New types
  property(name, value-type, comparator, value)
    value-type: number, string
  properties(list of (property))

  platform(type, properties)
    platform-type: amd-sev-snp, sgx, tdx, simulated
  environment(platform, measurement)

New facts (from attestation)

  platform-is platform(type, key, properties)

  SEV specific properties
    sev-api-major is number(v1)
    sev-api-minor is number(v2)
    keyshare is-disallowed
    migration is-disallowed
    debug is-disallowed
```

## New policy statements

  policy-key says platform(type, key, properties) has-trusted-platform-property
  platform(type, properties)
    types are amd-sev-snp, sgx, any

## New deductions


  if platform(type, property) platform-is-trusted
     and platform(type, properties) is-platform
     and platform(type, properties) satisfies platform(type, property-class)
     then platform(type, properties) platform-is-trusted

  if platform(type, properties) platform-is-trusted
     and measurement is-trusted then
     environment(platform, measurement) is-trusted

  if environment(platform, measurement) is-trusted and
     key speaks-for environment then
     key is-trusted-for-authentication

  satisfies
    platform-type: any, always true
    platform-type: amd-sev-snp
      debug-property is-subset-of debug-property-class
      keyshare-property is-subset-of keyshare-property-class
      migrate-property is-subset-of migrate-property-class
      api-major is-subset-of a
    platform-type: sgx
      todo

----


### Policy
1. "policyKey is-trusted"
2: "The policyKey says the ARK-key is-trusted-for-attestation"
3: "policyKey says measurement is-trusted"
4. "policyKey says platform[amd-sev-snp, no-debug, no-migrate, api-major >= 0, api-minor >= 0]
         has-trusted-platform-property"

### From attestation:
1. environment(platform[amd-sev-snp, attest-key: key, no-debug, no-migrate, api-major = 0, api-minor = 0],
         measurement[measurement]) is-environment
2. key[rsa, enclaveKey, b86447b…] speaks-for environment(platform, measurement)


### New constructproof

```
// At this point, the already_proved should be
//    0: "policyKey is-trusted"
//    1: "The policy-key says the ARK-key is-trusted-for-attestation"
//    2: "policyKey says measurement is-trusted"
//    3. "policyKey says platform[amd-sev-snp, no-debug, no-migrate, api-major >= 0, api-minor >= 0]
//            has-trusted-platform-property"
//    4: "The ARK-key says the ARK-key is-trusted-for-attestation"
//    5: "The ARK-key says the ASK-key is-trusted-for-attestation"
//    6: "The ASK-key says the VCEK-key is-trusted-for-attestation"
//    7: "VCEK says environment(platform, measurement) is-environment"
//    8: "VCEK says enclaveKey speaks-for environment"

// Proof is:
//    "policyKey is-trusted" AND policyKey says measurement is-trusted" -->
//        "measurement is-trusted" (R3)
//    "policyKey is-trusted" AND
//        "policy-key says the ARK-key is-trusted-for-attestation" -->
//        "the ARK-key is-trusted-for-attestation" (R3)
//    "the ARK-key is-trusted-for-attestation" AND
//        "The ARK-key says the ASK-key is-trusted-for-attestation" -->
//        "the ASK-key is-trusted-for-attestation" (R5)
//    "the ASK-key is-trusted-for-attestation" AND
//        "the ASK-key says the VCEK-key is-trusted-for-attestation" -->
//        "the VCEK-key is-trusted-for-attestation" (R5)
//    "VCEK-key is-trusted-for-attestation" AND
//        "the VCEK says environment(platform, measurement) is-environment -->
//        "environment(platform, measurement) is-environment"
//    "environment(platform, measurement) is-environment" AND
//        "platform[amd-sev-snp, no-debug,...] has-trusted-platform-property" -->
//        "environment(platform, measurement) environment-platform-is-trusted"
//    "environment(platform, measurement) is-environment" AND
//        "measurement is-trusted" -->
//        "environment(platform, measurement) environment-measurement-is-trusted"
//    "environment(platform, measurement) environment-platform-is-trusted" AND
//        "environment(platform, measurement) environment-measurement-is-trusted"  -->
//        "environment(platform, measurement) is-trusted
//    "VCEK-key is-trusted-for-attestation" AND
//      "VCEK-key says the enclave-key speaks-for the environment()" -->
//        "enclave-key speaks-for the environment()"
//    "environment(platform, measurement) is-trusted AND
//        enclave-key speaks-for environment(platform, measurement)  -->
//        enclave-key is-trusted-for-authentication  [or enclave-key is-trusted-for-attestation]
```