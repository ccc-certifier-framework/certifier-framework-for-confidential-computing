/* Copyright (C) 2021 Advanced Micro Devices, Inc. */
// Licensed under Apache 2.0

#include <stdio.h>
#include <stdint.h>
#include <attestation.h>
#include <report.h>

static void print_byte_array(const char *   label,
                             const uint8_t *array,
                             size_t         size) {
#define INDENT         "    "
#define MAX_LINE       80
#define CHARS_PER_BYTE 2

  size_t wrap = size;

  if (size > MAX_LINE / CHARS_PER_BYTE - sizeof(INDENT))
    wrap = size / 2;

  if (label)
    printf("%s:\n", label);

  printf(INDENT);

  if (!array) {
    printf("(null)\n");
    return;
  }

  for (size_t i = 0; i < size; i++) {
    if (i > 0 && (i % wrap) == 0) {
      putchar('\n');
      printf(INDENT);
    }
    printf("%02x", array[i]);
  }

  putchar('\n');
}

static void print_tcb_version(const char *label, const union tcb_version *tcb) {
  if (tcb) {
    printf("%s: %02u%02u%02u%02u%02u%02u%02u%02u\n",
           label,
           (unsigned)tcb->boot_loader,
           (unsigned)tcb->tee,
           (unsigned)tcb->reserved[0],
           (unsigned)tcb->reserved[1],
           (unsigned)tcb->reserved[2],
           (unsigned)tcb->reserved[3],
           (unsigned)tcb->snp,
           (unsigned)tcb->microcode);
    printf(" - Boot Loader SVN:  %2u\n", tcb->boot_loader);
    printf(" - TEE SVN:          %2u\n", tcb->tee);
    printf(" - SNP firmware SVN: %2u\n", tcb->snp);
    printf(" - Microcode SVN:    %2u\n", tcb->microcode);
  }
}

/*
 * Print the report version.
 */
void print_version(struct attestation_report *report) {
  if (report) {
    printf("Version: %u\n", report->version);
  }
}

/*
 * Print the guest SVN.
 */
void print_guest_svn(struct attestation_report *report) {
  if (report) {
    printf("Guest SVN: %u\n", report->guest_svn);
  }
}

/*
 * Print the guest policy.
 */
void print_policy(struct attestation_report *report) {
  if (report) {
    printf("Policy: %#0lx\n", report->policy);
    printf(" - Debugging Allowed:       %s\n",
           report->policy & POLICY_DEBUG_MASK ? "Yes" : "No");
    printf(" - Migration Agent Allowed: %s\n",
           report->policy & POLICY_MIGRATE_MA_MASK ? "Yes" : "No");
    printf(" - SMT Allowed:             %s\n",
           report->policy & POLICY_SMT_MASK ? "Yes" : "No");
    printf(" - Min. ABI Major:          %#lx\n",
           (report->policy & POLICY_ABI_MAJOR_MASK) >> POLICY_ABI_MAJOR_SHIFT);
    printf(" - Min. ABI Minor:          %#lx\n",
           (report->policy & POLICY_ABI_MINOR_MASK) >> POLICY_ABI_MINOR_SHIFT);
  }
}

/*
 * Print the family ID (in hex) supplied by the guest.
 */
void print_family_id(struct attestation_report *report) {
  if (report) {
    print_byte_array("Family ID", report->family_id, sizeof(report->family_id));
  }
}

/*
 * Print the image ID (in hex) supplied by the guest.
 */
void print_image_id(struct attestation_report *report) {
  if (report) {
    print_byte_array("Image ID", report->image_id, sizeof(report->image_id));
  }
}

/*
 * Print the guest VMPL.
 */
void print_vmpl(struct attestation_report *report) {
  if (report) {
    printf("VMPL: %u\n", report->vmpl);
  }
}

/*
 * Print the signature algorithm encoding.
 */
void print_signature_algo(struct attestation_report *report) {
  if (report) {
    printf("Signature Algorithm: %u (%s)\n",
           report->signature_algo,
           report->signature_algo == SIG_ALGO_ECDSA_P384_SHA384
               ? "ECDSA P-384 with SHA-384"
               : "Invalid");
  }
}

/*
 * Print the platform version.
 */
void print_platform_version(struct attestation_report *report) {
  if (report) {
    print_tcb_version("Platform Version", &report->platform_version);
  }
}

/*
 * Print the platform info.
 */
void print_platform_info(struct attestation_report *report) {
  if (report) {
    printf("Platform Info: %#0lx\n", report->platform_info);
    printf(" - SMT Enabled: %s\n",
           report->platform_info & PLATFORM_INFO_SMT_EN_MASK ? "Yes" : "No");
  }
}

/*
 * Print the Author key enable bit.
 */
void print_author_key_en(struct attestation_report *report) {
  if (report) {
    printf("Author Key Enabled: %s\n",
           report->platform_info & AUTHOR_KEY_EN_MASK ? "Yes" : "No");
  }
}

/*
 * Print the report data (in hex) supplied by the guest.
 */
void print_report_data(struct attestation_report *report) {
  if (report) {
    print_byte_array("Report Data",
                     report->report_data,
                     sizeof(report->report_data));
  }
}

/*
 * Print the launch measurement (in hex).
 */
void print_measurement(struct attestation_report *report) {
  if (report) {
    print_byte_array("Measurement",
                     report->measurement,
                     sizeof(report->measurement));
  }
}

/*
 * Print the host data (in hex).
 */
void print_host_data(struct attestation_report *report) {
  if (report) {
    print_byte_array("Host Data", report->host_data, sizeof(report->host_data));
  }
}

/*
 * Print the digest of the ID key (in hex).
 */
void print_id_key_digest(struct attestation_report *report) {
  if (report) {
    print_byte_array("ID Key Digest",
                     report->id_key_digest,
                     sizeof(report->id_key_digest));
  }
}

/*
 * Print the digest of the Author key (in hex).
 */
void print_author_key_digest(struct attestation_report *report) {
  if (report) {
    print_byte_array("Author Key Digest",
                     report->author_key_digest,
                     sizeof(report->author_key_digest));
  }
}

/*
 * Print the report ID (in hex).
 */
void print_report_id(struct attestation_report *report) {
  if (report) {
    print_byte_array("Report ID", report->report_id, sizeof(report->report_id));
  }
}

/*
 * Print the report ID (in hex) of the migration agent.
 */
void print_migration_agent_report_id(struct attestation_report *report) {
  if (report) {
    print_byte_array("Migration Agent Report ID",
                     report->report_id_ma,
                     sizeof(report->report_id_ma));
  }
}

/*
 * Print the reported TCB version needed to retreive the VCEK
 * from the AMD KDS.
 */
void print_reported_tcb(struct attestation_report *report) {
  if (report) {
    print_tcb_version("Reported TCB", &report->platform_version);
  }
}

/*
 * Print the chip ID (in hex).
 */
void print_chip_id(struct attestation_report *report) {
  if (report) {
    print_byte_array("Chip ID", report->chip_id, sizeof(report->chip_id));
  }
}

/*
 * Print the signature (in hex).
 */
void print_signature(struct attestation_report *report) {
  if (report) {
    printf("Signature:\n");
    print_byte_array("  R", report->signature.r, sizeof(report->signature.r));
    print_byte_array("  S", report->signature.s, sizeof(report->signature.s));
  }
}

/*
 * Print all fields of the guest report.
 */
void print_report(struct attestation_report *report) {
  print_version(report);
  print_guest_svn(report);
  print_policy(report);
  print_family_id(report);
  print_image_id(report);
  print_vmpl(report);
  print_signature_algo(report);
  print_platform_version(report);
  print_platform_info(report);
  print_author_key_en(report);
  print_report_data(report);
  print_measurement(report);
  print_host_data(report);
  print_id_key_digest(report);
  print_author_key_digest(report);
  print_report_id(report);
  print_migration_agent_report_id(report);
  print_reported_tcb(report);
  print_chip_id(report);
  print_signature(report);
}
