/* Copyright (C) 2021 Advanced Micro Devices, Inc. */

#ifndef REPORT_H
#define REPORT_H

#include <attestation.h>

/*
 * Print the report version.
 */
void print_version(struct attestation_report *report);

/*
 * Print the guest SVN.
 */
void print_guest_svn(struct attestation_report *report);

/*
 * Print the guest policy.
 */
void print_policy(struct attestation_report *report);

/*
 * Print the family ID (in hex) supplied by the guest.
 */
void print_family_id(struct attestation_report *report);

/*
 * Print the image ID (in hex) supplied by the guest.
 */
void print_image_id(struct attestation_report *report);

/*
 * Print the guest VMPL.
 */
void print_vmpl(struct attestation_report *report);

/*
 * Print the signature algorithm encoding.
 */
void print_signature_algo(struct attestation_report *report);

/*
 * Print the platform version.
 */
void print_platform_version(struct attestation_report *report);

/*
 * Print the platform info.
 */
void print_platform_info(struct attestation_report *report);

/*
 * Print the Author key enable bit.
 */
void print_author_key_en(struct attestation_report *report);

/*
 * Print the report data (in hex) supplied by the guest.
 */
void print_report_data(struct attestation_report *report);

/*
 * Print the launch measurement (in hex).
 */
void print_measurement(struct attestation_report *report);

/*
 * Print the host data (in hex).
 */
void print_host_data(struct attestation_report *report);

/*
 * Print the digest of the ID key (in hex).
 */
void print_id_key_digest(struct attestation_report *report);

/*
 * Print the digest of the Author key (in hex).
 */
void print_author_key_digest(struct attestation_report *report);

/*
 * Print the report ID (in hex).
 */
void print_report_id(struct attestation_report *report);

/*
 * Print the report ID (in hex) of the migration agent.
 */
void print_migration_agent_report_id(struct attestation_report *report);

/*
 * Print the reported TCB version needed to retreive the VCEK
 * from the AMD KDS.
 */
void print_reported_tcb(struct attestation_report *report);

/*
 * Print the chip ID (in hex).
 */
void print_chip_id(struct attestation_report *report);

/*
 * Print the signature (in hex).
 */
void print_signature(struct attestation_report *report);

/*
 * Print all fields of the guest report.
 */
void print_report(struct attestation_report *report);

#endif /* REPORT_H */
