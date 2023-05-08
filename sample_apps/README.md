# Sample Apps - README

This directory contains the following sample "applications" (i.e., example programs)
that demonstrate how to implement the Certifier APIs on different platforms.

- **simple_app/** - This stand-alone sample program provides an example of initializing,
  provisioning and using the Certifier Service with simulated enclaves.
  This simple_app can be run on any Linux machine without need for specialized hardware.

- **simple_app_under_gramine/** - This application is similar to the sample program,
  simple_app/, but one that can be run in Gramine enclaves. The app uses Intel SGX
  enclaves on Linux platform using the
  [Gramine library](https://github.com/gramineproject/gramine).
  A Gramine enclave uses SGX instructions to generate SGX quotes and reports.

- **simple_app_under_oe/** - This is a sample program that can be run on Intel SGX
  enclaves on Linux platform using the
  [Open Enclave SDK](https://openenclave.io/sdk/), referred briefly as 'OE'.
  Unlike the simple_app example program, an OE-application is partitioned into
  "untrusted" and "trusted" portions, also known as the host and enclave parts,
  respectively.

- **simple_app_under_sev/** - This is the same sample program as in simple_app/
  but one that can be run on
  [AMD Secure Encrypted Virtualization](https://www.amd.com/en/developer/sev.html)
  (SEV) platform using
  [AMD Secure Nested Paging](https://www.amd.com/system/files/TechDocs/SEV-SNP-strengthening-vm-isolation-with-integrity-protection-and-more.pdf)
  (SEV-SNP). The example currently runs under the simulated enclave and should
  run on any VM-based platform host. Of the VM-based platforms, it has been
  tested under SEV-SNP.

- **simple_app_under_app_service/** - This application is similar to the sample program,
   simple_app/, but runs under the application service. The example currently runs
   under a simulated-enclave and will eventually be ported to run under 
   AMD Secure Nested Paging (AMD SEV-SNP).

- **att_systemd_service/** - This is an example of using Certifier APIs to implement
  attestation for system utilities, like the systemd service. The example runs
  in AMD SEV-SNP enabled guest VM. This example for the systemd service is
  FOR DEMONSTRATION ONLY.

- **analytics_example/** - This is an example of Privacy Preserving data analytics with
  the Certifier framework. This sample application demonstrates how to conduct
  privacy preserving data analytics with the Certifier Framework on Open Enclave (OE).
