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

# run_example.sh - Setup and run test for sample application programs

This script packages the steps documented in the corresponding
instructions (e.g., [instructions.md](./simple_app/instructions.md)
for the simple_app) in a self-contained script to execute some of the
sample application programs.

```shell
$ ./run_example.sh --help
```
You can use this script to Build and run example programs.

   - Setup and execute the example program.
   - List the individual steps needed to setup the example program.
   - Run individual steps in sequence.

**Usage**:
```shell
run_example.sh [-h | --help] < sample-app-name > [ setup | run_test | --list ]

  To setup and run the simple_app program, end-to-end : ./run_example.sh simple_app
  To setup the simple_app program                     : ./run_example.sh simple_app setup
  To run and test the simple_app program              : ./run_example.sh simple_app run_test
  To list the individual steps for simple_app         : ./run_example.sh simple_app --list
  To run an individual step of the simple_app         : ./run_example.sh simple_app <step name>
```

- To setup and run the simple_app: `$ run_example.sh simple_app`

  In this mode, any artifacts produced by previous steps will be deleted, so
  you can exercise a clean end-to-end run of this script.

- In case there is any cleanup needed, issue: `$ cleanup.sh`
- You can perform the setup once, and execute the test multiple times as follows:

```shell
$ run_example.sh simple_app setup
$ run_example.sh simple_app run_test
$ run_example.sh simple_app run_test
```
- List the individual steps of the setup / test: `$ run_example.sh simple_app --list`
- Execute each step in the order listed. E.g., `$ run_example.sh  simple_app get_measurement_of_trusted_app`
