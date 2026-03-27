# Simple App under TPM instructions

This example app shows all the major steps in a Confidential Computing program,
running under the TPM.

This uses the same application as in [simple_app]
This example embeds the policy key in the application using the
`embed_policy_key.exe`.

## Simulated TPM Environment

We also support a TPM simulator (swtpm) which can be configured and installed
on any Linux host.  Installation instructions are below.

----

## Overview

The step by step instructions for building simple_app and running the tests
are enumerated below.  However, to save time, we also supply two shell
scripts to do this automatically. The shell script prepare-test.sh builds
the program and support files.  The shell script run-test.sh runs the test.
There is still benefit in carrying out the steps in run-test by copying and
pasting since you can see all the output and preserve the running servers.

The shell scripts assume you have all the right software installed including
the go programs and libraries mentioned below.

The shell scripts use the new API.

To prepare the test files, type:

  prepare-test.sh fresh [domain-name]
      - This clears out all old files
then
  prepare-test.sh all [domain-name]
      - This builds the files corresponding to steps 1-9 below.
then
  run-test.sh fresh [domain-name]
      - This removes old application files (policy store and cryptstore)
      - and runs the tests, corresponding to steps 9 and 10 below.

prepare-test.sh all runs the following subcommands in order:
  prepare-test.sh compile-utilities [domain-name]
      - This performs steps 1-2 below.
  prepare-test.sh make-keys [domain-name]
      - This performs step 3 below.
  prepare-test.sh compile-program [domain-name]
      - This performs step 4 to 5 below.
  prepare-test.sh make-policy [domain-name]
      - This performs steps 6 and 7 below.
  prepare-test.sh compile-certifier [domain-name]
      - This performs step 8 below.
  prepare-test.sh copy-files [domain-name]
      - This performs steps 9 to 12 below.

Each of these subcommands is runable from prepare-test.sh, for example,
you could run,
   prepare-test.sh make-policy [domain-name]
to remake the policy.

After you run "prepare-test.sh all", you can rerun the tests without
invoking prepare-test.sh.  After you run "prepare-test.sh all",
you need only run subcommands that cause a change in the files;
for example, if you change the policy, you need only run
"prepare-test.sh make-policy" before running the tests.


To run the tests
  echo "  ./run-test.sh fresh"
  echo "  ./run-test.sh fresh domain-name"
     -- This clears previous operational files.  The first assumes the
        default domain name ("datica-test").
  echo "  ./run-test.sh run
  echo "  ./run-test.sh run domain_name 
     -- This runds the test.  The first assumes the default domain
         name ("datica-test").

---------------------------------------------------------------------------------------


## Detailed steps by step instructions to build-and-run Simple App under AMD TPM

$CERTIFIER_PROTOTYPE is the top level directory for the certifier repository.
It is helpful to have a shell variable for it, e.g.,:

```shell
export CERTIFIER_PROTOTYPE=~/src/github.com/ccc-certifier-framework/certifier-framework-for-confidential-computing
```

$EXAMPLE_DIR is this directory containing the example application.  Again, a
shell variable is useful.

```shell
export EXAMPLE_DIR=$CERTIFIER_PROTOTYPE/sample_apps/simple_app_under_tpm
```
## Setup Software

## TPM Simulator utility

-----
## Step 1: Build the utilities
```shell
pushd $CERTIFIER_PROTOTYPE/utilities

make -f cert_utility.mak clean
make -f cert_utility.mak
make -f policy_utilities.mak
popd
```

## Step 2:  Create a directory for the provisioning files
```shell
mkdir $EXAMPLE_DIR/provisioning
```

## Step 3: Generate the policy key and self-signed certificate
```shell
cd $EXAMPLE_DIR/provisioning

$CERTIFIER_PROTOTYPE/utilities/cert_utility.exe       \
      --operation=generate-policy-key                 \
      --policy_key_output_file=policy_key_file.bin    \
      --policy_cert_output_file=policy_cert_file.bin
```

### Step 3(a): Use der-encoded versions of the certificates

Make sure there are der-encoded versions of the ARK, ASK and VCEK certificates in
the provisioning directory.  For TPM, these certificates come from the platform.

The script provides an alternate way to compile the application in a simulated
evironment provided by tpm-snp-simulator.

For that simulated environment, the compilation script,
[tpm_example_app.mak](./tpm_example_app.mak), supports passing-in `-DTPM_DUMMY_GUEST`
via the `CFLAGS` env-variable.

To test against this environment, you must generate an ARK, ASK and VCEK certificates
that are compatible with the tpm-snp-simulator keys.

To do this:

## Step 4: Embed the policy key in the example_app
```shell
cd $EXAMPLE_DIR/provisioning

$CERTIFIER_PROTOTYPE/utilities/embed_policy_key.exe     \
        --input=policy_cert_file.bin                    \
        --output=../policy_key.cc
```

## Step 5: Compile TPM-example_app with the embedded policy_key
```shell
cd $EXAMPLE_DIR

make -f tpm_example_app.mak clean
make -f tpm_example_app.mak
```

NOTE: If you are running in a TPM-simulated environment, do:
```shell
CFLAGS='-DTPM_DUMMY_GUEST' make -f tpm_example_app.mak
```
## Step 6: Obtain the measurement of the trusted application for this security domain

```shell
cd $EXAMPLE_DIR/provisioning

$CERTIFIER_PROTOTYPE/utilities/measurement_init.exe   \
        --mrenclave=<HASH>                            \
        --out_file=example_app.measurement
```
Replace <HASH> with your actual measurement from `tpm-snp-measure`.

If you are using the [tpm-snp-simulator](./../../INSTALL.md), use:

```
010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708
```

We are switching tools to calculate the tpm measurements off-line to virtee. 
You can download the tool from https://github.com/virtee/tpm-snp-measure.
Future versions of the Framework will use virtee measurements as a default.
Instructions for use are straightforward.  With virtee,important additional
properties can also become part of the measurement (and hence verified during
an attestation.  Among the most important are those that use the following flags:
  --ovmf PATH           OVMF file to calculate hash from
  --kernel PATH         Kernel file to calculate hash from
  --initrd PATH         Initrd file to calculate hash from (use with --kernel)
  --append CMDLINE      Kernel command line to calculate hash from (use with --kernel)

## Author the policy for the security domain and produce the signed claims the apps need

The policies can be generated either manually or through the Policy Generator tool.
In the steps below, follow either step (7), below, or step (8),
[Use Automated Policy Generator](#Step-8-Use-Automated-Policy-Generator).

## Step 7: Manual policy generation

### b. Construct policyKey says platformKey is-trusted-for-attestation

```shell
$CERTIFIER_PROTOTYPE/utilities/make_unary_vse_clause.exe    \
        --certificate-subject=ark_cert.der                  \
        --verb="is-trusted-for-attestation"                 \
        --output=ts1.bin

$CERTIFIER_PROTOTYPE/utilities/make_indirect_vse_clause.exe     \
        --key_subject=policy_key_file.bin                       \
        --verb="says"                                           \
        --clause=ts1.bin                                        \
        --output=vse_policy1.bin
```

### b. Produce the signed claims for each vse policy statement.

```shell
$CERTIFIER_PROTOTYPE/utilities/make_signed_claim_from_vse_clause.exe    \
        --vse_file=vse_policy1.bin                                      \
        --duration=9000                                                 \
        --private_key_file=policy_key_file.bin                          \
        --output=signed_claim_1.bin
```

### c. Construct the measurement policy
```shell
$CERTIFIER_PROTOTYPE/utilities/make_unary_vse_clause.exe    \
        --key_subject=""                                    \
        --measurement_subject=example_app.measurement   \
        --verb="is-trusted"                                 \
        --output=ts2.bin

$CERTIFIER_PROTOTYPE/utilities/make_indirect_vse_clause.exe     \
        --key_subject=policy_key_file.bin                       \
        --verb="says"                                           \
        --clause=ts2.bin                                        \
        --output=vse_policy2.bin

$CERTIFIER_PROTOTYPE/utilities/make_signed_claim_from_vse_clause.exe    \
        --vse_file=vse_policy2.bin                                      \
        --duration=9000                                                 \
        --private_key_file=policy_key_file.bin                          \
        --output=signed_claim_2.bin
```

### d. Construct the trusted platform policy

```shell
$CERTIFIER_PROTOTYPE/utilities/make_property.exe    \
        --property_name=debug                       \
        --property_type='string' comparator="="     \
        --string_value=no                           \
        --output=property1.bin

$CERTIFIER_PROTOTYPE/utilities/make_property.exe    \
        --property_name=migrate                     \
        --property_type='string' comparator="="     \
        --string_value=no                           \
        --output=property2.bin

$CERTIFIER_PROTOTYPE/utilities/make_property.exe    \
        --property_name=smt                         \
        --property_type='string' comparator="="     \
        --string_value=no                           \
        --output=property5.bin

$CERTIFIER_PROTOTYPE/utilities/make_property.exe    \
        --property_name='api-major'                 \
        --property_type=int                         \
        --comparator=">="                           \
        --int_value=0                               \
        --output=property3.bin

$CERTIFIER_PROTOTYPE/utilities/make_property.exe    \
        --property_name='api-minor'                 \
        --property_type=int                         \
        --comparator=">="                           \
        --int_value=0                               \
        --output=property4.bin

$CERTIFIER_PROTOTYPE/utilities/make_property.exe    \
        --property_name='tcb-version'               \
        --property_type=int                         \
        --comparator="="                            \
        --int_value=0x03000000000008115             \
        --output=property6.bin

$CERTIFIER_PROTOTYPE/utilities/combine_properties.exe   \
      --in=property1.bin,property2.bin,property3.bin,property4.bin,property5.bin,property6.bin \
      --output=properties.bin

$CERTIFIER_PROTOTYPE/utilities/make_platform.exe    \
        --platform_type=amd-tpm-snp                 \
        --properties_file=properties.bin            \
        --output=platform.bin

$CERTIFIER_PROTOTYPE/utilities/make_unary_vse_clause.exe    \
        --platform_subject=platform.bin                     \
        --verb="has-trusted-platform-property"              \
        --output=ts3.bin

$CERTIFIER_PROTOTYPE/utilities/make_indirect_vse_clause.exe     \
        --key_subject=policy_key_file.bin                       \
        --verb="says"                                           \
        --clause=ts3.bin                                        \
        --output=vse_policy3.bin

$CERTIFIER_PROTOTYPE/utilities/make_signed_claim_from_vse_clause.exe    \
        --vse_file=vse_policy3.bin                                      \
        --duration=9000                                                 \
        --private_key_file=policy_key_file.bin                          \
        --output=signed_claim_3.bin
```

### e. Package the policy for the certifier
```shell
$CERTIFIER_PROTOTYPE/utilities/package_claims.exe                           \
        --input=signed_claim_1.bin,signed_claim_2.bin,signed_claim_3.bin    \
        --output=policy.bin
```

### f. [optional] Print the policy
```shell
$CERTIFIER_PROTOTYPE/utilities/print_packaged_claims.exe --input=policy.bin
```
## Step 8: Use Automated Policy Generator

NOTE: You have to implement either one of step (7) or this step (8).

### a. Edit policy file

Open tpm_policy.json and replace trusted measurements in the
"measurements" property with the expected measurement.

If you are using the tpm-snp-simulator, use:

```
010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708
```

**NOTE:** The default [tpm_policy.json](./tpm_policy.json) provided in this repo
      is custom-crafted to specify the policy and measurement for the TPM
      test machine internally used.
The  [run_example.sh](../run_example.sh#:~:text=get_measurement_of_trusted_simple_app_under_tpm)
script expects that the user will provide a fully-specified JSON file for
their platform on which this test will be run.


### b. Build the Policy Generator

```shell
cd $CERTIFIER_PROTOTYPE/utilities
LOCAL_LIB=/usr/local/lib64 make -f policy_generator.mak
```

### c. Run Policy Generator:

```shell
cd $EXAMPLE_DIR/provisioning

$CERTIFIER_PROTOTYPE/utilities/policy_generator.exe                         \
        --policy_input=../tpm_policy.json                                   \
        --schema_input=$CERTIFIER_PROTOTYPE/utilities/policy_schema.json    \
        --util_path=$CERTIFIER_PROTOTYPE/utilities
```

### d. [optional] Print the policy
```shell
$CERTIFIER_PROTOTYPE/utilities/print_packaged_claims.exe --input=policy.bin
```

## Step 8: Build SimpleServer:

You should have gotten the protobuf compiler (protoc) for go when you got go.
If not:

```shell
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
```
Compile the protobuf
```shell
cd $CERTIFIER_PROTOTYPE/certifier_service/certprotos

protoc --go_opt=paths=source_relative --go_out=. --go_opt=M=certifier.proto ./certifier.proto
```
Compile the oelib for OE host verification
```shell
cd $CERTIFIER_PROTOTYPE/certifier_service/oelib

make
```
If you do not have OE SDK installed or do not want to enable OE:
```shell
make dummy
```

Compile the teelib for running the certifier service inside a TEE
```shell
cd $CERTIFIER_PROTOTYPE/certifier_service/teelib

make
```

This should produce a Go file for the certifier protobufs called certifier.pb.go in certprotos.

Now build simpleserver:
```shell
cd $CERTIFIER_PROTOTYPE/certifier_service

go build simpleserver.go
```


## Step 9: Create directories for app data and service data
```shell
cd $EXAMPLE_DIR
mkdir app1_data app2_data service
```

## Step 10: Provision the app files

Note: These files are required for the "simulated-enclave" which cannot measure the
example app and needs a provisioned attestation key and platform certificate.  On real
hardware, these are not needed.

```shell
cd $EXAMPLE_DIR/provisioning

cp -p ./* $EXAMPLE_DIR/app1_data
cp -p ./* $EXAMPLE_DIR/app2_data
```


## Step 11: Provision the service files
```shell
cd $EXAMPLE_DIR/provisioning

cp -p policy_key_file.bin policy_cert_file.bin policy.bin $EXAMPLE_DIR/service
cp -p *.der $EXAMPLE_DIR/service
```


## Step 12: Start the Certifier Service
  In a new terminal window:
```shell
cd $EXAMPLE_DIR/service
$CERTIFIER_PROTOTYPE/certifier_service/simpleserver \
      --policyFile=policy.bin                       \
      --readPolicy=true
```


## Step 13:  Run the apps and get admission certificates from Certifier Service

Open two new terminals (one for the app as a client and one for the app as a server):

In app-as-a-client terminal run the following:
```shell
cd $EXAMPLE_DIR

$EXAMPLE_DIR/tpm_example_app.exe            \
        --data_dir=./app1_data/             \
        --operation=cold-init               \
        --policy_store_file=policy_store    \
        --print_all=true

$EXAMPLE_DIR/tpm_example_app.exe            \
        --data_dir=./app1_data/             \
        --operation=get-certified           \
        --policy_store_file=policy_store    \
        --print_all=true
```

In app-as-a-server terminal run the following:
```shell
cd $EXAMPLE_DIR

$EXAMPLE_DIR/tpm_example_app.exe            \
        --data_dir=./app2_data/             \
        --operation=cold-init               \
        --policy_store_file=policy_store    \
        --print_all=true

$EXAMPLE_DIR/tpm_example_app.exe            \
        --data_dir=./app2_data/             \
        --operation=get-certified           \
        --policy_store_file=policy_store    \
        --print_all=true
```

At this point, both versions of the app have their admission certificates.
You can look at the output of the terminal running simpleserver for output.

Now all we have to do is have the apps connect to each other for the final test.
The Certifier Service is no longer needed at this point.

## Step 14:  Run the apps to test trusted services

In app-as-a-server terminal run the following:
```shell
cd $EXAMPLE_DIR

$EXAMPLE_DIR/tpm_example_app.exe            \
        --data_dir=./app2_data/             \
        --operation=run-app-as-server       \
        --policy_store_file=policy_store    \
        --print_all=true
```

In app-as-a-client terminal run the following:
```shell
cd $EXAMPLE_DIR

$EXAMPLE_DIR/tpm_example_app.exe            \
        --data_dir=./app1_data/             \
        --operation=run-app-as-client       \
        --policy_store_file=policy_store    \
        --print_all=true
```

You should see the message "Hi from your secret server" in the client terminal
window and "Hi from your secret client".

If so, **your first Confidential Computing program using AMD TPM worked!**

------
## General notes on building and running an TPM-enabled VM under KVM

This section of the document gives some general instructions to configure and
setup an TPM enabled KVM and a compatible guest kernel.

As it stand today (_circa_ Oct. 2022), you will need to prepare the following
components to have TPM VMs under KVM:

  - Server BIOS/Firmware update to support TPM
  - AMD TPM firmware update if necessary
  - Linux kernel build with SNP support (for both the host and the guest)
  - Build the SNP enabled virtual firmware for the guest OS (OVMF)
  - Build the SNP enabled QEMU
  - Build guest and host TPM tools
  - A prepared guest disk image if desired

You first need to make sure your EPYC 7xx3 (or newer) server BIOS is updated to
the newest version with SNP support. This heavily depends on your server
vendor. But they should provide all the tools required for the job.

Once you have the newest BIOS/Firmware, you should see some processor settings
in the BIOS similar to:

- TPM-ES ASID space limit
- TPM SNP memory coverage

Set the ES limit and enable SNP memory coverage or reservation. The terms would
be different for different servers. The way to know whether you have enabled
the hardware properly is to boot the host with a Linux kernel with SNP support
and do the following:

```shell
vmware@tpm-snp1:~$ dmesg | grep -i TPM
[    3.291523] TPM: RMP table physical address 0x0000017e7fa00000 - 0x0000017fffafffff
[    6.513026] systemd[1]: Set hostname to <tpm-snp1>.
[    7.002618] ccp 0000:2a:00.1: tpm enabled
[   70.954551] ccp 0000:2a:00.1: TPM API:1.52 build:4
[   70.954564] ccp 0000:2a:00.1: TPM API:1.52 build:4
[   70.977781] TPM supported: 478 ASIDs
[   70.977782] TPM-ES and TPM supported: 31 ASIDs
```

You need to make sure you have the Reverse Map (RMP) table reserved and
TPM supported in the log. Otherwise, you missed something in the platform
configuration.

You might also need to update the TPM firmware. You should do this if you know
the firmware version is too low. Follow the instructions at:
https://github.com/AMDESE/AMDTPM/tree/tpm-snp-devel#upgrade-tpm-firmware

AMD helps with all the software and tools building steps with some scripts.
Make sure you clone it from: https://github.com/AMDESE/AMDTPM.git

Make sure you switch to the "tpm-snp-devel" branch. Follow the instructions in
the README and you are supposed to have everything ready. However, we encountered
tpmeral issues during the process. Hopefully these will be fixed by the time of
your attempt. Eventually, AMD will upstream all this TPM support to
Linux/QEMU/OVMF, etc. so that none of the building-from-the-sources steps are
necessary.

Most of the errors you will encounter are related to environment setup. When
the error log is clear, nothing can't be solved with a couple of Google
searches. However, due to how OVMF is built, you might encounter errors with
misleading messages. If you do encounter problems building OVMF with SNP
support, first make sure you have both IASL and NASM installed on your build
system. When the error occurs and you are at a loss, you should at least be
able to see the command failed.

You can manually retry the command after setting the EDK environment manually.
For instance:

```shell
$ cd AMDTPM/ovmf

$ . ./edksetup.sh

$ nice build -v --cmd-len=64436 -DDEBUG_ON_SERIAL_PORT=TRUE -n 256 -t GCC5 -a X64 -p OvmfPkg/OvmfPkgX64.dsc
```

This should give you more helpful info. If you encounter any errors with NASM
complaining about new x86 instructions, remember to build and install the
newest version of NASM. The one that comes with your Linux distro might be too
old.

When following the AMD script, if you have problems building the kernel,
or while generating the ramdisk or if you need special kernel configurations,
you can always build your own.

Clone the AMD Linux kernel source at: https://github.com/AMDESE/linux.git
Switch to the newest SNP branch. Currently, tpm-snp-5.19-rc5 would do.

Copy your host config to the source:

```shell
$ cp /boot/config-`uname -r` .config
```

Sift through the configuration differences and double check the TPM-related ones:

```shell
$ make oldconfig
$ make menuconfig
```

Compile the kernel and generate the deb packages:

```shell
$ make -j `getconf _NPROCESSORS_ONLN`
$ make -j deb-pkg LOCALVERSION=-custom
```

Whatever problems you encounter here should be straight-forward enough to fix.
You should have the following packages ready for install with `dpkg` after
everything is done:

```shell
linux-headers-5.19.0-rc5-next-20220706-custom_5.19.0-rc5-next-20220706-custom-4_amd64.deb
linux-image-5.19.0-rc5-next-20220706-custom_5.19.0-rc5-next-20220706-custom-4_amd64.deb
linux-image-5.19.0-rc5-next-20220706-custom-dbg_5.19.0-rc5-next-20220706-custom-4_amd64.deb
linux-libc-dev_5.19.0-rc5-next-20220706-custom-4_amd64.deb
```

Their identities should be self-explanatory. If you need to update the ramdisk,
you can do it after installing the linux-image-xxx package.

After the installation is done, create `/etc/modprobe.d/kvm.conf` and add the
following line to it:

```shell
options kvm_amd tpm-snp=1 tpm=1 tpm-es=1
```

Reboot your host Linux and verify SNP is ready. Try the dmesg above first and
do the following. Make sure you see the 'Y'.
```shell
$ cat /sys/module/kvm_amd/parameters/tpm_snp
Y
```

You should also be able to see the TPM device on the host at /dev/tpm. Now you
should have host, kernel, QEMU, and OVMF ready.

The last thing to do on the host is to install tpm-tool and retrieve the
platform certificates.

Clone the tpm-tool source at: https://github.com/AMDESE/tpm-tool.git

Follow the instructions and build the tool. Usage is also included in the
README. However, if for some reason you encountered some buffer overflow during
the certificate retrieval, try applying the following patch:

```shell
--- a/src/tpmcore_linux.cpp
+++ b/src/tpmcore_linux.cpp
@@ -680,7 +680,7 @@ int TPMDevice::generate_vcek_ask(const std::string output_folder,
    int cmd_ret = TPM_RET_UNSUPPORTED;
    int ioctl_ret = -1;
    tpm_user_data_get_id id_buf;
-    char cmd[235];
+    char cmd[512];
    std::string fmt;
    std::string output = "";
    std::string der_cert_w_path = output_folder + vcek_der_file;
```

Hopefully it will be fixed by the time of your attempt.

The next step is to create a guest. You do this as:
- Follow the general KVM/QEMU tutorial.
- After the guest is installed, install the guest linux
  kernel/header/libc packages in the guest.
- Locate your disk image at `/var/lib/libvirt/images`.

And it is time to launch your guest. Go to your AMDTPM repo and do the following:

```shell
$ ./launch-qemu.sh -hda /var/lib/libvirt/images/your_disk_image.qcow2 -tpm-snp
```

To get networking and VNC, we recommend updating the script to fix the options
(expecting some familiarity with what you are doing).
Here is just a reference:

```shell
add_opts "-netdev user,id=vmnic,hostfwd=tcp::8000-:22 -device e1000,netdev=vmnic,romfile="
add_opts "-monitor pty -monitor unix:monitor,server,nowait -vnc :0"
```

If you encountered problems with accessing `/dev/tpm`, make sure your SeLinux
or AppArmor is configured with proper permissions or just disable them. You
should be able to check these potential permission problems in dmesg.

If the guest boots successfully, you should be able to see the /dev/tpm-guest
device and the corresponding TPM-related messages in the guest OS kernel log:

```shell
$ dmesg | grep -i TPM
[    0.185529] Memory Encryption Features active: AMD TPM TPM-ES TPM
[    0.324674] TPM: Using SNP CPUID table, 31 entries present.
[    0.512198] TPM: SNP guest platform device initialized.
[    0.670153] tpm-guest tpm-guest: Initialized TPM guest driver (using vmpck_id 0)
[    1.373997] systemd[1]: Set hostname to <tpm-snp-vm>.
```

-------------------------------------------------------------------------
### Measuring an TPM kernel and initram

The easiest way to measure your SNP VM is using the open source
TPM-MEASUREMENT tool from IBM. You can clone the project from here:
https://github.com/IBM/tpm-snp-measure.git

```shell
$ tpm-snp-measure --help
usage: tpm-snp-measure [-h] [--version] [-v] --mode {tpm,tpmes,snp} [--vcpus N]
                       [--vcpu-type CPUTYPE] [--vcpu-sig VALUE] [--vcpu-family FAMILY]
                       [--vcpu-model MODEL] [--vcpu-stepping STEPPING] --ovmf PATH [--kernel PATH]
                       [--initrd PATH] [--append CMDLINE] [--output-format {hex,base64}]
```

You should use 'snp' for the mode option. N is the number of vcpus you
allocated for your SNP VM. You can also check it inside the VM. Instead of
using vcpu-sig / vcpu-family / vcpu-model / vcpu-stepping combinations, you
can use vcpu-type for the input. This is the vcpu type you specified when
you start your VM. You can check `/proc/cpuinfo` inside the guest too.

The `--ovmf` option is used to provide the OVMF firmware image of your VM if
you are booting with OVMF. Otherwise, you can use `--kernel` / `--initrd` /
`--append` to specify kernel image, initrd image, and kernel boot parameters.
You can get your guest boot parameters by reading `/proc/cmdline`.

If you used the launch-qemu.sh script from AMD, you are booting the VM using
OVMF. The kernel and initrd are all on the disk image. In this case, you can
get the measurement of your VM by issuing the following:
```shell
$ ./tpm-snp-measure.py --mode snp --vcpus=4 --vcpu-type=EPYC-v4 --ovmf=usr/local/share/qemu/OVMF_CODE.fd
```

The output will match the measurement field in the attestation report from your
TPM firmware.

-------------------------------------------------------------------------
