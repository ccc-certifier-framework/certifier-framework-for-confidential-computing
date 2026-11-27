# Using SEV VM's with the Certifier

In this description, $CERTIFIER_ROOT is the top level directory for the Certifier
repository.  $EXAMPLE_DIR is this directory containing the example application
(like $CERTIFIER_ROOT/vm_model_tools/examples/scenario1.

## Overview

Everything upon which the security of the certifier relies on including
the code and all critical data used by the VM and the (Linux)
VM policy must configured correctly and measured.  In a VM, any program that
can access the the Certifier primitives (like cf_utility.exe) must
be part of a measurement ans so should start up scripts as well as
the policy certificates for the security domains the VM operates in.
These measured quantities ahould not be mutable.

For the tests in this directory, the scripts do all this.  This
document helps describe those scripts and can serve as a guide for
building your own VM.

The approach described here is to build a locked-down and entirely memory
resident operating system and system disk containing all security related
programs and configuration.  Measurement then consists of measuring
the kernel image (vmlinuz) and the filesystem (initrd.img).

Building a VM to use the Certifier using this approach requires
You must build a bootable kernel consisting of a compressed kernel
(vmlinuz) and an initial (and in some cases persistant) file system
initrd (or initramfs, we use these terms interchangeably although there
are some differences.

To run such a VM:

  1. You must use a secure measured hypervisor that is sev enlightened (when
  using SNP).  This hypervisor should be measured (to avoid single
  stepping attacks).  {describe in appendix later]
  2. Use the bootable kernel consisting of a compressed kernel
  (vmlinuz) and an initial (and in some cases persistant) file system
  initrdd, described above.
  3. You must supply the hypervisor with a virutalization shim and a
  command line for the kernel you are booting.

## Step by step instructions

First, you will need a "small" Linux OS.  You can build your own but
we will start with an existing one.  We use a small Debian OS called
Trixie, which is an AMD SEV-enabled server (either bare metal or a
confidential VM guest), based on 64 bit Debian 13.

You can start with an ISO and install it into a real or virtual disk
(for Trixie, get it at Link: https://www.debian.org/download) or a
prebuilt virtual disk (get it at https://cdimage.debian.org/cdimage/cloud/).
We'll do the latter.

### Step 1 - Download the image

Use a browser to download a qcow image.  You should get a file named something
like debian-13-generic-amd64-20261123-2671.qcow2.

Copy the VHD into your images.
```script
```

### Step 2 - Run the image under a hypervisor

### Step 3 - Copy the programs, scripts, files and libraries you need to the VM image

### Step 4 - Fix the SSH and password configuration

### Step 5 - Unpack initrd

### Step 6 - Copy the needed files into initrd

### Step 7 - Modify the init script in the initrd filesystem

### Step 8 - Repack initrd

### Step 9 - Copy the resulting kernel image and initrd for distribution




