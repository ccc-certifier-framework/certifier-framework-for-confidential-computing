# DRAFT in Progress


# Building a VM

In the scripts, $CERTIFIER_ROOT is the top level directory for the Certifier
repository.  $EXAMPLE_DIR is this directory containing the example
application.

Here we describe some aspect of the "building your own VM option" referred to
in instructions.md.

In an normal boot, the process is as follows:

The Boot Process Involving vmlinuz and initrd

  1. Loading Stage: For a nom VMM boot, the bootloader (like GRUB) loads both
  the vmlinuz and initrd into memory.  This is done by the VMM.

  2. Decompression of vmlinuz: The embedded routine in vmlinuz decompresses the kernel
  into memory.

  3. Handoff to initrd: Post-decompression, control is passed to the kernel, which then
  mounts the initrd as its initial root filesystem.



## Overview and implementation alternatives

Everything upon which the security of the certifier relies on including
the code and all critical data used by the VM and the (Linux)
VM policy must configured correctly and measured.  In a VM, any program that
can access the the Certifier primitives (like cf_utility.exe) must
be part of a measurement ans so should start up scripts.  These
measured quantities ahould not be mutable.

Building and using a VM to use the Certifier securely has several
components:

  1. You must use a secure measured hypervisor that is sev enlightened (when
  using SNP).  This hypervisor should be measured (to avoid single
  stepping attacks.
  2. You must build a bootable kernel consisting of a compressed kernel
  (vmlinuz) and an initial (and in some cases persistant) file system
  initramfs.
  3. You must supply the hypervisor with a virutalization shim and a
  command line for booting.

Most of this document describes step 2.

In our example, the VMM is KVM and "security" depends on minimizing
the kernel, preventing module loading and configuring external I/O
safely.  Doing this is an art in itself and, except for the actual
hypervisor stack we use, we don't have much to say here.  This is
step 1 above.

Step 3 is important.  Our only comment here is that while it is common
to use QEMU, we recommend minimizing the virtualization layer by
using Firecracker if appropriate.

As for step 2, there are several design options.  All must ensure that
startup script is measured and safe, and that all programs that are
called in the VM are safe.  Conceptually, the VM boot must ensure the
"policy key" certificate and programs are the ones expected and
immutable.  We take the approach described below but there are alternatives
(for example, one suggested by Paul England) that uses integrity protected
file system images.  Additionally, support for interacting with the
hypervisor including hypercalls must similarly be sxpected and immutable.

In our example build-vm.sh script, The way we ensure the above properties
is conceptually simple.

1. Our initrd.img contains the critical programs, policy key certificate
and all required libraries.  It is part of the "VM" measurement
must be measured, including basic system software and libraries you rely on.
On Linux, we can protect and measure all that requires protection by
incorporating it into a small, in memory, filesystem provided with the
kernel boot image called initrd.img.

On most Linux systems, initramfs is dismounted and replaced by the
“system disk”  during the boot. In out example VM, initramfs not
dismounted and serves as the permanent system disk. We do this by
changing the shell script in initramfs that normally dismounts initramfs
and mounts the “real” disk; instead, we simply mount the “real disk”
under intiramfs.  All other disks are mounted under initramfs and
should not be trusted.  This procedure provides the complete control
over system components and libraries we need.  It is important that
some writable file system is mounted and available, even if it
is untrusted, because most programs (including certifier programs)
will need storage.  In our case, initrd contains the startup scripts,
at a mimimum, all programs and libraries required by cf_utility,
key_server and key-client are in initrd as well as the libraries
they use.  As mentioned below in building the kernel, any program that
the OS allows to run that is not in initrd should be signed and checked.
The check must be a part of the Linux machine policy.  It is also
up to the kernel build (and dependent files in initrd) that the
firewalls, device permissions and other configuration is set properly.
In most kernels, no external logins should be permitted and certainly
no one should be able to log in as root.

Having done that, we have ensured that the measurement used in
the attestation guarentees the needed VM security properties.  In
the detailed instructions below, you can see how we provision the
policy cert, certifier libraries and measure the vm (and calling
command line) using sev-snp-measure.

The steps carried out by the build-vm.sh script to do this are
described in the two subsections "Building vmlinuz" and
"Building initrd.img".  They describe coping the policy
cert, programs, libraries, modifying the startup scripts
and configuring the Linux at startup (for example, to not
load additional modules).  You should be able to modify these
scripts to build your own VMs for an actual deployment.

For additional information on step 2, consult:
https://kpj.github.io/linux/KernelBuilding.html.

### Hypervisor

KVM ...

### Launching the VM and virtualization layer

Firecracker

### Building vmlinuz

These are the steps carried out by the build-vm.sh script.

1. Download the Linux source and configure the kernel:

```script
bash
tar -xvf linux-x.y.z.tar.xz
cd linux-x.y.z
make defconfig
make menuconfig # Customize drivers/options if needed
```

2. Compile the kernel:

```script
bash
make -j$(nproc)
```
The compressed kernel image will be created at arch/x86/boot/bzImage
(copy this to /boot/vmlinuz).

3. Install modules:

```script
bash
make modules_install
```

### Building initrd.img

1. Install the initram tools for Ubuntu:

a. update-initramfs, mkinitramfs
b. Mkinitrd (mkinitrd)
c. CPIO + Gzip

1. Create a directory and a preliminary init script:

```script
mkdir -p initramfs
mkdir -p initramfs/{bin,sbin,dev,proc,sys,etc,lib}
```

1. Download and unpack the busybox source
We use Busybox to provide a basic set of Unix utilities to use on the VM instance.

```script
mkdir /tmp/tiny_linux
cd /tmp/tiny_linux
curl https://www.kernel.org/pub/linux/kernel/\
	v4.x/linux-4.0.3.tar.xz | tar xJf -
	curl https://busybox.net/downloads/busybox-1.23.2.tar.bz2 \
| tar xjf -
```

2. Build busybox

```script
mkdir -pv ../obj/busybox-x86
make O=../obj/busybox-x86 defconfig
make O=../obj/busybox-x86 menuconfig
```

The last command opens an interactive menu. We will select to build BusyBox statically to ensure it can run on the VM instance.

-> Busybox Settings
  -> Build Options
[ ] Build BusyBox as a static binary (no shared libs)

Select the above option, save your selection and quit the interactive menu.
Next we build Busybox as shown below.

```script
cd ../obj/busybox-x86
	make -j2
	make install
```

3. Build initrd image
Next we build the init RAM disk image.

```script
mkdir -p /tmp/tiny_linux/initramfs/x86-busybox

cd /tmp/tiny_linux/initramfs/x86-busybox
mkdir -pv {bin,sbin,etc,proc,sys,usr/{bin,sbin}}
cp -av $TOP/obj/busybox-x86/_install/*
```

4. Configure initrd.img for your purpose:

You should have already obtained the policy certs for the
security domains this VM will participate in as well as
building the certifier and applications you want.

Now copy the applications, policy cert, certifier programs and
shared libraries into initrd.img.

```script
```

We will need an init script. The following minimal script works.

```script
#!/bin/sh
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs -o mode=0755 udev /dev

exec /bin/sh
```

Save the above script in a file called init and make it executable.

```script
chmod +x init
```

Finally we archive and compress this directory to create our initrd image.

```script
find . -print0 \
    | cpio --null -ov --format=newc \
    | gzip -9 > /tmp/tiny_linux/obj/initramfs-busybox-x86.cpio.gz
```

An alternative to building initrd.img from scratch is to start with an
exiting one and modify it, To inspect, modify, or inject custom scripts
into an existing initrd or initramfs image:

1. Extract the archive:
```script
mkdir custom_init && cd custom_init
zcat /boot/initrd.img-$(uname -r) | cpio -idmv
```

2. Edit contents (add custom binaries, config files, or modify the /init script).

3. Rebuild the archive:

```script
find . -print0 | cpio --null -o -H newc | gzip -c >
/boot/new_initrd.img
```

Now you can start at step 4 above.

### Measuring the VM

As set forth in instructions.md, you should have installed the ovmf files and
gotten the machine class ARK cert for policy building.  You will also have called
cpu-id.exe -sev-parameters to obtain the arguments for sev-snp-measue (or obtained
them some other way) and you should also also have the command line used for the VM
launch.  The measure vm script uses them to call:

```script
      $MEASURE_PROG_DIR/sev-snp-measure.py --mode snp --vcpu-family $CPU_FAMILY --vcpu-model $CPU_MODEL --vcpu-stepping $CPU_STEPPING \
        --ovmf $OVMF_LOCATION --kernel $VM_KERNEL_FILE_NAME --initrd $VM_INITRAM_FILE_NAME  \
```

to obtain the measurement.

 
