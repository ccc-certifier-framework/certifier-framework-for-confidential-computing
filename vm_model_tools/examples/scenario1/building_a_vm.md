#DRAFT IN Progress


# Building a VM

In the scripts, $CERTIFIER_ROOT is the top level directory for the Certifier
repository and $EXAMPLE_DIR as described above.  $EXAMPLE_DIR is this
directory containing the example application.  These are used by the
scripts.


## Overview and implementation alternatives

Everything upon which the security of your software relies must be
measured, including basic system software and libraries you rely on.
On Linux, we can protect and measure all that requires protection by
incorporating it into a small, in memory, filesystem provided with the
kernel boot image.

dmcrypt and verity

On most Linux systems, initramfs is dismounted and replaced by the
“system disk.”  On Cloudproxy Linux, initramfs not dismounted and serves
as the permanent system disk; we do this by changing the shell script in
initramfs that normally dismounts initramfs and mounts the “real” disk;
instead, we simply mount the “real disk” under intiramfs.  All
other disks are mounted under initramfs and should not be trusted.
This procedure provides the complete control over system components
and libraries we need.

In addition, we encrypt the page file and swap devices using dmcrypt.
Dmcrypt uses keys randomly generated at boot and we often require this
“swap disk” be inside the secure physical cage protecting the computer
(CPU and memory) running Cloudproxy. 



### Hypervisor

KVM ...

### Launching the VM and virtualization layer

grub

### Building vmlinuz

### Building initrd.img

1.	Download and unpack Linux kernel and busybox source
We use Busybox to provide a basic set of Unix utilities to use on the VM instance.

mkdir /tmp/tiny_linux
cd /tmp/tiny_linux
curl https://www.kernel.org/pub/linux/kernel/\
	v4.x/linux-4.0.3.tar.xz | tar xJf -
	curl https://busybox.net/downloads/busybox-1.23.2.tar.bz2 \
| tar xjf -

2.	Build busybox

mkdir -pv ../obj/busybox-x86
make O=../obj/busybox-x86 defconfig
make O=../obj/busybox-x86 menuconfig

The last command opens an interactive menu. We will select to build BusyBox statically to ensure it can run on the VM instance.

-> Busybox Settings
  -> Build Options
[ ] Build BusyBox as a static binary (no shared libs)

Select the above option, save your selection and quit the interactive menu.
Next we build Busybox as shown below.

cd ../obj/busybox-x86
	make -j2
	make install

3.	Build initrd image
Next we build the init RAM disk image.

mkdir -p /tmp/tiny_linux/initramfs/x86-busybox
cd /tmp/tiny_linux/initramfs/x86-busybox
mkdir -pv {bin,sbin,etc,proc,sys,usr/{bin,sbin}}
cp -av $TOP/obj/busybox-x86/_install/*

We will need an init script. The following minimal script works.

#!/bin/sh
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs -o mode=0755 udev /dev

exec /bin/sh

Save the above script in a file called init and make it executable.

chmod +x init

Finally we archive and compress this directory to create our initrd image.

find . -print0 \
    | cpio --null -ov --format=newc \
    | gzip -9 > /tmp/tiny_linux/obj/initramfs-busybox-x86.cpio.gz



### Measuring the VM


4.	Build linux kernel.

cd /tmp/tiny_linux/linux-4.0.3
make O=../obj/linux-x86-basic x86_64_defconfig
make O=../obj/linux-x86-basic kvmconfig
make O=../obj/linux-x86-basic -j2

The kernel image can be found at /tmp/tiny_linux/obj/linux-x86-basic/arch/x86_64/boot/bzImage

 
