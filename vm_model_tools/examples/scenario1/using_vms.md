# Using SEV VM's with the Certifier

In this description, we use a number if exported variables.

$HOST_CERTIFIER_ROOT is the top level directory for the Certifier
repository on a development machine.  This is
~/src/github.com/certifier-framework-for-confidential-computing on
my machine.

$HOST_EXAMPLE_DIR is the directory containing the example application
and executables. This is $HOST_CERTIFIER_ROOT/ vm_model_tools/examples/scenario1
for me.

$VM_CERTIFIER_ROOT is the top level directory for the Certifier files
on the virtual disk.  This is /home/certifier in my scripts.

$VM_INITRAM_DIR is the directory on the virtual disk where we unpack
initrd and modify it.  It is $VM_CERTIFIER_ROOT/custom_init in my
tests.

We also use:

  $HOST_FS to mean "/" on the developer's machine.
  $VM_FS to mean "/" on the developer's machine.

Here are the defines

```script
export HOST_CERTIFIER_ROOT=/home/jlm/src/github.com/certifier-framework-for-confidential-computing
export HOST_EXAMPLE_DIR=$HOST_CERTIFIER_ROOT/vm_model_tools/examples/scenario1
export VM_CERTIFIER_ROOT=/home/certifier
export VM_INITRAM_DIR=$VM_FS/tmp
export VM_INITRAM_CUSTOMER_FOLDER=$VM_INITRAM_DIR/custom_init
mkdir $VM_INITRAM_CUSTOMER_FOLDER
export HOST_FS /    # on the development machine
export VM_FS /      # in the vm
```


## Overview

Everything upon which the security of the certifier relies on including
the code and all critical data used by the VM and the (Linux)
VM policy must configured correctly and measured.  In a VM, any program that
can access the the Certifier primitives (like cf_utility.exe) must
be part of a measurement ans so should start up scripts as well as
the policy certificates for the security domains the VM operates in.
These measured quantities ahould not be mutable.

For the tests in $HOST_EXAMPLE_DIR, the scripts do all this.  This
document helps describe those scripts and can serve as a guide for
building your own VM.

The approach described here is to build a locked-down and entirely memory
resident operating system and system disk containing all security related
programs and configuration.  Measurement then consists of measuring
the kernel image (vmlinuz) and the filesystem (initrd.img).  For testing,
we allow root logind via ssh but in a real VM you'd NOT do that.

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

To build the VM in step 2, you will need to start with a "small" Linux OS.
You can build your own but we will start with an existing one.  We use a
small Debian OS called Trixie, which is an AMD SEV-enabled server
(either bare metal or a confidential VM guest), based on 64 bit Debian 13.

You could start with an ISO and install it into a real or virtual disk
(for Trixie, get it at Link: https://www.debian.org/download) but we start
with a prebuilt virtual disk (get it at
https://cdimage.debian.org/cdimage/cloud/).  We'll do the latter.

Instructions for building and running the VM follow.


## Install KVM (if you haven't already)

Most people already have a KVM installed.  If not, do the following on
your development machine.

Install the required packages, make sure KVM is sev enabled.

```script
sudo apt -y install bridge-utils cpu-checker libvirt-clients libvirt-daemon qemu qemu-kvm cpu-checker qemu-img libvirt-daemon-system qemu-utils
'''

Step 2: Check virtualization capabilities

Execute the following command to make sure your processor supports virtualisation capabilities:

```script
  kvm-ok
  modinfo kvm-amd
  lsmod | grep kvm
  qemu-system-x86_64 --version
```
The output of this command and indicates whether KVM can be used or not:

INFO: /dev/kvm exists
KVM acceleration can be used

Setup guest services:

```script
  sudo systemctl start libvirtd  # if it hasn't already started
```

1. Check Virtualization Support

```script
egrep -c '(vmx|svm)' /proc/cpuinfo
lscpu | grep Virtualization
# how many cpu's do you have?
nproc
```

2. Check KVM module is available

```script
lsmod | grep kvm
```

3. If virtualization is disabled, enable it in BIOS/UEFI settings.

4. Install KVM and Tools

```script
# Install
sudo apt update
sudo apt install qemu-system libvirt-daemon-system libvirt-clients bridge-utils virtinst virt-manager -y
# Verify installation
virsh --version
qemu-system-x86_64 --version
```

5. Configure User Permissions

```script
# Add your user to libvirt and kvm groups
sudo usermod -aG libvirt $USER
sudo usermod -aG kvm $USER
```

6. Apply changes (or log out and back in)

```script
sudo apt install util-linux-extra
newgrp libvirt
# Start libvirt daemon
sudo systemctl start libvirtd
```

7. Enable on boot
```script
sudo systemctl enable libvirtd
```

8. Check status
```script
sudo systemctl status libvirtd
```

10. Check KVM is working

```script
virsh list --all
```

11. Check default network

```script
virsh net-list --all
```

12. If default network is inactive, start it

```script
sudo virsh net-start default
sudo virsh net-autostart default
```

To run VM's use virt-manager or virtsh

```script
virt-manager
    1. Click "Create a new virtual machine"
    2. Select installation method (ISO)
    3. Choose OS type and version
    4. Allocate RAM and CPUs
    5. Create disk image
    6. Name VM and configure network
    7. Begin installation

virsh list --all
```

Some commands you might use are:

```script
# List all VMs
virsh list --all

# Start VM
virsh start ubuntu-vm

# Shutdown VM gracefully
virsh shutdown ubuntu-vm

# Force stop VM
virsh destroy ubuntu-vm

# Reboot VM
virsh reboot ubuntu-vm

# Suspend VM
virsh suspend ubuntu-vm

# Resume VM
virsh resume ubuntu-vm
VM Information

# VM details
virsh dominfo ubuntu-vm

# VM configuration XML
virsh dumpxml ubuntu-vm

# Console access
virsh console ubuntu-vm

# VNC display info
virsh vncdisplay ubuntu-vm
Delete VM

# Remove VM (keeps disk)
virsh undefine ubuntu-vm

# Remove VM and disk
virsh undefine ubuntu-vm --remove-all-storage
```

To create a vm from an ISO (untested):

```script
virt-install \
  --name ubuntu-vm \
  --ram 2048 \
  --vcpus 2 \
    --disk path=/var/lib/libvirt/images/ubuntu-vm.qcow2,size=20 \
  --os-variant ubuntu22.04 \
  --network network=default \
  --graphics vnc,listen=0.0.0.0 \
  --cdrom /path/to/ubuntu-22.04-live-server-amd64.iso \
  --boot cdrom

or

# TODO: Change this
openstack image create \
    --container-format bare \
    --disk-format qcow2 \
    --property hw_disk_bus=scsi \
    --property hw_scsi_model=virtio-scsi \
    --property os_type=linux \
    --property os_distro=debian \
    --property os_admin_user=debian \
    --property os_version='10.9.1' \
    --public \
    --file debian-13-generic-amd64-20250811-2201.qcow2 \
    debian-13-generic-amd64-20250811-2201.qcow2
```


## Step by step instructions without cloud-init


### Step 1 - Download the image and customize it

Use a browser to download a qcow image.  You should get a file named something
like debian-13-generic-amd64-20261123-2671.qcow2.  The installation guide
is at https://www.debian.org/releases/trixie/installmanual.

Let's assume the image is in ~/Downloads.

First, fix the image so you can log in.  You may first have to install a tool:

```script
apt install guestfs-tools
```
```script

virt-customize -a /home/jlm/Downloads/debian-13-generic-amd64-20261123-2671.qcow2 \
  --root-password password:certifier \
  --ssh-inject root:file:/home/jlm/.ssh/id_rsa.pub \
  --timezone America/Los_Angeles \
  --hostname certifier-vm-host

#   You can copy files here too
#     --upload local-config.conf:/etc/app/config.conf
```

Next, import the image as a VM in your KVM using virt-manager.
You may have to be root to do this.  I called my vm jlm-test-vm.


### Step 2 - Run the VHD under a hypervisor

Start the vm:

```script
virtsh jlm-test-vm
```

Now log in as root and add certifier user:

```script
adduser certifier
usermod -aG sudo certifier
```

We need one more program for testing that we should compile:

```script
cd  $HOST_EXAMPLE_DIR
g++ -o startup_program.exe startup_program.cc
```

Note that the NW installed is virbr0.


### Step 3 - Copy the programs, scripts, files and libraries you need to the VM image

Copy from the host machine with the certifier to the VM.

In the runnig VM you started up:
```script
  mkdir $VM_CERTIFIER_ROOT/bin
  chown certifier $VM_CERTIFIER_ROOT/bin
  mkdir $VM_CERTIFIER_ROOT/app
  chown certifier $VM_CERTIFIER_ROOT/app

  cp $HOST_CERTIFIER_ROOT/vm_model_tools/src/cf_key_server.exe $VM_CERTIFIER_ROOT/bin
  cp $HOST_CERTIFIER_ROOT/vm_model_tools/src/cf_key_client.exe $VM_CERTIFIER_ROOT/bin
  cp $HOST_CERTIFIER_ROOT/vm_model_tools/src/cf_utilities.exe $VM_CERTIFIER_ROOT/bin
  cp $HOST_CERTIFIER_ROOT/utilities/cpuid.exe $VM_CERTIFIER_ROOT/bin
  cp $HOST_EXAMPLE_DIR/startup_program.exe $VM_CERTIFIER_ROOT/bin
  cp $SNPTOOL_DIR/snpguest $VM_CERTIFIER_ROOT/bin
  chmod +x $VM_CERTIFIER_ROOT/bin/*

  cp $HOST_EXAMPLE_DIR/provisioning/$POLICY_CERT_FILE_NAME $VM_FS/etc/$POLICY_CERT_FILE_NAME
  chmod 0644 $VM_FS/etc/$POLICY_CERT_FILE_NAME

  # Copy (or make) start-script.sh to call at init
  cp $HOST_EXAMPLE_DIR/start-script.sh $VM_FS/scripts

  # Your startup-script will also have to obtain the ARK, ASK and
  # VCERT certificates on the real machine.

  # Copy needed libraries into VM filesystem
  # libraries needed will be in $HOST_FS/usr/lib/x86_64-linux-gnu
  export HOST_LIB=$HOST_FS/usr/lib/x86_64-linux-gnu
  export VM_LIB=$VM_FS/usr/lib/x86_64-linux-gnu
  cp $HOST_LIB/libprotobuf.so.32 $HOST_LIB
  cp $HOST_LIB/libgflags.so.2.2 $HOST_LIB
  cp $HOST_LIB/libcrypto.so.3 $HOST_LIB
  cp $HOST_LIB/libssl.so.3 $HOST_LIB
  cp $HOST_LIB/libuuid.so.1 $HOST_LIB
  cp $HOST_LIB/libstdc++.so.6 $HOST_LIB
  cp $HOST_LIB/libc.so.6 $HOST_LIB
  cp $HOST_LIB/libz.so.1 $HOST_LIB
```

### Step 4 - Unpack initrd

You should install the intram tools:

```script
#  Install the initram tools for Ubuntu:

  # Install update-initramfs, mkinitramfs and mkinitrd
  # as root
  apt update
  apt install initramfs-tools

  # Install cpio and gzip
  apt install cpio
  apt-get install gzip
```

Then extract the archive:

```script
  pushd $VM_INITRAM_CUSTOMER_FOLDER
    unmkinitramfs $VM_FS/boot/initrd.img $VM_INTIRAM_DIR
    ls -l .
  popd
```

You should see something like this:

  lrwxrwxrwx  1 jlm jlm    7 Nov  3 12:08 bin -> usr/bin
  drwxr-xr-x  3 jlm jlm 4096 Nov  3 12:08 conf
  drwxr-xr-x 10 jlm jlm 4096 Nov  3 12:08 etc
  -rwxr-xr-x  1 jlm jlm 7827 Apr  2  2026 init
  drwxr-xr-x  3 jlm jlm 4096 Nov  3  2025 kernel
  lrwxrwxrwx  1 jlm jlm    7 Nov  3 12:08 lib -> usr/lib
  lrwxrwxrwx  1 jlm jlm    9 Nov  3 12:08 lib64 -> usr/lib64
  drwxr-xr-x  2 jlm jlm 4096 Nov  3 12:08 run
  lrwxrwxrwx  1 jlm jlm    8 Nov  3 12:08 sbin -> usr/sbin
  drwxr-xr-x  9 jlm jlm 4096 Nov  3 12:08 scripts
  drwxr-xr-x  9 jlm jlm 4096 Nov  3 12:08 usr
  drwxr-xr-x  4 jlm jlm 4096 Nov  3 12:08 var


### Step 5 - Copy the needed files into initrd

Copy the files needed in initrd:

```script
cp -r $VM_FS/etc $VM_INITRAM_CUSTOM_FOLDER/etc
cp -r $VM_FS/usr $VM_INITRAM_CUSTOM_FOLDER/usr
cp -r $VM_FS/home /$VM_INITRAM_CUSTOM_FOLDER/home
cp $HOST_EXAMPLE_DIR/provisioning/$POLICY_CERT_FILE_NAME $VM_FS/etc/$POLICY_CERT_FILE_NAME
```

Set the domain names:

``script
cat $DOMAIN_NAME >> $VM_INITRAM_CUSTOM_FOLDER/etc/domains
cat $startup_program.exe $VM_INITRAM_CUSTOM_FOLDER/usr/bin
chmod +x $VM_INITRAM_CUSTOM_FOLDER/usr/bin/startup_program.exe
cp $VM_FS/etc/$POLICY_CERT_FILE_NAME $INITRAM_CUSTOM_FOLDER/etc
```

### Step 6 - Modify the init script in the initrd filesystem

Changes to init ($VM_INITRAM_CUSTOM_FOLDER/init)
  Change default.target to multi-user.target in /etc/systemd/system/default.target.
  Towards the bottom of the standard init initrd, before run_scripts /scripts/init-bottom:


### Step 7 - Repack initrd

Finally we will recompress initrd.img.

You may need to inject special drivers for your VM.  Make sure
your module names (e.g., virtio_blk, virtio_net) are listed in
/etc/initramfs-tools/modules, then update:

```script
  pushd $VM_INITRAM_CUSTOM_FOLDER
    update-initramfs -u -k all
  popd
```
Now, rebuild the archive:

```script
  find . -print0 | cpio --null -o -H newc | gzip -c > $VMINITRAM_DIR/new_initrd.img
```

### Step 8 - Copy the resulting kernel image and initrd for distribution

```script
pushd $VM_INITRAM_DIR
cd ..
scp $VM_INITRAM_DIR/new_init.img certifier@vm-certifier-host:$HOST_EXAMPLE_DIR
scp $VM_FS/boot/vimlinz certifier@vm-certifier-host:$HOST_EXAMPLE_DIR
```

Now you have the files for your vm.

### Step 9 --- Run the new vm

Follow the instructions in instructions.md for the test.  You'll need the ip address for
the test.  You can get it as follows:

```script
ip address
```


## Step by step instructions with cloud-init

Paul


## Measuring the VM you built

As indicated in instructions.md, you should have installed the ovmf files and
gotten the machine class ARK cert for policy building.  You will also have called
cpu-id.exe -sev-parameters to obtain the arguments for sev-snp-measue (or obtained
them some other way) and you should also also have the command line used for the VM
launch.  The measure vm script uses them to call:

```script
 $MEASURE_PROG_DIR/sev-snp-measure.py --mode snp --vcpu-family $CPU_FAMILY --vcpu-model $CPU_MODEL --vcpu-stepping $CPU_STEPPING \
        --ovmf $OVMF_LOCATION --kernel $VM_KERNEL_FILE_NAME --initrd $VM_INITRAM_FILE_NAME  \
```
to obtain the measurement.

