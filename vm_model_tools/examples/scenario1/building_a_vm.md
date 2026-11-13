# Building a VM

In the scripts, $CERTIFIER_ROOT is the top level directory for the Certifier
repository.  $EXAMPLE_DIR is this directory containing the example
application.

Here we describe some aspect of the "building your own VM option" referred to
in instructions.md.

In an normal boot, the process is as follows:

  1. Loading Stage: For a non VMM boot, the bootloader (like GRUB) loads both
  the vmlinuz and initrd into memory.  This is done by the VMM.

  2. Decompress vmlinuz: The embedded routine in vmlinuz decompresses the kernel
  into memory.

  3. Handoff to initrd: Post-decompression, control is passed to the kernel, which then
  mounts the initrd as its initial root filesystem.


## Overview

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
  stepping attacks).  {describe in appendix later]
  2. You must build a bootable kernel consisting of a compressed kernel
  (vmlinuz) and an initial (and in some cases persistant) file system
  initramfs.
  3. You must supply the hypervisor with a virutalization shim and a
  command line for the kernel you are booting.

Most of this document describes step 2.

In our example, the VMM is KVM and "security" depends on minimizing
the kernel, preventing module loading and configuring external I/O
safely.  Doing this is an art in itself and, except for the actual
hypervisor stack we use, we don't have much to say here.  This is
step 1 above.

Step 3 is important.  Our only comment here is that while it is common
to use QEMU, we are investigating using Firecracker, which does not
currently support SEV nor several important "real" instructions (e.g.-
related to hardware based entropy for RNG) .

As for step 2, there are several design options. The approach described
here, and used in the example scripts, is to build a locked-down and
entirely memory resident operating system and system disk containing all
security related programs and configuration.  Other approaches are possible
[add reference].

Using our approach, we  must ensure that startup script is measured
and safe, that all programs that are called in the VM are safe.  In
addition, the we must ensure the "policy key" certificates are part of
the measurement and accessible to the certifier.

In our approach the VM build is implemented by build-vm.sh script
which is vmlinuz focused and copy-vm-files.sh which build the
memory resident file system in initrd.img.

1. Our initrd.img contains all of Linux userland including
the critical runable programs, the policy key certificate(s) for
the security domain will be certified in, and all required libraries.
It is part of the "VM" measurement must be measured.

On most Linux systems, initrd.img (also called initramfs, sometimes)
is dismounted and replaced by the “system disk” late in the boot.
In our approach,, initrd.img is never dismounted and serves as the
permanent system disk; any additional file system is mounted in this
foundation file system and is generally "not trusted." We do this by
changing the shell script (init) in initrd.img.  This procedure provides
the complete control over system components and libraries we need and
incorporates them in the VM measurement.  It is important that
some writable file system is mounted and available, even if it
is untrusted, because most programs (including certifier programs)
will need storage.

As a result, initrd contains the startup scripts, at a mimimum, all programs
and libraries required by cf_utility, key_server and key-client
as well as the libraries they use.   If you need have additional
programs that will employ the certifier primitivess, they and the
libraries they rely on must also be in initrd.img. In fact, any program that
the OS allows to run that is not in initrd should be signed and checked.
This check must be a part of the Linux machine
policy.  It is also up to the kernel build (and dependent files in initrd) that
the firewalls, device permissions and other configuration is set properly.
In most kernels, no external logins should be permitted, no one should be able
to log in as root and not modules should be loaded after boot (unless signed and
checked in accordance with the securoty domain policy.

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
https://kpj.github.io/linux/KernelBuilding.html.  But first,
we describe how to boot your VM using KVM.

A focused view of this document is that it explains what we did
in our test scripts to build a vm that meets out needs but I hope
it can serve as a guide to help you build your own VMs if you
use this approach for measurement integrity and contrrol.

Note:  We use the terms "initrd.img" and "initramfs" interchangably but
they are not.  The older term is initramfs which is historically a
tmpfs space sed before the OS boots with the "real" fs.

initrd.img allows for more
difficult and complex boot options such as LVM-on-root, booting from
an NFS mount, etc.  As others have done (Android, http://www.tinycorelinux.net,
and our previous cloudproxy), we actually retain this file system as root.

The most obvious difference between initrd and intramfs is that an initrd is loaded
into a ramdisk. It consists of an actual filesystem (typically ext2).
An initramfs, on the other hand, is not a filesystem.  It is simply a (compressed)
cpio archive (of type newc) which is unpacked into a tmpfs.
This has a side-effect of making initramfs loadable a little earlier in
the kernel boot process than an initrd. The size of the initramfs in memory
is smaller, since the kernel can adapt the size of the tmpfs to what is actually
loaded, rather than relying on predefined ramdisk sizes, and it can also
clean up the ram that was used whereas ramdisks tend to remain in use
(due to details of the pivot_root implementation).

Since an initrd is an actual filesystem unpacked into ram, the root device must
actually be the ramdisk (which is good for us). For an initramfs, there is a
kernel "rootfs" which becomes the tmpfs that the initramfs is unpacked into
(if the kernel loads an initramfs; if not, then the rootfs is simply the filesystem
specified via the root= kernel boot parameter), but this interim rootfs should not
be specified as the root= boot parameter.  This means that you can still pass your
real root device to the kernel when using an initramfs. With an initrd, you have
to process what the real root device is yourself. Also, since the "real" root device
with an initrd is the ramdisk, the kernel has to switch root devices from one
real device (the ramdisk) to the other (your real root). In the case of an initramfs,
the initramfs space (the tmpfs) is not a real device, so the kernel doesn't switch
real devices. Thus, while the command pivot_root is used with an initrd, a different
command has to be used for an initramfs. Busybox provides switch_root to accomplish
this, while klibc offers new_root. This article will focus on busybox (and ignore klibc).

As a result of all this, the initial "init" file for intrd is more complex than
the previous "initramfs" script.  We actually use initrd and these instructions are
specific to that.


## Hypervisor

First, install the required packages, make sure KVM is sev enabled.

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

### Step by step for KVM from third tutorial

This section is long and informative but if you're in a hurry,
skip to "What you actually need to do to run the tests."

There are number of tutorials on line like:

1 .https://www.youtube.com/watch?v=_X1imTzohsY
2. https://docs.beamnetworks.dev/en/kvm/create-vm-full
3. https://oneuptime.com/blog/post/2026-01-15-setup-kvm-qemu-virtualization-ubuntu/view
4. QEMU & KVM Virtualization, Vexel

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

9. Verify KVM Installation
```script
# Tell libvirt to use the system-wide hypervisor
# instead of using session mode that runs VMs under
# your personal user account
export LIBVIRT_DEFAULT_URI='qemu:///system'
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


13. Create Virtual Machine (another way) using virt-install (CLI)

```script
# Create VM from ISO
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
```
# or

# download iso using a browser

# build vm
virt-manager


14. Create Virtual Machine (another way) using virt-install (CLI)
Using virt-manager (GUI)

```script
virt-manager
    1. Click "Create a new virtual machine"
    2. Select installation method (ISO)
    3. Choose OS type and version
    4. Allocate RAM and CPUs
    5. Create disk image
    6. Name VM and configure network
    7. Begin installation

15. Commands with virtsh

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
Networking Configuration
Default NAT Network
VMs use NAT by default, sharing the host's IP:

# View default network
virsh net-dumpxml default

virsh domiflist ubuntu-vm

# Bridged Network
# For VMs to have their own IP on the LAN:
# Create bridge configuration
# sudo nano /etc/netplan/01-netcfg.yaml

# network:
#   version: 2
#   renderer: networkd
#   ethernets:
#     enp0s3:
#       dhcp4: false
#   bridges:
#     br0:
#       interfaces: [enp0s3]
#       dhcp4: true
#       parameters:
#         stp: false
#         forward-delay: 0

# Apply configuration
sudo netplan apply

# Define bridge network for libvirt
sudo nano /tmp/bridge-network.xml

<network>
  <name>br0-network</name>
  <forward mode="bridge"/>
  <bridge name="br0"/>
</network>


# Create and start bridge network
virsh net-define /tmp/bridge-network.xml
virsh net-start br0-network
virsh net-autostart br0-network
Storage Management
Storage Pools

# List storage pools
virsh pool-list --all

22.  Create new storage pool
virsh pool-define-as mypool dir --target /data/vms

23. Start and autostart pool

virsh pool-start mypool
virsh pool-autostart mypool

# List volumes in pool
virsh vol-list mypool
Disk Images

# Create disk image
qemu-img create -f qcow2 /var/lib/libvirt/images/newdisk.qcow2 50G

# Check image info
qemu-img info /var/lib/libvirt/images/newdisk.qcow2

# Resize disk (VM must be off)
qemu-img resize /var/lib/libvirt/images/ubuntu-vm.qcow2 +10G

# Convert image format
qemu-img convert -f raw -O qcow2 disk.raw disk.qcow2
Attach Disk to VM
# Attach disk (persistent)
virsh attach-disk ubuntu-vm /var/lib/libvirt/images/data.qcow2 vdb --persistent

# Detach disk
virsh detach-disk ubuntu-vm vdb --persistent
Snapshots

# Create snapshot
virsh snapshot-create-as ubuntu-vm snap1 "Before update"

# List snapshots
virsh snapshot-list ubuntu-vm

# Revert to snapshot
virsh snapshot-revert ubuntu-vm snap1

# Delete snapshot
virsh snapshot-delete ubuntu-vm snap1
Resource Management
CPU and Memory

# Set vCPUs (online)
virsh setvcpus ubuntu-vm 4 --live

# Set maximum vCPUs
virsh setvcpus ubuntu-vm 8 --config --maximum

# Set memory (live, in KiB)
virsh setmem ubuntu-vm 4194304 --live

# Edit VM configuration
virsh edit ubuntu-vm
CPU Pinning
Pin vCPUs to specific host CPUs:

virsh edit ubuntu-vm
# Add to the domain XML:
<cputune>
  <vcpupin vcpu='0' cpuset='0'/>
  <vcpupin vcpu='1' cpuset='1'/>
</cputune>

# Clone VM (source must be off)
virt-clone --original ubuntu-vm --name ubuntu-vm-clone --auto-clone

# Clone with specific disk path
virt-clone --original ubuntu-vm --name ubuntu-vm-clone --file /var/lib/libvirt/images/ubuntu-vm-clone.qcow2
Migration
Live Migration (requires shared storage)

# Migrate VM to another host
virsh migrate --live ubuntu-vm qemu+ssh://destination-host/system
#Offline Migration
# Dump VM XML
virsh dumpxml ubuntu-vm > ubuntu-vm.xml

# Copy disk and XML to destination
scp /var/lib/libvirt/images/ubuntu-vm.qcow2 dest:/var/lib/libvirt/images/
scp ubuntu-vm.xml dest:

# On destination, define VM
virsh define ubuntu-vm.xml
Performance Tuning
Enable Hugepages

# Check current hugepages
cat /proc/meminfo | grep Huge

# Configure hugepages (2MB pages)
echo 1024 | sudo tee /proc/sys/vm/nr_hugepages

# Make permanent
#echo "vm.nr_hugepages=1024" | sudo tee -a /etc/sysctl.conf
#Enable in VM configuration:

<memoryBacking>
  <hugepages/>
</memoryBacking>
VirtIO Drivers
Use VirtIO for best performance:

<disk type='file' device='disk'>
  <driver name='qemu' type='qcow2'/>
  <source file='/var/lib/libvirt/images/vm.qcow2'/>
  <target dev='vda' bus='virtio'/>
</disk>

<interface type='network'>
  <source network='default'/>
  <model type='virtio'/>
</interface>
Troubleshooting
VM Won't Start
What you actually need to do to run the tests

# Check libvirtd logs
sudo journalctl -u libvirtd -n 50

# Check VM logs
sudo cat /var/log/libvirt/qemu/ubuntu-vm.log
Network Issues

# Restart default network
virsh net-destroy default
virsh net-start default

# Check iptables rules
sudo iptables -L -n | grep virbr

# Fix image permissions
sudo chown libvirt-qemu:kvm /var/lib/libvirt/images/*.qcow2
sudo chmod 600 /var/lib/libvirt/images/*.qcow2
```

## Building vmlinuz and initrd.img

A Linux VM cosist of two components, a kernal file, called vmlinuz and
an in memory storage component called initrd.img.

In the scripts we use a very simple procedure to build these.

###  The kernal (vmlinuz)

We simply copy the existing kernal from the existing machine which
is located at /boot/vmlinuz.

For most use cases you will build your own, compiling the Linux source.
You can configure your kernel by using a utility, menuconfig.
The master file for configuration is the hidden file .config which is placed
in the root of the build tree. If unpacked your source into the directory
/usr/src/linux-source-xyz, so the full pathname of the config file is
/usr/src/linux-source-xyz/.config. To install the configuration, you must run
a script, for example make oldconfig, to integrate into the Kconfig files
that are scattered around the build tree those options specified in .config.
Other scripts are make defconfig, which creates a configuration based on the
current platform, or make menuconfig that presents a curses
interface to make build selections. You will need ncurses-dev installed for
menuconfig to work.

Here are things you should remember about building a kernal:

  1. Make it as small as possible.  Don't include any software you don't trust.
  2. Don't allow any loadable modules.
  3. As we will see below, the normal system disk is mounted at /writabledisk
     so some scripts and variables you use in programs.
  4. You can download source, configure, compile and install modules as follows:

```script

    tar -xvf linux-x.y.z.tar.xz
    cd linux-x.y.z
    make defconfig
    make menuconfig # Customize drivers/options if needed

    make -j$(nproc)

    make modules_install INSTALL_MOD_PATH=/path/to/rootfs
```

The compressed kernel image will be created at arch/x86/boot/bzImage
(copy this to /boot/vmlinuz).  The scripts that build the VM are in build-vm.sh.


### Building initrd.img

The script also starts with an existing initd.img although you can
build your own from scratch.  Before the script run (or you build it yourself,
you must install the tools:

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
  mkdir custom_init && cd custom_init
  unmkinitramfs ../initrd.img .
  ls -l .
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

We will be modifying the init script "init".  Sample changes are in
$EXAMPLE_DIR/init.new.

We need to modify the initial fs by adding binaries, libraries and script
particular to the VM as described below. We also need to modify the
init and passwd files as described below:

```script

  # a useful variable
  export ORIG_FS_DIR=$EXAMPLE_DIR/custom_init

  # Copy (or modify existing) /etc/passwd to prevent root login and add
  # "relyingparty" resticted user
  cp $EXAMPLE_DIR/passwd.new $ORIG_FS_DIR/etc/passwd

  # Copy binaries, including CF utilities and programs including
  # cf_utilities, cf_key_server, cf_key_client.  The programs you
  # load into initrd should either be the only ones that can run or
  # you must make sure using another mechanism that only trusted
  # programs can execute (especially as root).  You will also have
  # to copy other programs (and libraries, seee below), you use but
  # those will depend on what your VM does.  In our script, these
  # are the only programs that run resulting in a fairly uninteresting
  # VM.

  cp $CERTIFIER_ROOT/vm_model_tools/src/cf_key_server.exe $ORIG_FS_DIR/usr/bin
  cp $CERTIFIER_ROOT/vm_model_tools/src/cf_key_client.exe $ORIG_FS_DIR/usr/bin
  cp $CERTIFIER_ROOT/vm_model_tools/src/cf_utilities.exe $ORIG_FS_DIR/usr/bin
  cp $CERTIFIER_ROOT/utilities/cpuid.exe usr/bin
  cp $EXAMPLE_DIR/startup_program.exe $ORIG_FS_DIR/bin

  # Copy needed libraries
  # Find out, what the sharable libraries are.  You can do this, for example, by:
    ldd cf_utility.exe
  # or
    readelf -d
  # Many of these may already be in usr/lib
  cp linux-vdso.so.1 $ORIG_FS_DIR/usr/lib
  cp libprotobuf.so.32 $ORIG_FS_DIR/usr/lib
  cp libgflags.so.2.2 $ORIG_FS_DIR/usr/lib
  cp libcrypto.so.3 $ORIG_FS_DIR/usr/lib
  cp libssl.so.3 $ORIG_FS_DIR/usr/lib
  cp libuuid.so.1 $ORIG_FS_DIR/usr/lib
  cp libstdc++.so.6 $ORIG_FS_DIR/usr/lib
  cp libgcc_s.so.1 $ORIG_FS_DIR/usr/lib
  cp libc.so.6 $ORIG_FS_DIR/usr/lib
  cp libz.so.1 $ORIG_FS_DIR/usr/lib
  cp /lib64/ld-linux-x86-64.so.2 $ORIG_FS_DIR/usr/lib
  cp libzstd.so.1 $ORIG_FS_DIR/usr/lib
  cp libm.so.6 $ORIG_FS_DIR/usr/lib
  # Copy any others you need

  # Make sure the libraries you load are the only ones that can be used
  # libc.so, libcurses.so, libm.so and libtermcap.so are necessary for
  # starting up the Linux system
  # I think this is automatic since /writablefs is not in search path

  # Copy the policy key cert(s) in the VM serving as a guest.
  # In VM's intended for distribution , you should obain these, in advance, from the
  # security domain administrator.  In the test script, this is generated
  # by provision-keys.sh and copied in copy-vm-files.sh..

  cp $EXAMPLE_DIR/provisioning/$POLICY_CERT_FILE_NAME $ORIG_FS_DIR/etc/$POLICY_CERT_FILE_NAME
  chmod 0644 $ORIG_FS_DIR/etc/$POLICY_CERT_FILE_NAME

  # Copy (or make) start-script.sh to call at init
  cp $EXAMPLE_DIR/start-script.sh $ORIG_FS_DIR/scripts

  # Disallow root access at least remotely (FIX)
  /etc/ssh/sshd_config:
        PermitRootLogin no #disabled
  /etc/init.d/sshd restart

  # Change init:
  #   Make a /writablefs directory for disk mount point in init
  #   Change init and mount the writable disk under /writeablefs
  #   Mount $ROOT_FS /writablefs/$ROOT_FS
  #   Modify init to call start-script.sh
  #   Modify init to NOT replace initramfs with system disk
  cp $EXAMPLE_DIR/init.new $ORIG_FS_DIR/init

  # copy any scripts you need into $ORIG_FS_DIR/scripts

  # Make sure all your scripts are executable
    chmod +x $ORIG_FS_DIR/init
    chmod +x $ORIG_FS_DIR/scripts/start-script.sh
```

Finally we will recompress initrd.img.

You may need to inject special drivers for your VM.  Make sure
your module names (e.g., virtio_blk, virtio_net) are listed in
/etc/initramfs-tools/modules, then update:

```script
  update-initramfs -u -k all
startup_program.cc```

Now, rebuild the archive:

```script
  find . -print0 | cpio --null -o -H newc | gzip -c > ../new_initrd.img
```

### Measuring the VM

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


### What you actually need to do to run the tests

First, check the setup the KVM and QEMU we described in the beginning of the Hypervisor session and that
you have SEV:

```script
 kvm-ok
  modinfo kvm-amd
  lsmod | grep kvm
  qemu-system-x86_64 --version
  grep -w sev /proc/cpuinfo
```

To enable SEV in the kernel arguments:

```script
  mem_encrypt=on kvm_amd.sev=1
```

Update the bootloader:

```script
  grub2-mkconfig -o /boot/grub2/grub.cfg
```

Reboot your host:

```script
# virsh domcapabilities | grep -A 5 "<sev"
```

Launch the VM:

```script
After building a vm as described above, as is done by the scripts and
installing KVM/QEMU as decribed above, you need to build a VHD wich will
be used as a writable store

```script
# Build a VHD
```

Finally, start the VM:
```script
# we assume you've installed kvm and qemu as above.
sudo virt-install --name ubuntu-guest --os-variant ubuntu20.04 --vcpus 2 --ram 2048 --location http://ftp.ubuntu.com/ubuntu/dists/focal/main/installer-amd64/ --network bridge=virbr0,model=virtio --graphics none --extra-args='console=ttyS0,115200n8 serial'
```
















#### Delete the following, it is replaced by above


Launch the VM:

```script
  virt-install --name sev-guest \
    --machine q35 \
    --boot uefi \
    --vcpus 4 \
    --memory 4096 \
    --memtune hard_limit=4563402 \
    --disk size=30 \
    --launchSecurity sev,policy=0x1 \
    --network bridge=br0,model=virtio,rom.bar=off \
    --location /path/to/os-installer.iso \
    --install kernel_args="console=ttyS0"
```

We use Busybox to provide a basic set of Unix utilities to use on the VM instance.
To get it:

```script
  mkdir /tmp/tiny_linux
  cd /tmp/tiny_linux
  curl https://www.kernel.org/pub/linux/kernel/\
        v4.x/linux-4.0.3.tar.xz | tar xJf -
        curl https://busybox.net/downloads/busybox-1.23.2.tar.bz2 \
  | tar xjf -
```

Build busybox

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
