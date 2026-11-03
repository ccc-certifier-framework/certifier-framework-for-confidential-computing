# DRAFT in Progress --- JLM


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
The script is a good model for an SEV "appliance" with a very few
programs all designed for the Certifier envionment.  Paul's mechanism is
better for a complex "legacy" VM with lots of programs and dependencies.

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
will need storage.

In our case, initrd contains the startup scripts, at a mimimum, all programs
and libraries required by cf_utility, key_server and key-client are in
initrd as well as the libraries they use.  As mentioned below in building
the kernel, any program that the OS allows to run that is not in initrd
should be signed and checked.  The check must be a part of the Linux machine
policy.  It is also up to the kernel build (and dependent files in initrd) that
the firewalls, device permissions and other configuration is set properly.
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

## Hypervisor

Step 1: Install the required packages, make sure KVM is sev enabled.

```script
sudo apt -y install bridge-utils cpu-checker libvirt-clients libvirt-daemon qemu qemu-kvm
'''

Step 2: Check virtualisation capabilities

Execute the following command to make sure your processor supports virtualisation capabilities:

```script
  kvm-ok
```
The output of this command and indicates whether KVM can be used or not:

INFO: /dev/kvm exists
KVM acceleration can be used

Step 3: Launch a VM

In order to launch your first Ubuntu Server 20.04 LTS instance on KVM execute the following command:


```script
$ sudo virt-install --name ubuntu-guest --os-variant ubuntu20.04 --vcpus 2 --ram 2048 --location http://ftp.ubuntu.com/ubuntu/dists/focal/main/installer-amd64/ --network bridge=virbr0,model=virtio --graphics none --extra-args='console=ttyS0,115200n8 serial'
```

This opens an interactive console that you can use to manually install the Ubuntu guest.

### Tutorials and first aid for KVM

There are number of tutorials on line like:

1 .https://www.youtube.com/watch?v=_X1imTzohsY
2. https://docs.beamnetworks.dev/en/kvm/create-vm-full
3. https://oneuptime.com/blog/post/2026-01-15-setup-kvm-qemu-virtualization-ubuntu/view

### Step by step for KVM from third tutorial

1. Check Virtualization Support

```script
egrep -c '(vmx|svm)' /proc/cpuinfo
lscpu | grep Virtualization
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
# Tell libvirt to use the system-wide QEMU hypervisor
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

###  The kernal

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
(copy this to /boot/vmlinuz).

The scripts that build the VM are in build-vm.sh.


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

We will be modifying the init script "init".  The changes will be at the
very end of the file, which looks like:

  # Move virtual filesystems over to the real filesystem
  mount -n -o move /sys ${rootmnt}/sys
  mount -n -o move /proc ${rootmnt}/proc

  # Chain to real filesystem
  # shellcheck disable=SC2086,SC2094
  exec run-init ${drop_caps} "${rootmnt}" "${init}" "$@" <"${rootmnt}/dev/console" >"${rootmnt}/dev/console" 2>&1
  echo "Something went badly wrong in the initramfs."
  panic "Please file a bug on initramfs-tools."

We will add the executables to usr/bin and libraries to usr/lib.

We will add the policy cert to etc.

Finally we will recompress.

Edit contents add custom binaries, config files, or modify the /init script

```script

  # Copy binaries, including CF utilities and programs including
  # cf_utilities, cf_key_server, cf_key_client.  The programs you
  # load into initrd should either be the only ones that can run or
  # you must make sure using another mechanism that only trusted
  # programs can execute (especially as root).
  cp $CERTIFIER_ROOT/vm_model_tools/src/cf_key_server.exe usr/bin
  cp $CERTIFIER_ROOT/vm_model_tools/src/cf_key_client.exe usr/bin
  cp $CERTIFIER_ROOT/vm_model_tools/src/cf_utilities.exe usr/bin
  cp $CERTIFIER_ROOT/utilities/cpuid.exe usr/bin
  # Don't forget your application dependant libraries and scripts

  # Copy the policy key cert
  cp $EXAMPLE_DIR/provisioning/$POLICY_CERT_FILE_NAME etc/$POLICY_CERT_FILE_NAME
  chmod 0644 etc/$POLICY_CERT_FILE_NAME

  # Copy needed libraries
  # Find out, what the sharable libraries are.  You can do this, for example, by:
    ldd cf_utility.exe
  # or
    readelf -d
  # cp linux-vdso.so.1 usr/bin
  # cp libprotobuf.so.32 usr/bin
  # cp libgflags.so.2.2 usr/bin
  # cp libcrypto.so.3 usr/bin
  # cp libssl.so.3 usr/bin
  # cp libuuid.so.1 usr/bin
  # cp libstdc++.so.6 usr/bin
  # cp libgcc_s.so.1 usr/bin
  # cp libc.so.6 usr/bin
  # cp libz.so.1 usr/bin
  # cp /lib64/ld-linux-x86-64.so.2 usr/bin
  # cp libzstd.so.1 usr/bin
  # cp libm.so.6 usr/bin

  # Make sure the libraries you load are the only ones that can be used
  # libc.so, libcurses.so, libm.so and libtermcap.so are necessary for starting up the Linux system
  # The program ldconfig will search the directories listed in /etc/ld.so.conf and store all of the shared libraries which are found in /etc/ld.so.cache. 

  # copy any scripts you need

  # Disallow root access at least remotely
  /etc/ssh/sshd_config:
        PermitRootLogin no #disabled
  /etc/init.d/sshd restart

  # Change init and mount the writable disk under /
  # mount $ROOT_FS /root/$ROOT_FS

  # Make sure the init script is executable
    chmod +x init
```

You may need to inject special drivers for your VM.  Make sure
your module names (e.g., virtio_blk, virtio_net) are listed in
/etc/initramfs-tools/modules, then update:

```script
  update-initramfs -u -k all
```

Now, rebuild the archive:

```script
  find . -print0 | cpio --null -o -H newc | gzip -c > ../new_initrd.img
```

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

### Launching the VM and virtualization layer

TODO: Explain Firecracker launch too.

Here's how to KVM boot and sev VM on bare metal.

Verify you have SEV:

```script
  grep -w sev /proc/cpuinfo
```

Enable SEV in /etc/default/grub or kernel arguments:

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

# Appendix

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
