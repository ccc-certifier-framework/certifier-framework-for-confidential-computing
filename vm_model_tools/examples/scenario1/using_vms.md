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

First, you will need a "small" Linux OS.  You can build your own but
we will start with an existing one.  We use a small Debian OS called
Trixie, which is an AMD SEV-enabled server (either bare metal or a
confidential VM guest), based on 64 bit Debian 13.

You can start with an ISO and install it into a real or virtual disk
(for Trixie, get it at Link: https://www.debian.org/download) or a
prebuilt virtual disk (get it at https://cdimage.debian.org/cdimage/cloud/).
We'll do the latter.

## Install KVM (if you haven't already)

Most people already have a KVM installed.  If not, do the following.

install the required packages, make sure KVM is sev enabled.

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

To create a vm from an ISO:

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

Let assume the image is in ~/Downloads.

First, fix the image so you can log in.  You may first have to install a tool:

```script
apt install guestfs-tools
```
```script

virt-customize -a /home/jlm/Downloads/debian-13-generic-amd64-20261123-2671.qcow2 \
  --root-password password:certifier \
  --ssh-inject root:file:/home/jlm/.ssh/id_rsa.pub \
  --timezone America/Los_Angeles

#  --ssh-inject debian:file:/home/jlm/.ssh/id_rsa.pub \
#  --upload local-config.conf:/etc/app/config.conf
```

Import the image as a VM for KVM startup using virt-manager.
You may have to be root to do this.  I called mine jlm-test-vm.

```script
/etc/ssh/sshd_config.d/

It's generally good practice to add configuration file(s) with
your desired changes and options into that subdirectory, rather
than editing the system default sshd_config file directly.

E.g. if you wanted to allow users bill and ted to ssh, create a file called

/etc/ssh/sshd_config.d/allowusers.conf

with a line that looks like:

AllowUsers bill ted

This /etc/ssh/sshd_config works fine!

# Package generated configuration file
# See the sshd(8) manpage for details

# What ports, IPs and protocols we listen for
Port 30000
# Use these options to restrict which interfaces/protocols sshd will bind to
#ListenAddress ::
#ListenAddress 0.0.0.0
Protocol 2
# HostKeys for protocol version 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_dsa_key
#Privilege Separation is turned on for security
UsePrivilegeSeparation yes

# Lifetime and size of ephemeral version 1 server key
KeyRegenerationInterval 3600
ServerKeyBits 768

# Logging
SyslogFacility AUTH
LogLevel INFO

# Authentication:
LoginGraceTime 120
PermitRootLogin yes
StrictModes yes

RSAAuthentication yes
PubkeyAuthentication yes
#AuthorizedKeysFile     %h/.ssh/authorized_keys

# Don't read the user's ~/.rhosts and ~/.shosts files
IgnoreRhosts yes
# For this to work you will also need host keys in /etc/ssh_known_hosts
RhostsRSAAuthentication no
# similar for protocol version 2
HostbasedAuthentication no
# Uncomment if you don't trust ~/.ssh/known_hosts for RhostsRSAAuthentication
#IgnoreUserKnownHosts yes

# To enable empty passwords, change to yes (NOT RECOMMENDED)
PermitEmptyPasswords no

# Change to yes to enable challenge-response passwords (beware issues with
# some PAM modules and threads)
ChallengeResponseAuthentication no

# Change to no to disable tunnelled clear text passwords
#PasswordAuthentication yes

# Kerberos options
#KerberosAuthentication no
#KerberosGetAFSToken no
#KerberosOrLocalPasswd yes
#KerberosTicketCleanup yes

# GSSAPI options
#GSSAPIAuthentication no
#GSSAPICleanupCredentials yes

X11Forwarding yes
X11DisplayOffset 10
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
#UseLogin no

#MaxStartups 10:30:60
#Banner /etc/issue.net

# Allow client to pass locale environment variables
AcceptEnv LANG LC_*

```


### Step 2 - Run the VHD under a hypervisor

From virt-manager, create a new virtual machine from the image you downloaded.  Name it debian13.

```script
# Start VM
virsh start debian13
```

Note that the NW installed is virbr0.

### Step 3 - Copy the programs, scripts, files and libraries you need to the VM image

### Step 4 - Fix the SSH and password configuration

### Step 5 - Unpack initrd

### Step 6 - Copy the needed files into initrd

### Step 7 - Modify the init script in the initrd filesystem

### Step 8 - Repack initrd

### Step 9 - Copy the resulting kernel image and initrd for distribution




