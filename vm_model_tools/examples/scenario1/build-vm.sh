#!/bin/bash

# ############################################################################
# build_vm.sh script to build final deployable VM
# ############################################################################

set -Eeuo pipefail
Me=$(basename "$0")

source ./arg-processing.inc

# ---------------------------------------------------------------------------------

echo ""
echo "build-vm.sh"
echo "Processing arguments"
process-args
echo "Arguments processed"

if [[ $TEST_TYPE == "simulated" ]]; then
	echo "Nothing to do in simulated environment"
fi
if [[ $TEST_TYPE == "real" ]]; then
	echo "we don't build VM's yet so this ony works in the test environment"
fi

# Copy an vmlinuz and initrd.img
sudo bash
cp /boot/vmlinuz $EXAMPLE_DIR
cp /boot/initrd.img $EXAMPLE_DIR
chmod 0666 $EXAMPLE_DIR/vmlinuz $EXAMPLE_DIR/initrd.img
exit

# Some defines
export ORIG_FS_DIR=$EXAMPLE_DIR/custom_init
pushd $CERTIFIER_ROOT
  cd ../virtee/snpguest
  export SNPTOOL_DIR=$(pwd)
popd
export ORIG_FS_DIR=$EXAMPLE_DIR/custom_init
pushd $CERTIFIER_ROOT
  cd ../virtee/snpguest
  export SNPTOOL_DIR=$(pwd)
popd


##### Fix initrd.img

# unpack it
cd $EXAMPLE_DIR
mkdir custom_init && cd custom_init
unmkinitramfs ../initrd.img .
ls -l .

# Compile test program
g++ -o startup_program.exe startup_program.cc

# install busybox
export BUSYBOX_DIR=/usr/bin
cp $BUSYBOX_DIR/busybox $ORIG_FS_DIR/usr/bin
install ~/busybox/examples/inittab $ORIG_FS_DIR/etc/inittab

# When the Linux kernel finishes booting, it executes /sbin/init (or /linuxrc)
# which starts busybox init.  busybox init reads /etc/inittab to determine what
# programs to run. 
# If /etc/inittab does not exist, BusyBox uses hardcoded
# default actions to mount filesystems and spawn a shell.
# Otherwise, the script typically iterates through and executes other scripts
# in /etc/init.d/ in numerical order (such as S01*, S10*, S20*).

# Init
mkdir $ORIG_FS_DIR/etc/init.d || true
cp $EXAMPLE_DIR/rcS $ORIG_FS_DIR/etc/init.d
chmod +x $ORIG_FS_DIR/etc/init.d/rcS
cp $EXAMPLE_DIR/inittab $ORIG_FS_DIR/etc

# Populate init.d
# Not sure what to put in init.s (besides rcS)
# install udhcpc?  If so:
# ip link set eth0 up
# udhcpc -i eth0 -s /usr/share/udhcpc/default.script -q -n
# cron libvirtd udhcpc console? openssh
# link linuxrc-->busybox ?

# Copy Programs and libraries
cp $CERTIFIER_ROOT/vm_model_tools/src/cf_key_server.exe $ORIG_FS_DIR/usr/bin
cp $CERTIFIER_ROOT/vm_model_tools/src/cf_key_client.exe $ORIG_FS_DIR/usr/bin
cp $CERTIFIER_ROOT/vm_model_tools/src/cf_utilities.exe $ORIG_FS_DIR/usr/bin
cp $CERTIFIER_ROOT/utilities/cpuid.exe usr/bin
cp $EXAMPLE_DIR/startup_program.exe $ORIG_FS_DIR/bin
cp /usr/lib/x86_64-linux-gnu/linux-vdso.so.1 $ORIG_FS_DIR/usr/lib
cp /usr/lib/x86_64-linux-gnu/libprotobuf.so.32 $ORIG_FS_DIR/usr/lib
cp /usr/lib/x86_64-linux-gnu/libgflags.so.2.2 $ORIG_FS_DIR/usr/lib
cp /usr/lib/x86_64-linux-gnu/libcrypto.so.3 $ORIG_FS_DIR/usr/lib
cp /usr/lib/x86_64-linux-gnu/libssl.so.3 $ORIG_FS_DIR/usr/lib
cp /usr/lib/x86_64-linux-gnu/libuuid.so.1 $ORIG_FS_DIR/usr/lib
cp /usr/lib/x86_64-linux-gnu/libstdc++.so.6 $ORIG_FS_DIR/usr/lib
cp /usr/lib/x86_64-linux-gnu/libgcc_s.so.1 $ORIG_FS_DIR/usr/lib
cp /usr/lib/x86_64-linux-gnu/libc.so.6 $ORIG_FS_DIR/usr/lib
cp /usr/lib/x86_64-linux-gnu/libz.so.1 $ORIG_FS_DIR/usr/lib
cp /lib64/ld-linux-x86-64.so.2 $ORIG_FS_DIR/usr/lib
cp /usr/lib/x86_64-linux-gnu/libzstd.so.1 $ORIG_FS_DIR/usr/lib
cp /usr/lib/x86_64-linux-gnu/libm.so.6 $ORIG_FS_DIR/usr/lib

# Policy cert and domain name
cp $EXAMPLE_DIR/provisioning/$POLICY_CERT_FILE_NAME $ORIG_FS_DIR/etc/$POLICY_CERT_FILE_NAME
chmod 0644 $ORIG_FS_DIR/etc/$POLICY_CERT_FILE_NAME
$DOMAIN_NAME >> $ORIG_FS_DIR/etc/domains

# Copy scripts
cp $EXAMPLE_DIR/start-script.sh $ORIG_FS_DIR/scripts

# Copy init file
cp $EXAMPLE_DIR/init.new $ORIG_FS_DIR/init
chmod +x $ORIG_FS_DIR/init
chmod +x $ORIG_FS_DIR/scripts/start-script.sh

# Remake it
mkinitramfs -l 9 -o $EXAMPLE_DIR/new_initrd.img 

echo "done"

# --------------------------------------------------------------------------------

