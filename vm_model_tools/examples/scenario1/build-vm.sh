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

# Copy Programs and libraries
cp $CERTIFIER_ROOT/vm_model_tools/src/cf_key_server.exe $ORIG_FS_DIR/usr/bin
cp $CERTIFIER_ROOT/vm_model_tools/src/cf_key_client.exe $ORIG_FS_DIR/usr/bin
cp $CERTIFIER_ROOT/vm_model_tools/src/cf_utilities.exe $ORIG_FS_DIR/usr/bin
cp $CERTIFIER_ROOT/utilities/cpuid.exe usr/bin
cp $EXAMPLE_DIR/startup_program.exe $ORIG_FS_DIR/bin
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
# find . -print0 | cpio --null -o -H newc | gzip -c > $EXAMPLE_DIR/new_initrd.img
# find . | cpio -o -c -R root:root | gzip -9 > $EXAMPLE_DIR/new_initrd.img
mkinitramfs -l 9 -o $EXAMPLE_DIR/new_initrd.img 

echo "done"

# --------------------------------------------------------------------------------

