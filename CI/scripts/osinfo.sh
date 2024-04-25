#!/bin/bash
# ##############################################################################
# Simple script to grab OS-specific config for Linux boxes.
#
# History:
#   Apr 2024    Added to debug CI-build-jobs' instability on CCC CI-harness.
# ##############################################################################

numCPUs=`grep "^processor" /proc/cpuinfo | wc -l`
cpuModel=`grep "model name" /proc/cpuinfo | head -1 | cut -f2 -d':'`
cpuVendor=`grep "vendor_id" /proc/cpuinfo | head -1 | cut -f2 -d':'`
totalMemGB=`free -g | grep "^Mem:" | awk '{print $2}'`

uname -a
echo "${cpuVendor}, ${numCPUs} CPUs, ${totalMemGB} GB, ${cpuModel}"
ping -4 -c 1 `uname -n` | head -2

echo
lsb_release -a
