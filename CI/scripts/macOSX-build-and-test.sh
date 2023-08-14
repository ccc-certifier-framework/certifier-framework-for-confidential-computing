#!/bin/bash
# ##############################################################################
# Driver script to go through basic build-and-test test cycle on Mac/OSX
# ##############################################################################

set -Eeuo pipefail

# Setup script globals, to establish curdir and root path to Certifier code base
Me=$(basename "$0")

numCPUs=2

# Establish root-dir for Certifier library.
pushd "$(dirname "$0")" > /dev/null 2>&1

cd ../../

# shellcheck disable=SC2046
CERT_ROOT="$(pwd)"; export CERT_ROOT

popd > /dev/null 2>&1

echo "${Me}: CERT_ROOT=${CERT_ROOT}"

subdir="src"
echo "***************************************************************************"
echo "${Me}: ${subdir}/ sub-dir ..."
echo " "
pushd "${CERT_ROOT}/${subdir}" > /dev/null 2>&1

# make -f certifier.mak clean && make -f certifier.mak -j${numCPUs}

# make -f certifier_tests.mak clean && make -f certifier_tests.mak -j${numCPUs}

# make -f certifier.mak --always-make -j${numCPUs} sharedlib

# make -f certifier_tests.mak --always-make -j${numCPUs} sharedlib

popd > /dev/null 2>&1

subdir="utilities"
echo "***************************************************************************"
echo "${Me}: ${subdir}/ sub-dir ..."
echo " "
pushd "${CERT_ROOT}/${subdir}" > /dev/null 2>&1

for mkfile in cert_utility.mak policy_utilities.mak policy_generator.mak
do
    make -f ${mkfile} clean && make -f ${mkfile} -j${numCPUs}
done

popd > /dev/null 2>&1

