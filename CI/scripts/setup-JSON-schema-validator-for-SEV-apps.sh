#!/bin/bash
# #############################################################################
# setup-JSON-schema-validator-for-SEV-apps.sh:
#
# Run through steps to install s/w components needed to build the
# Policy Generator.
# #############################################################################
set -Eeuo pipefail

# Setup script globals, to establish curdir and root path to Certifier code base
Me=$(basename "$0")

numCPUs=$(grep -c "^processor" /proc/cpuinfo)
if [ "${numCPUs}" -eq "0" ]; then numCPUs=1; fi

# Establish root-dir for Certifier library.
pushd "$(dirname "$0")" > /dev/null 2>&1

cd ../../

# shellcheck disable=SC2046
CERT_PROTO="$(pwd)"; export CERT_PROTO

popd > /dev/null 2>&1

echo "${Me}: CERT_PROTO=${CERT_PROTO}"

echo " "
echo "******************************************************************"
echo "* ${Me}:"
echo "* Install s/w components needed to build the Policy Generator"
echo "* This step (make -f policy_generator.mak) needs some prerequisite"
echo "* s/w components. See INSTALL.md"
echo "******************************************************************"
echo " "
pushd utilities

echo " "
echo "* ---------------------------------------------------------------"
echo "* ${Me}: The json-schema-validator library requires JSON for Modern C++"
echo "* $ git clone https://github.com/nlohmann/json.git"
echo "* ---------------------------------------------------------------"
echo " "

set -x
if [ ! -d ./json ]; then
   git clone https://github.com/nlohmann/json.git
fi
cd json
if [ ! -d ./build ]; then mkdir build; fi

pushd build

cmake ..
make -j${numCPUs}

sudo make install

set +x
popd   # Back to utilities/

echo " "
echo "* -----------------------------------------------------------------"
echo "* The Policy Generator requires the json-schema-validator library"
echo "* $ git clone https://github.com/pboettch/json-schema-validator.git"
echo "* -----------------------------------------------------------------"
echo " "
set -x
if [ ! -d ./json-schema-validator ]; then
   git clone https://github.com/pboettch/json-schema-validator.git
fi

pushd json-schema-validator
if [ ! -d ./build ]; then mkdir build; fi
pushd build

cmake .. -DBUILD_SHARED_LIBS=ON ..
make -j${numCPUs}
sudo make install

set +x
popd   # Back to json-schema-validator
popd   # Back to utilities

popd   # Back to certifier-root-dir/

# #############################################################################
# Post-install checks and setup
# #############################################################################
echo " "

# See if the libnlohmann_json_schema_validator.so.2 was installed at expected place
ls -aFlrt /usr/local/lib

echo "${Me}: $(TZ="America/Los_Angeles" date) Completed."
exit 0

echo " "
cat /etc/ld.so.conf

# Need to fiddle with above ld-configuration, so stuff is picked up at build time
set -x
# if [ $(cat /etc/ld.so.conf | grep -c "/usr/local/lib") -eq 0 ]; then fi
set +x
