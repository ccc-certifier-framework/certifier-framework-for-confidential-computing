#!/bin/bash

# ############################################################################
# copy-vm-files-test.sh
# ############################################################################

set -Eeuo pipefail
Me=$(basename "$0")

source ./arg-processing.inc

# ------------------------------------------------------------------------------------------


function do-copy-vm-files() {
	echo " "
	echo "do-copy-vm-files"
      
	if [[ ! -e "$EXAMPLE_DIR/provisioning" ]] ; then
		mkdir $EXAMPLE_DIR/provisioning
	fi
	if [[ ! -e "$EXAMPLE_DIR/service" ]] ; then
		mkdir $EXAMPLE_DIR/service
	fi
	if [[ ! -e "$EXAMPLE_DIR/cf_data" ]] ; then
		mkdir $EXAMPLE_DIR/cf_data
	fi
	pushd $EXAMPLE_DIR/provisioning
	cp -p $POLICY_KEY_FILE_NAME $POLICY_CERT_FILE_NAME policy.bin $EXAMPLE_DIR/service
	cp -p sev_policy.bin ark_cert.der ask_cert.der vcek_cert.der $EXAMPLE_DIR/service
	cp -p $POLICY_CERT_FILE_NAME $EXAMPLE_DIR/cf_data
	cp -p platform_key_file.bin attest_key_file.bin sev_cf_utility.measurement $EXAMPLE_DIR/cf_data
	cp -p cf_utility.measurement platform_attest_endorsement.bin $EXAMPLE_DIR/cf_data
	cp -p ark_cert.der ask_cert.der vcek_cert.der $EXAMPLE_DIR/cf_data
	popd

	pushd $EXAMPLE_DIR/cf_data
	$CERTIFIER_ROOT/utilities/combine_policy_certs.exe \
	  --init=true --new_cert_file=$POLICY_CERT_FILE_NAME \
	  --output=my_certs
	popd

	echo "do-copy-vm-files done"
	echo " "
}

# --------------------------------------------------------------------------------------------------

echo "Processing arguments"
process-args
echo "Arguments processed"

if [[ $VERBOSE -eq 1 ]]; then
        print-variables
fi

if [[ $TEST_TYPE = "simulated" ]]; then
        echo "Nothing to do in simulated environment"
	exit
fi

echo "John need =s help with this"
echo ""
