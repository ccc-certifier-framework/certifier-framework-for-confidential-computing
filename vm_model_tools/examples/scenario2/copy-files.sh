#!/bin/bash

# ############################################################################
# copy-files.sh copy run time files
# ############################################################################

set -Eeuo pipefail
Me=$(basename "$0")

source ./arg-processing.inc

# This script copies file from the provisioning directory to the
# locations used at run-time.

# ------------------------------------------------------------------------------------------


function do-copy-files() {
	echo " "
	echo "do-copy-files"
      
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
	cp -p $POLICY_FILE_NAME ark_cert.der ask_cert.der vcek_cert.der $EXAMPLE_DIR/service
	cp -p $POLICY_CERT_FILE_NAME $EXAMPLE_DIR/cf_data

	if [[ -f cf_utility.measurement ]]; then
		cp -p cf_utility.measurement $EXAMPLE_DIR
		cp -p cf_utility.measurement $EXAMPLE_DIR/cf_data
	fi
	if [[ -f sev_cf_utility.measurement ]]; then
		cp -p sev_cf_utility.measurement $EXAMPLE_DIR
		cp -p sev_cf_utility.measurement $EXAMPLE_DIR/cf_data
	fi
	if [[ -f $VM_NAME.measurement.measurement ]]; then
		cp -p $VM_NAME.measurement $EXAMPLE_DIR
		cp -p $VM_NAME.measurement $EXAMPLE_DIR/cf_data
	fi
	if [[ -f platform_attest_endorsement.bin ]]; then
		cp -p platform_key_file.bin attest_key_file.bin \
			platform_attest_endorsement.bin $EXAMPLE_DIR/cf_data
	fi

	popd

	pushd $EXAMPLE_DIR/cf_data
	$CERTIFIER_ROOT/utilities/combine_policy_certs.exe \
	  --init=true --new_cert_file=$POLICY_CERT_FILE_NAME \
	  --output=my_certs
	popd

	echo "do-copy-files done"
	echo " "
}

echo "Processing arguments"
process-args
echo "Processed arguments"

if [[ $VERBOSE -eq 1 ]]; then
        print-variables
fi

do-copy-files
echo "Files copied"
echo ""
