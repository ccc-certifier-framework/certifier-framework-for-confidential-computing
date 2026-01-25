#!/bin/bash

# ############################################################################
# provision-keys.sh: Generate Certifier keys
# ############################################################################

set -Eeuo pipefail
Me=$(basename "$0")

source ./arg-processing.inc

# ------------------------------------------------------------------------------------------


function do-fresh() {
  echo " "
  echo "do-fresh"

  pushd $EXAMPLE_DIR
    if [[ -e "$POLICY_STORE_NAME" ]] ; then
      rm $POLICY_STORE_NAME
    fi
    if [[ -e "$CRYPTSTORE_NAME" ]] ; then
      rm $CRYPTSTORE_NAME
    fi
  popd

  echo "do-fresh done"
}

function do-make-keys() {
	echo ""
	echo "running do-make-keys"
     	 
	if [[ ! -e "$EXAMPLE_DIR/provisioning" ]] ; then
		mkdir $EXAMPLE_DIR/provisioning
	fi  
	pushd $EXAMPLE_DIR/provisioning
		$CERTIFIER_ROOT/utilities/cert_utility.exe  \
		   --operation=generate-policy-key-and-test-keys  \
		   --domain_name=$DOMAIN_NAME \
		   --policy_key_output_file=$POLICY_KEY_FILE_NAME  \
		   --policy_cert_output_file=$POLICY_CERT_FILE_NAME \
		   --platform_key_output_file=platform_key_file.bin  \
		   --attest_key_output_file=attest_key_file.bin

		$CERTIFIER_ROOT/utilities/simulated_sev_key_generation.exe            \
		   --ark_der=sev_ark_cert.der                                        \
		   --ask_der=sev_ask_cert.der                                        \
		   --vcek_der=sev_vcek_cert.der                                      \
		   --vcek_key_file=/etc/certifier-snp-sim/ec-secp384r1-pub-key.pem

		mv sev_ark_cert.der ark_cert.der
		mv sev_ask_cert.der ask_cert.der
		mv sev_vcek_cert.der vcek_cert.der

		cp -p ark_cert.der ask_cert.der vcek_cert.der $EXAMPLE_DIR/cf_data
	popd

echo "do-make-keys done"
echo ""
}

# ----------------------------------------------------------------

echo ""
echo "Provision keys"
echo ""

echo "Processing arguments"
process-args
echo "Processed arguments"

if [[ $VERBOSE -eq 1 ]]; then
	print-variables
fi

if [[ $CLEAN -eq 1 ]]; then
	do-fresh
fi

do-make-keys

echo "Provision keys done"
echo ""
