#!/bin/bash

# ############################################################################
# build-activation-policy.sh: Script to build activation policy on the deployment machine
# ############################################################################

set -Eeuo pipefail
Me=$(basename "$0")

source ./arg-processing.inc

# -------------------------------------------------------------------------------

function make-root-list() {

  echo "make-root-list"
  echo ""
  pushd $EXAMPLE_DIR/provisioning
    cp /var/lib/swtpm-localca/swtpm-localca-rootca-cert.pem root.pem
    cp /var/lib/swtpm-localca/issuercert.pem issuercert.pem
    openssl x509 -inform pem -in root.pem -outform der -out root.der
    openssl x509 -inform der -in root.der -text
    openssl x509 -inform pem -in issuercert.pem -outform der -out issuercert.der
    openssl x509 -inform der -in issuercert.der -text
    $CERTIFIER_ROOT/utilities/make_der_cert_chain.exe \
        --output="trustedRoots.bin" -init=true \
        --new_cert_file="root.der" --add_cert=true
  popd
  echo ""
  echo "make-root-list done"
}

function do-make-activation-policy() {
    echo "do-make-activation-policy"

    if [[ ! -e "$EXAMPLE_DIR/provisioning" ]] ; then
      mkdir $EXAMPLE_DIR/provisioning
    fi

    if [[ ! $DEPLOYED_ENCLAVE_TYPE = "tpm-enclave" ]]; then
        echo "Can only make policy for tpm activation"
	exit
    fi

    make-root-list
    cp $EXAMPLE_DIR/provisioning/trustedRoots.bin $EXAMPLE_DIR/service
    cp $EXAMPLE_DIR/provisioning/$POLICY_KEY_FILE_NAME $EXAMPLE_DIR/service
    cp $EXAMPLE_DIR/provisioning/$POLICY_CERT_FILE_NAME $EXAMPLE_DIR/service

  echo ""
  echo "do-make-activation-policy done"
}

# ------------------------------------------------------------------------------

echo ""
echo "build-activation-policy.sh"
echo ""

echo "Processing arguments"
process-args
echo "Arguments processed"

if [[ $VERBOSE -eq 1 ]]; then                   
        print-variables                         
fi

do-make-activation-policy

echo ""
echo "build-activation-policy.sh done"
echo ""

# ------------------------------------------------------------------------------

