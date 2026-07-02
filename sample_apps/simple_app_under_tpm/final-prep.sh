#!/bin/bash

# ############################################################################
# final-prep.sh: Script to make-policy and copy files
# ############################################################################
  
set -Eeuo pipefail
Me=$(basename "$0")
  
if [[ -v CERTIFIER_ROOT ]] ; then
  echo "CERTIFIER_ROOT already set."
else
  pushd ../..
  CERTIFIER_ROOT=$(pwd)
  popd
fi    
EXAMPLE_DIR=$(pwd)
    
echo " "
echo "Certifier root: $CERTIFIER_ROOT"
echo "Example directory: $EXAMPLE_DIR"
      
ARG_SIZE="$#"
    
if [[ $ARG_SIZE == 0 ]] ; then
  echo "Must call with arguments, as follows:"
  echo "  ./final-prep.sh domain_name"
fi

if [[ $ARG_SIZE == 0 ]] ; then
  DOMAIN_NAME="datica-test"
fi
DOMAIN_NAME=$1
echo "domain name: $DOMAIN_NAME"

POLICY_KEY_FILE_NAME="policy_key_file.$DOMAIN_NAME"
POLICY_CERT_FILE_NAME="policy_cert_file.$DOMAIN_NAME"
echo "policy key file name: $POLICY_KEY_FILE_NAME"
echo "policy cert file name: $POLICY_CERT_FILE_NAME"

POLICY_STORE_NAME="policy_store.$DOMAIN_NAME"
echo "policy store name: $POLICY_STORE_NAME"

function do-make-policy() {
  echo " "
  echo "do-make-policy"

  pushd $EXAMPLE_DIR/provisioning
    echo " "

    $CERTIFIER_ROOT/utilities/make_unary_vse_clause.exe \
      --key_subject="" --measurement_subject="measurement" \
      --verb="is-trusted" --output=ts2.bin --config="7"
    $CERTIFIER_ROOT/utilities/make_indirect_vse_clause.exe \
      --key_subject=$POLICY_KEY_FILE_NAME --verb="says" \
      --clause=ts2.bin --output=vse_policy1.bin
    $CERTIFIER_ROOT/utilities/make_signed_claim_from_vse_clause.exe \
      --vse_file=vse_policy1.bin --duration=9000 --private_key_file=$POLICY_KEY_FILE_NAME \
      --output=signed_claim_1.bin

    $CERTIFIER_ROOT/utilities/package_claims.exe \
        --input=signed_claim_1.bin \
        --output=policy.bin
    $CERTIFIER_ROOT/utilities/print_packaged_claims.exe --input=policy.bin
  popd

  echo " "
  echo "do-make-policy done"
}
 
function make-cert-chain() {

  #pushd $EXAMPLE_DIR/provisioning
  #  cp /var/lib/swtpm-localca/swtpm-localca-rootca-cert.pem root.pem
  #  openssl x509 -inform pem -in root.pem -outform der -out root.der
  #  openssl x509 -inform der -in root.der -text
  #  $CERTIFIER_ROOT/utilities/make_der_cert_chain.exe \
  #	--output="endorsement_cert_chain.bin" -init=true \
  #	--new_cert_file="root.der" --add_cert=true
  #  popd
  echo ""
}

function do-copy-files() {
  echo " "
  echo "do-copy-files"

  pushd $EXAMPLE_DIR
    if [[ ! -d "$EXAMPLE_DIR/provisioning" ]] ; then
      mkdir $EXAMPLE_DIR/provisioning
    fi
    if [[ ! -d "$EXAMPLE_DIR/service" ]] ; then
      mkdir $EXAMPLE_DIR/service
    fi
    if [[ ! -d "$EXAMPLE_DIR/app1_data" ]] ; then
      mkdir $EXAMPLE_DIR/app1_data
    fi
    if [[ ! -d "$EXAMPLE_DIR/app2_data" ]] ; then
      mkdir $EXAMPLE_DIR/app2_data
    fi
  popd

  pushd $EXAMPLE_DIR/provisioning
    cp -p $POLICY_KEY_FILE_NAME $POLICY_CERT_FILE_NAME policy.bin $EXAMPLE_DIR/service
    cp -p $POLICY_CERT_FILE_NAME attest_key_file.bin platform_key_file.bin $EXAMPLE_DIR/app1_data
    cp -p $POLICY_CERT_FILE_NAME attest_key_file.bin platform_key_file.bin $EXAMPLE_DIR/app2_data
    cp -p quote_cert.crt $EXAMPLE_DIR/service
    cp -p quote_cert.crt $EXAMPLE_DIR/app1_data
    cp -p quote_cert.crt $EXAMPLE_DIR/app2_data
    cp -p ekchain.bin $EXAMPLE_DIR/app1_data
    cp -p ekchain.bin $EXAMPLE_DIR/app2_data
  popd
  echo "do-copy-files done"
}

if [ "$1" == "copy-files" ] ; then
  echo " "
  do-copy-files
  exit
fi

do-make-policy
do-copy-files
make-cert-chain

echo " "
echo "done "
echo " "

