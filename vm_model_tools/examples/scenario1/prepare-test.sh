#!/bin/bash
# ############################################################################
# prepare-test.sh: Driver script to run build-and-test for cf_utility.
# ############################################################################

set -Eeuo pipefail
Me=$(basename "$0")

if [ -z "{$CERTIFIER_ROOT}+set" ] ; then
  echo " "
  CERTIFIER_ROOT=../../..
else
  echo " "
  echo "CERTIFIER_ROOT already set."
fi
EXAMPLE_DIR=$(pwd)

echo " "
echo "Certifier root: $CERTIFIER_ROOT"
echo "Example directory: $EXAMPLE_DIR"

ARG_SIZE="$#"

if [ $ARG_SIZE == 0 ] ; then
  echo "Must call with an arguments, as follows:"
  echo "  ./prepare-test.sh fresh"
  echo "  ./prepare-test.sh all"
  echo "  ./prepare-test.sh compile-utilities"
  echo "  ./prepare-test.sh make-keys"
  echo "  ./prepare-test.sh all"
  echo "  ./prepare-test.sh make-policy"
  echo "  ./prepare-test.sh compile-certifier"
  echo "  ./prepare-test.sh copy-files"
  exit
fi

if [ $ARG_SIZE == 1 ] ; then
  DOMAIN_NAME="datica-test"
else
  DOMAIN_NAME=$2
fi
echo "domain name: $DOMAIN_NAME"

POLICY_KEY_FILE_NAME="policy_key_file.$DOMAIN_NAME"
POLICY_CERT_FILE_NAME="policy_cert_file.$DOMAIN_NAME"
echo "policy key file name: $POLICY_KEY_FILE_NAME"
echo "policy cert file name: $POLICY_CERT_FILE_NAME"

POLICY_STORE_NAME="policy_store.$DOMAIN_NAME"
CRYPTSTORE_NAME="cryptstore.$DOMAIN_NAME"
echo "policy store name: $POLICY_STORE_NAME"
echo "cryptstore name: $CRYPTSTORE_NAME"

function do-fresh() {
  echo "do-fresh"

  pushd $CERTIFIER_ROOT/utilities > /dev/null
  make clean -f cert_utility.mak
  make clean -f policy_utilities.mak
  popd > /dev/null
  pushd $CERTIFIER_ROOT/vm_model_tools/src > /dev/null
  make clean -f cf_utility.mak
  popd > /dev/null

  mkdir $EXAMPLE_DIR/provisioning || true
  pushd $EXAMPLE_DIR/provisioning  > /dev/null

  if [[ "$(pwd)" == "${EXAMPLE_DIR}/provisioning" ]] ; then
    echo " "
    echo "in $(pwd)"
    rm ./* || true
    echo " "
  else
    echo "Wrong directory "
    exit
  fi
  popd > /dev/null

  mkdir $EXAMPLE_DIR/service || true
  pushd $EXAMPLE_DIR/service > /dev/null

  if [[ "$(pwd)" == "${EXAMPLE_DIR}/service" ]] ; then
    echo " "
    echo "In $(pwd)"
    rm ./* || true
    echo " "
  else
    echo "Wrong directory "
    exit
  fi
  popd > /dev/null

  pushd $EXAMPLE_DIR > /dev/null
  rm $POLICY_STORE_NAME || true
  rm $CRYPTSTORE_NAME || true
  popd > /dev/null

  echo "Done"

  exit
}

function do-compile-utilities() {
  echo "do-compile-utilities"

  pushd $CERTIFIER_ROOT/utilities > /dev/null
  make -f cert_utility.mak
  make -f policy_utilities.mak
  popd > /dev/null 2>&1

  echo "do-compile-utilities done"
}

function do-make-keys() {
  echo "do-make-keys"

  mkdir $EXAMPLE_DIR/provisioning || true
  pushd $EXAMPLE_DIR/provisioning > /dev/null
    $CERTIFIER_ROOT/utilities/cert_utility.exe  \
      --operation=generate-policy-key-and-test-keys  \
      --policy_key_output_file=$POLICY_KEY_FILE_NAME  \
      --policy_cert_output_file=$POLICY_CERT_FILE_NAME \
      --platform_key_output_file=platform_key_file.bin  \
      --attest_key_output_file=attest_key_file.bin
  popd > /dev/null

  echo "do-make-keys done"
}

function do-compile-program() {
  echo "do-compile-program"

  pushd $CERTIFIER_ROOT/vm_model_tools/src > /dev/null
  make -f cf_utility.mak
  popd > /dev/null

  echo "do-compile-program done"
}

function do-make-policy() {
  echo "do-make-policy"

  pushd $EXAMPLE_DIR/provisioning > /dev/null
  popd > /dev/null

  echo "do-make-policy done"
}

function do-compile-certifier() {
  echo "do-compile-certifier"

  pushd $CERTIFIER_ROOT/certifier_service > /dev/null

  pushd graminelib > /dev/null
    make dummy
  popd > /dev/null
  pushd oelib > /dev/null
    make dummy
  popd > /dev/null
  pushd isletlib > /dev/null
    make dummy
  popd > /dev/null
  pushd teelib > /dev/null
    make
  popd > /dev/null

  go build simpleserver.go

  popd > /dev/null

  echo "do-compile-certifier done"
}

function do-copy-files() {
  echo "do-copy-files"
  echo "cp $POLICY_KEY_FILE_NAME $EXAMPLE_DIR/$POLICY_KEY_FILE_NAME"
  echo "cp $POLICY_CERT_FILE_NAME $EXAMPLE_DIR/$POLICY_CERT_FILE_NAME"
  exit

  pushd $EXAMPLE_DIR/provisioning > /dev/null
    cp -p $POLICY_KEY_FILE_NAME $POLICY_CERT_FILE_NAME policy.bin $EXAMPLE_DIR/service
    cp -p sev_policy.bin ark_cert.der ask_cert.der vcek_cert.der $EXAMPLE_DIR/service
    cp -p $POLICY_KEY_FILE_NAME $POLICY_CERT_FILE_NAME ..
  popd > /dev/null

  echo "do-copy-files done"
}

function do-all() {
  echo " "
  echo "do-all"

  do-compile-utilities
  do-make-keys
  do-compile-program
  do-make-policy
  do-compile-certifier
  do-copy-files

  echo " "
  echo "do-all done"
}


if [ "$1" == "fresh" ] ; then
  echo " "
  do-fresh
  exit
fi

if [ "$1" == "all" ] ; then
  echo "Base name: $0"
  do-all
  exit
fi

if [ "$1" == "compile-utilities" ] ; then
  echo " "
  do-compile-utilities
  exit
fi

if [ "$1" == "make-keys" ] ; then
  echo " "
  do-make-keys
  exit
fi

if [ "$1" == "compile-program" ] ; then
  echo " "
  do-compile-program
  exit
fi

if [ "$1" == "make-policy" ] ; then
  echo " "
  do-make-policy
  exit
fi

if [ "$1" == "compile-certifier" ] ; then
  echo " "
  do-compile-certifier
  exit
fi

if [ "$1" == "copy-files" ] ; then
  echo " "
  do-copy-files
  exit
fi
