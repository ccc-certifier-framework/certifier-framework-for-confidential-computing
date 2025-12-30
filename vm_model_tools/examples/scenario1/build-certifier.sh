#!/bin/bash
# ############################################################################
# build-certifier.sh: Script to build certifier and utilities
# ############################################################################

set -Eeuo pipefail
Me=$(basename "$0")

if [[ -v CERTIFIER_ROOT ]] ; then
  echo "CERTIFIER_ROOT already set."
else
  pushd ../../..
  CERTIFIER_ROOT=$(pwd)
  popd
fi
EXAMPLE_DIR=$(pwd)

echo " "
echo "Certifier root: $CERTIFIER_ROOT"
echo "Example directory: $EXAMPLE_DIR"

ARG_SIZE="$#"

if [[ $ARG_SIZE == 0 || $ARG_SIZE > 2 ]] ; then
  exit
fi

if [[ $ARG_SIZE == 1 ]] ; then
  DOMAIN_NAME="datica-test"
else
  DOMAIN_NAME=$2
fi
echo "domain name: $DOMAIN_NAME"

POLICY_KEY_FILE_NAME="policy_key_file.$DOMAIN_NAME"
POLICY_CERT_FILE_NAME="policy_cert_file.$DOMAIN_NAME"
echo "Policy key file name: $POLICY_KEY_FILE_NAME"
echo "Policy cert file name: $POLICY_CERT_FILE_NAME"

POLICY_STORE_NAME="policy_store.$DOMAIN_NAME"
CRYPTSTORE_NAME="cryptstore.$DOMAIN_NAME"
echo "Policy store name: $POLICY_STORE_NAME"
echo "Cryptstore name: $CRYPTSTORE_NAME"

function do-fresh() {
  echo " "
  echo "do-fresh"

  if [[ ! -v NO_COMPILE_UTILITIES ]] ; then
    echo "compiling utilities"
    pushd $CERTIFIER_ROOT/utilities
      make clean -f cert_utility.mak
      make clean -f policy_utilities.mak
    popd
  else
    echo "not compiling utilities"
  fi

  pushd $CERTIFIER_ROOT/vm_model_tools/src
    make clean -f cf_utility.mak
  popd

  if [[ ! -d "$EXAMPLE_DIR/provisioning" ]] ; then
    mkdir $EXAMPLE_DIR/provisioning
  fi
  pushd $EXAMPLE_DIR/provisioning
    if [[ "$(pwd)" == "${EXAMPLE_DIR}/provisioning" ]] ; then
      echo " "
      echo "in $(pwd)"
      if [[ ! -z "$( ls -A '.' )" ]]; then
        rm ./*
      fi
      echo " "
    else
      echo "Wrong directory "
      exit
    fi
  popd

  if [[ ! -d "$EXAMPLE_DIR/cf_data" ]] ; then
    mkdir $EXAMPLE_DIR/cf_data
  fi
  pushd $EXAMPLE_DIR/cf_data
    if [[ "$(pwd)" == "${EXAMPLE_DIR}/cf_data" ]] ; then
      echo " "
      echo "in $(pwd)"
      if [[ ! -z "$( ls -A '.' )" ]]; then
        rm ./*
      fi
      echo " "
    else
      echo "Wrong directory "
      exit
    fi
  popd

  if [[ ! -d "$EXAMPLE_DIR/service" ]] ; then
    mkdir $EXAMPLE_DIR/service
  fi
  pushd $EXAMPLE_DIR/service
    if [[ "$(pwd)" == "${EXAMPLE_DIR}/service" ]] ; then
      echo " "
      echo "In $(pwd)"
      if [[ ! -z "$( ls -A '.' )" ]]; then
        rm ./*
      fi
      echo " "
    else
      echo "Wrong directory "
      exit
    fi
  popd

  echo "Done"
  exit
}

function do-compile-utilities() {
  echo " "
  echo "do-compile-utilities"

  if [[ ! -v NO_COMPILE_UTILITIES ]] ; then
    pushd $CERTIFIER_ROOT/utilities
      make -f cert_utility.mak
      make -f policy_utilities.mak
    popd
  fi

  echo "do-compile-utilities done"
}

function do-compile-program() {
  echo " "
  echo "do-compile-program"

  pushd $CERTIFIER_ROOT/vm_model_tools/src
    make -f cf_utility.mak
  popd

  echo "do-compile-program done"
}

function do-compile-certifier() {
  echo " "
  echo "do-compile-certifier"

  pushd $CERTIFIER_ROOT/certifier_service/certprotos
    if [[ ! -e "./certifier.proto.go" ]] ; then
      echo " "
      echo "making protobufs"
      protoc --go_opt=paths=source_relative --go_out=. --go_opt=M=certifier.proto ./certifier.proto
    fi
  popd

  pushd $CERTIFIER_ROOT/certifier_service
    pushd graminelib
      make dummy
    popd
   pushd oelib
     make dummy
   popd
    pushd isletlib
      make dummy
    popd
    pushd teelib
      make
    popd

    go build simpleserver.go
  popd

  echo "do-compile-certifier done"
}
echo "removing old programs"
do-fresh
echo "removing old programs"
do-compile-certifier
echo "simpleserver built"
do-compile-utilities
echo "utilities built"
do-compile-program
echo "cf_utility.exe built"

echo " "
echo "Unknown option: $1"
