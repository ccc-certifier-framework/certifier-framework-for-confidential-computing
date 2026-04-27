#!/bin/bash
# ############################################################################
# prepare-test.sh: Script to run build simple_app_under_tpm test environment.
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

NO_COMPILE_UTILITIES=1

echo " "
echo "Certifier root: $CERTIFIER_ROOT"
echo "Example directory: $EXAMPLE_DIR"

ARG_SIZE="$#"

if [[ $ARG_SIZE == 0 ]] ; then
  echo "Must call with arguments, as follows:"
  echo "  ./prepare-test.sh fresh [domain_name]"
  echo "  ./prepare-test.sh all [domain_name]"
  echo "  ./prepare-test.sh compile-utilities [domain_name]"
  echo "  ./prepare-test.sh make-keys [domain_name]"
  echo "  ./prepare-test.sh compile-program [domain_name]"
  echo "  ./prepare-test.sh compile-certifier [domain_name]"
  exit
fi

if [[ $ARG_SIZE == 1 ]] ; then
  DOMAIN_NAME="datica-test"
fi
if [[ $ARG_SIZE == 2 ]] ; then
  DOMAIN_NAME=$2
fi
echo "domain name: $DOMAIN_NAME"

POLICY_KEY_FILE_NAME="policy_key_file.$DOMAIN_NAME"
POLICY_CERT_FILE_NAME="policy_cert_file.$DOMAIN_NAME"
echo "policy key file name: $POLICY_KEY_FILE_NAME"
echo "policy cert file name: $POLICY_CERT_FILE_NAME"

POLICY_STORE_NAME="policy_store.$DOMAIN_NAME"
echo "policy store name: $POLICY_STORE_NAME"

function do-fresh() {
  echo " "
  echo "do-fresh"

  if [[ ! -v NO_COMPILE_UTILITIES ]] ; then
    pushd $CERTIFIER_ROOT/utilities
      make clean -f cert_utility.mak
      make clean -f policy_utilities.mak
    popd
  fi

  pushd $EXAMPLE_DIR
    make clean -f tpm_example_app_new_api.mak
  popd

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

  pushd $EXAMPLE_DIR/service
    if [[ "$(pwd)" == "${EXAMPLE_DIR}/service" ]] ; then
      echo " "
      echo "In $(pwd)"
      if [[ ! -z "$( ls -A '.' )" ]]; then
        rm ./*
      fi
    else
      echo "Wrong directory "
      exit
    fi
  popd

  pushd $EXAMPLE_DIR/app1_data
    if [[ "$(pwd)" == "${EXAMPLE_DIR}/app1_data" ]] ; then
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

  pushd $EXAMPLE_DIR/app2_data
    if [[ "$(pwd)" == "${EXAMPLE_DIR}/app2_data" ]] ; then
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

  echo "Done"
  exit
}

function do-compile-utilities() {
  echo " "
  echo "do-compile-utilities"

  pushd $CERTIFIER_ROOT/utilities
    make -f cert_utility.mak
    make -f policy_utilities.mak
  popd

  echo "do-compile-utilities done"
}

function do-make-keys() {
  echo " "
  echo "do-make-keys"

  if [[ ! -d "$EXAMPLE_DIR/provisioning" ]] ; then
    mkdir $EXAMPLE_DIR/provisioning
  fi

  pushd $EXAMPLE_DIR/provisioning
    authorityName="$DOMAIN_NAME/policyAuthority"
    $CERTIFIER_ROOT/utilities/cert_utility.exe  \
      --operation=generate-policy-key-and-test-keys  \
      --policy_authority_name=$authorityName   \
      --policy_key_output_file=$POLICY_KEY_FILE_NAME  \
      --policy_cert_output_file=$POLICY_CERT_FILE_NAME \
  popd

  echo "do-make-keys done"
}

function do-compile-program() {
  echo " "
  echo "do-compile-program"

  pushd $EXAMPLE_DIR
    pushd ./provisioning
      $CERTIFIER_ROOT/utilities/embed_policy_key.exe  \
        --input=$POLICY_CERT_FILE_NAME --output=../policy_key.cc
    popd

    make -f tpm_example_app_new_api.mak
  popd

  echo "do-compile-program done"
}

function make-root-list() {

  echo "root cert in prepare-test"
  echo ""
  pushd $EXAMPLE_DIR/provisioning
    cp /var/lib/swtpm-localca/swtpm-localca-rootca-cert.pem root.pem
    openssl x509 -inform pem -in root.pem -outform der -out root.der
    openssl x509 -inform der -in root.der -text
    $CERTIFIER_ROOT/utilities/make_der_cert_chain.exe \
	--output="trustedRoots.bin" -init=true \
	--new_cert_file="root.der" --add_cert=true
  popd
  echo ""
  echo "make-root-list done"
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
    pushd tpmlib
      make
    popd

    go build simpleserver.go

  popd

  echo "do-compile-certifier done"
}

function do-all() {
  echo " "
  echo "do-all"

  # do-compile-utilities
  do-make-keys
  do-compile-program
  do-compile-certifier
  make-root-list
    pushd $EXAMPLE_DIR
    if [[ ! -d "$EXAMPLE_DIR/provisioning" ]] ; then
      mkdir $EXAMPLE_DIR/provisioning
    fi
    if [[ ! -d "$EXAMPLE_DIR/service" ]] ; then
      mkdir $EXAMPLE_DIR/service
    fi
  popd

  cp $EXAMPLE_DIR/provisioning/trustedRoots.bin $EXAMPLE_DIR/service
  
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

if [ "$1" == "compile-certifier" ] ; then
  echo " "
  do-compile-certifier
  exit
fi

echo " "
echo "Unknown option: $1"
