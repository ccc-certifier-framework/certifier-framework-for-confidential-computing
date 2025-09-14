#!/bin/bash
# ############################################################################
# prepare-test.sh: Script to run build simple_app under the app service.
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

if [[ ! -v APP_SERVICE_DIR ]] ; then
  pushd $CERTIFIER_ROOT/application_service
    APP_SERVICE_DIR=$(pwd)
  popd
fi

echo " "
echo "Certifier root: $CERTIFIER_ROOT"
echo "Example directory: $EXAMPLE_DIR"
echo "App service directory: $APP_SERVICE_DIR"

ARG_SIZE="$#"

if [[ $ARG_SIZE == 0 || $ARG_SIZE > 2 ]] ; then
  echo "Must call with arguments, as follows:"
  echo "  ./prepare-test.sh fresh [domain_name]"
  echo "  ./prepare-test.sh all [domain_name]"
  echo "  ./prepare-test.sh compile-utilities [domain_name]"
  echo "  ./prepare-test.sh make-keys [domain_name]"
  echo "  ./prepare-test.sh compile-program [domain_name]"
  echo "  ./prepare-test.sh make-policy [domain_name]"
  echo "  ./prepare-test.sh compile-certifier [domain_name]"
  echo "  ./prepare-test.sh copy-files [domain_name]"
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
echo "Policy key file name: $POLICY_KEY_FILE_NAME"
echo "Policy cert file name: $POLICY_CERT_FILE_NAME"

POLICY_STORE_NAME="policy_store.$DOMAIN_NAME"
echo "Policy store name: $POLICY_STORE_NAME"

APP_SERVICE_POLICY_KEY_CERT=""

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
    make clean -f example_app_new_api.mak
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

function do-make-service () {
echo " "
echo "do-make-service"

  pushd $APP_SERVICE_DIR

    if [[ -e "$APP_SERVICE_DIR/app_service.exe" && -d "$APP_SERVICE_DIR/service" ]] ; then
        echo "App service already built"
        if [[ -e "$APP_SERVICE_DIR/service/policy_cert_file.app_service" ]] ; then
          APP_SERVICE_POLICY_KEY_CERT="$APP_SERVICE_DIR/service/policy_cert_file.app_service"
        fi
        return
    fi
    echo "Building app service"
    ./prepare-test.sh fresh "app_service"
    ./prepare-test.sh all "se" "app_service"
    ./run-test.sh fresh
    ./run-test.sh run  "se" "app_service"
  popd

echo "do-make-service done"
}

function do-compile-utilities() {
  echo "do-compile-utilities"

  if [[ ! -v NO_COMPILE_UTILITIES ]] ; then
    pushd $CERTIFIER_ROOT/utilities
      make -f cert_utility.mak
      make -f policy_utilities.mak
    popd
  fi

  echo "do-compile-utilities done"
}

function do-make-keys() {
  echo "do-make-keys"

  do-make-service

  if [[ ! -e "$EXAMPLE_DIR/provisioning" ]] ; then
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
  echo "do-compile-program"

  pushd $EXAMPLE_DIR
    pushd ./provisioning
    $CERTIFIER_ROOT/utilities/embed_policy_key.exe  \
      --input=$POLICY_CERT_FILE_NAME --output=../policy_key.cc
    popd

    make all -f example_app_new_api.mak
    # This make also makes start_program
  popd

  echo "do-compile-program done"
}

function do-make-policy() {
  echo "do-make-policy"

  do-make-service   # Gets service key
  pushd $EXAMPLE_DIR/provisioning

    echo " "

    if [[ "$APP_SERVICE_POLICY_KEY_CERT" == "" ]] ; then
      echo "app attestation key does not exist"
      exit
    fi

    echo "got signing cert: $APP_SERVICE_POLICY_KEY_CERT"

    $CERTIFIER_ROOT/utilities/measurement_utility.exe      \
      --type=hash --input=../service_example_app.exe --output=service_example_app.measurement

    $CERTIFIER_ROOT/utilities/make_unary_vse_clause.exe \
      --cert_subject=$APP_SERVICE_POLICY_KEY_CERT --verb="is-trusted-for-attestation" \
      --output=ts1.bin
    $CERTIFIER_ROOT/utilities/make_indirect_vse_clause.exe \
      --key_subject=$POLICY_KEY_FILE_NAME --verb="says" \
      --clause=ts1.bin --output=vse_policy1.bin

    $CERTIFIER_ROOT/utilities/make_unary_vse_clause.exe \
      --key_subject="" --measurement_subject="service_example_app.measurement" \
      --verb="is-trusted" --output=ts2.bin

    $CERTIFIER_ROOT/utilities/make_indirect_vse_clause.exe \
      --key_subject=$POLICY_KEY_FILE_NAME --verb="says" \
      --clause=ts2.bin --output=vse_policy2.bin

    $CERTIFIER_ROOT/utilities/make_signed_claim_from_vse_clause.exe \
      --vse_file=vse_policy1.bin --duration=9000 --private_key_file=$POLICY_KEY_FILE_NAME \
      --output=signed_claim_1.bin

    $CERTIFIER_ROOT/utilities/make_signed_claim_from_vse_clause.exe \
      --vse_file=vse_policy2.bin  --duration=9000  \
      --private_key_file=$POLICY_KEY_FILE_NAME --output=signed_claim_2.bin

    $CERTIFIER_ROOT/utilities/package_claims.exe \
      --input=signed_claim_1.bin,signed_claim_2.bin --output=policy.bin
    $CERTIFIER_ROOT/utilities/print_packaged_claims.exe --input=policy.bin

    echo " "
  popd

  echo "do-make-policy done"
}

function do-compile-certifier() {

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

function do-copy-files() {
  echo "do-copy-files"

  pushd $EXAMPLE_DIR
    if [[ ! -e "$EXAMPLE_DIR/provisioning" ]] ; then
      mkdir $EXAMPLE_DIR/provisioning
    fi
    if [[ ! -e "$EXAMPLE_DIR/service" ]] ; then
      mkdir $EXAMPLE_DIR/service
    fi
    if [[ ! -e "$EXAMPLE_DIR/app1_data" ]] ; then
      mkdir $EXAMPLE_DIR/app1_data
    fi
    if [[ ! -e "$EXAMPLE_DIR/app2_data" ]] ; then
      mkdir $EXAMPLE_DIR/app2_data
    fi
  popd

  pushd $EXAMPLE_DIR/provisioning
    cp -p $POLICY_KEY_FILE_NAME $POLICY_CERT_FILE_NAME policy.bin $EXAMPLE_DIR/service
    cp -p $POLICY_CERT_FILE_NAME service_example_app.measurement policy.bin $EXAMPLE_DIR/app1_data
    cp -p $POLICY_CERT_FILE_NAME service_example_app.measurement policy.bin $EXAMPLE_DIR/app2_data
    cp $APP_SERVICE_DIR/service_data/service_attestation_cert.bin ./provisioning
  popd
}

function do-all() {
  echo " "
  echo "do-all"

  do-compile-utilities
  do-make-service
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

echo " "
echo "Unknown option: $1"
