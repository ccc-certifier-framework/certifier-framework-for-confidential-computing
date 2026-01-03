#!/bin/bash

# ############################################################################
# build-certifier.sh: Script to build certifier and utilities
# ############################################################################

set -Eeuo pipefail
Me=$(basename "$0")

source ./arg-processing.inc

# ------------------------------------------------------------------------------------------


function do-fresh() {
  echo " "
  echo "do-fresh"

  if [[ $CLEAN -eq 1 ]] ; then
	echo "cleaning programs and utilities"
	pushd $CERTIFIER_ROOT/utilities
	make clean -f cert_utility.mak
	make clean -f policy_utilities.mak
	popd

    	echo "cleaning cf_program"
  	pushd $CERTIFIER_ROOT/vm_model_tools/src
    	make clean -f cf_utility.mak
  	popd
  else
  	echo "not cleaning programs or utilities"
  fi

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

  echo "Done fresh"
  echo ""
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

function do-compile-program() {
	echo " "
	echo "do-compile-program"

	pushd $CERTIFIER_ROOT/vm_model_tools/src
	if [[ $DEPLOYED_ENCLAVE_TYPE = "sev-enclave" && $TEST_TYPE = "simulated" ]]; then
		make -f cf_utility.mak
	else
		CFLAGS += '-DSEV_DUMMY_GUEST' make -f cf_utility.mak
	fi
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

echo "processing arguments"
process-args
echo "processed arguments"

if [[ $VERBOSE -eq 1 ]]; then                   
        print-variables                         
fi

if [[ $CLEAN -eq 1 ]]; then
	echo "Removing old programs"
	do-fresh
	echo "Removed old programs"
else
	echo "Not removing existing versions"
fi

echo "compiling utilities"
do-compile-utilities
echo "utilities built"

echo "compiling cf_utility.exe"
do-compile-program
echo "cf_utility.exe built"

echo "compiling simpleserver"
do-compile-certifier
echo "simpleserver built"
