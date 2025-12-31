#!/bin/bash
echo "process shell args"

if [ [ -v CERTIFIER_ROOT ] ]
then
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

echo "num args: $ARG_SIZE"
arg_string=$*

# Variables to find
#	POLICY_KEY_FILE_NAME
#	POLICY_CERT_FILE_NAME
#	POLICY_STORE_NAME
#	CRYPTSTORE_NAME
#	DOMAIN_NAME
#	ENCLAVE_TYPE
#	DATA_DIR
#	SYMMETRIC_ENCRYPTION_ALGORITHM
#	ASYMMETRIC_ENCRYPTION_ALGORITHM
#	PROGRAM_NAME
#	VM_NAME
#	TEST_TYPE

function process-args() {

	##let i=0
	#for T in \"${arg_string[@]}\"; do
		#echo "arg[$i]: ${T//'"'}"
		#let i=i+1
	#done

	IFS=' ' read -ra array <<< "$arg_string"
	for (( i=0; i < $ARG_SIZE; i++ )); do
	echo "ar[$i] ${array[i]}"
	done
}

process-args

