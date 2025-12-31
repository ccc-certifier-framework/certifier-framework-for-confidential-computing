#!/bin/bash

# Argument proccessing
ARG_SIZE="$#"

if [[ -z $CERTIFIER_ROOT ]] ; then
	pushd ../../..
	CERTIFIER_ROOT=$(pwd)
	popd
fi

if [[ -z $EXAMPLE_DIR ]]; then
	EXAMPLE_DIR=$(pwd)
fi

#echo ""
#echo "Starting"

# Variables to find
#	Variable NAME				Flag		Values
#	POLICY_KEY_FILE_NAME			-pkn		name
#	POLICY_CERT_FILE_NAME			-cfn		name
#	POLICY_STORE_NAME			-psn		name
#	CRYPTSTORE_NAME				-csn		name
#	DOMAIN_NAME				-dn		name
#	ENCLAVE_TYPE				-et		enclave type
#	DATA_DIR				-dd		directory
#	SYMMETRIC_ENCRYPTION_ALGORITHM		-sea		alg name (see certifier)
#	ASYMMETRIC_ENCRYPTION_ALGORITHM		-aen		alg name (see certifier)
#	PROGRAM_NAME				-pn		name
#	VM_NAME					-vmn		name
#	TEST_TYPE				-tt		test/real
#	COMPILE_UTILITIES			-cut		1 or 0
#	COMPILE_CF				-ccf		1 or 0
#	POLICY_FILE_NAME			-pfn		name
#	POLICY_SERVER_ADDRESS			-psa		ip address or localhost
#	POLICY_SERVER_PORT   			-psp		port number
#	KEY_SERVER_ADDRESS			-ksa		ip address or localhost
#	KEY_SERVER_PORT   			-ksp		port number

function print-options() {

	echo "Defined flags and variables"
	echo ""
	echo "Variable name			Flag		Value"
	echo "POLICY_KEY_FILE_NAME		-pkn		name"
	echo "POLICY_CERT_FILE_NAME		-cfn		name"
	echo "POLICY_STORE_NAME		-psn		name"
	echo "CRYPTSTORE_NAME			-csn		name"
	echo "DOMAIN_NAME			-dn		name"
	echo "ENCLAVE_TYPE			-et		enclave type"
	echo "DATA_DIR			-dd		directory"
	echo "SYMMETRIC_ENCRYPTION_ALGORITHM	-sea		alg name (see certifier)"
	echo "ASYMMETRIC_ENCRYPTION_ALGORITHM	-aen		alg name (see certifier)"
	echo "PROGRAM_NAME			-pn		name"
	echo "VM_NAME				-vmn		name"
	echo "TEST_TYPE			-tt		test/real"
	echo "COMPILE_UTILITIES		-cut		1 or 0"
	echo "COMPILE_CF			-ccf		1 or 0"
	echo "POLICY_FILE_NAME		-pfn		name"
	echo "POLICY_SERVER_ADDRESS		-psa		ip address or localhost"
	echo "POLICY_SERVER_PORT   		-psp		port number"
	echo "KEY_SERVER_ADDRESS		-ksa		ip address or localhost"
	echo "KEY_SERVER_PORT   		-ksp		port number"
	echo ""
}

# Defaults

DOMAIN_NAME="datica"
POLICY_KEY_FILE_NAME="policy_key_file"
POLICY_CERT_FILE_NAME="policy_cert_file"
POLICY_STORE_NAME="policy_store"
CRYPTSTORE_NAME="cryptstore"
PROGRAM_NAME="datica-program"
ENCLAVE_TYPE="simulated-enclave"
DATA_DIR="./cf_data"
SYMMETRIC_ENCRYPTION_ALGORITHM="aes256-gcm"
ASYMMETRIC_ENCRYPTION_ALGORITHM="RSA-4096"
VM_NAME="datica-sample-vm"
TEST_TYPE="test"
COMPILE_UTILITIES=1
COMPILE_CF=1
POLICY_FILE_NAME="policy.bin"
POLICY_SERVER_ADDRESS="localhost"
POLICY_SERVER_PORT="8123"
KEY_SERVER_ADDRESS="localhost"
KEY_SERVER_PORT="8120"


function print-variables() {
	echo ""
	echo "Certifier root:                        $CERTIFIER_ROOT"
	echo "Example directory:                     $EXAMPLE_DIR"
	echo "Domain name:                           $DOMAIN_NAME"
	echo "Policy Key file name:                  $POLICY_KEY_FILE_NAME"
	echo "Policy cert file name:                 $POLICY_CERT_FILE_NAME"
	echo "Policy store file name:                $POLICY_STORE_NAME"
	echo "Cryptstore file name:                  $CRYPTSTORE_NAME"
	echo "Program name:                          $PROGRAM_NAME"
	echo "Enclave type:                          $ENCLAVE_TYPE"
	echo "Data directory name:                   $DATA_DIR"
	echo "Encryption Algorithm:                  $SYMMETRIC_ENCRYPTION_ALGORITHM"
	echo "Public key algorithm:                  $ASYMMETRIC_ENCRYPTION_ALGORITHM"
	echo "VM name:                               $VM_NAME"
	echo "Test type:                             $TEST_TYPE"
	echo "Compile utilities flag:                $COMPILE_UTILITIES"
	echo "Compile Certifier flag:                $COMPILE_CF"
	echo "Policy file name:                      $POLICY_FILE_NAME"
	echo "Policy Server address:                 $POLICY_SERVER_ADDRESS"
	echo "Policy server port:                    $POLICY_SERVER_PORT"
	echo "Key server address:                    $KEY_SERVER_ADDRESS"
	echo "Key server port:                       $KEY_SERVER_PORT"
	echo ""
}


arg_string=$*
function process-args() {


	IFS=' ' read -ra array <<< "$arg_string"
	for (( i=0; i < $ARG_SIZE; i++ )); do
		# echo "Processing arg $i: ${array[i]}"

		if [ ${array[i]} = "-dn" ]; then
			DOMAIN_NAME="${array[i+1]}"
		fi
		if [ ${array[i]} = "-pkn" ]; then
			POLICY_KEY_FILE_NAME="${array[i+1]}"
		fi
		if [ ${array[i]} = "-cfn" ]; then
			POLICY_CERT_FILE_NAME="${array[i+1]}"
		fi
		if [ ${array[i]} = "-psn" ]; then
			POLICY_STORE_NAME="${array[i+1]}"
		fi
		if [ ${array[i]} = "-csn" ]; then
			CRYPTSTORE_NAME="${array[i+1]}"
		fi
		if [ ${array[i]} = "-et" ]; then
			ENCLAVE_TYPE="${array[i+1]}"
		fi
		if [ ${array[i]} = "-dd" ]; then
			DATA_DIR="${array[i+1]}"
		fi
		if [ ${array[i]} = "-sea" ]; then
			SYMMETRIC_ENCRYPTION_ALGORITHM="${array[i+1]}"
		fi
		if [ ${array[i]} = "-aen" ]; then
			ASYMMETRIC_ENCRYPTION_ALGORITHM="${array[i+1]}"
		fi
		if [ ${array[i]} = "-pn" ]; then
			PROGRAM_NAME="${array[i+1]}"
		fi
		if [ ${array[i]} = "-vmn" ]; then
			VM_NAME="${array[i+1]}"
		fi
		if [ ${array[i]} = "-tt" ]; then
			TEST_TYPE="${array[i+1]}"
		fi
		if [ ${array[i]} = "-cut" ]; then
			COMPILE_UTILITIES="${array[i+1]}"
		fi
		if [ ${array[i]} = "-ccf" ]; then
			COMPILE_CF="${array[i+1]}"
		fi
		if [ ${array[i]} = "-pfn" ]; then
			POLICY_FILE_NAME="${array[i+1]}"
		fi
		if [ ${array[i]} = "-psa" ]; then
			POLICY_SERVER_ADDRESS="${array[i+1]}"
		fi
		if [ ${array[i]} = "-psp" ]; then
			POLICY_SERVER_PORT="${array[i+1]}"
		fi
		if [ ${array[i]} = "-ksa" ]; then
			KEY_SERVER_ADDRESS="${array[i+1]}"
		fi
		if [ ${array[i]} = "-ksp" ]; then
			KEY_SERVER_PORT="${array[i+1]}"
		fi
	done

	POLICY_CERT_FILE_NAME=$POLICY_CERT_FILE_NAME.$DOMAIN_NAME
	POLICY_STORE_NAME=$POLICY_STORE_NAME.$DOMAIN_NAME
	CRYPTSTORE_NAME=$CRYPTSTORE_NAME.$DOMAIN_NAME
}


# This script will print the above options if called with -print as first argument.
#echo "Start"

if [ $1 = "-print" ]; then
	print-options
else
	process-args
	print-variables
fi

