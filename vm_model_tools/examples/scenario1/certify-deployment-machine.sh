#!/bin/bash

# ############################################################################
# certify deployment machine.sh 
# ############################################################################

set -Eeuo pipefail
Me=$(basename "$0")

# ------------------------------------------------------------------------------------------

# Argument proccessing
ARG_SIZE="$#"

if [[ ${CERTIFIER_ROOT+x} ]]; then
	echo "CERTIFIER_ROOT already set"
else
	echo "setting CERTIFIER_ROOT"
	pushd ../../.. > /dev/null
	CERTIFIER_ROOT=$(pwd) > /dev/null
	popd > /dev/null
fi

if [[ ${EXAMPLE_DIR+x} ]]; then
	echo "EXAMPLE_DIR already set"
else
	echo "setting EXAMPLE_DIR"
	EXAMPLE_DIR=$(pwd) > /dev/null
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
#	TEST_TYPE				-tt		simulated/real
#	COMPILE_UTILITIES			-cut		1 or 0
#	COMPILE_CF				-ccf		1 or 0
#	POLICY_FILE_NAME			-pfn		name
#	POLICY_SERVER_ADDRESS			-psa		ip address or localhost
#	POLICY_SERVER_PORT   			-psp		port number
#	KEY_SERVER_ADDRESS			-ksa		ip address or localhost
#	KEY_SERVER_PORT   			-ksp		port number
#	OPERATION         			-op 		name
#	CLEAN             			-clean 		0/1
#	VERBOSE           			-loud 		0/1
#       DEPLOYMENT_ENCLAVE_TYPE			-et1		enclave types
#       DEPLOYED_ENCLAVE_TYPE			-et2		enclave types

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
	echo "TEST_TYPE			-tt		simulated/real"
	echo "COMPILE_UTILITIES		-cut		1 or 0"
	echo "COMPILE_CF			-ccf		1 or 0"
	echo "POLICY_FILE_NAME		-pfn		name"
	echo "POLICY_SERVER_ADDRESS		-psa		ip address or localhost"
	echo "POLICY_SERVER_PORT   		-psp		port number"
	echo "KEY_SERVER_ADDRESS		-ksa		ip address or localhost"
	echo "KEY_SERVER_PORT   		-ksp		port number"
	echo "OPERATION     	   		-op 		operation"
	echo "CLEAN             		-clean		0/1"
        echo "DEPLOYMENT_ENCLAVE_TYPE		-et1		enclave types"
        echo "DEPLOYED_ENCLAVE_TYPE		-et2		enclave types"
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
DATA_DIR="./"
SYMMETRIC_ENCRYPTION_ALGORITHM="aes-256-gcm"
ASYMMETRIC_ENCRYPTION_ALGORITHM="RSA-4096"
VM_NAME="datica-sample-vm"
TEST_TYPE="simulated"
COMPILE_UTILITIES=1
COMPILE_CF=1
POLICY_FILE_NAME="policy.bin"
POLICY_SERVER_ADDRESS="localhost"
POLICY_SERVER_PORT="8123"
KEY_SERVER_ADDRESS="localhost"
KEY_SERVER_PORT="8120"
OPERATION=""
CLEAN=0
VERBOSE=1
DEPLOYMENT_ENCLAVE_TYPE="simulated-enclave"
DEPLOYED_ENCLAVE_TYPE="sev"


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
	echo "Operation:                             $OPERATION"
	echo "Clean:                                 $CLEAN"
	echo "Verbose:                               $VERBOSE"
	echo "Deployment enclave type                $DEPLOYMENT_ENCLAVE_TYPE"
	echo "Deployed enclave type                  $DEPLOYED_ENCLAVE_TYPE"
	echo "Enclave type:                          $ENCLAVE_TYPE"
	echo ""
}


arg_string=$*
function process-args() {

	IFS=' ' read -ra array <<< "$arg_string"
	for (( i=0; i < $ARG_SIZE; i++ )); do
		#echo "Processing arg $i: ${array[i]}"

		if [[ ${array[i]} = "-dn" ]]; then
			DOMAIN_NAME="${array[i+1]}"
		fi
		if [[ ${array[i]} = "-pkn" ]]; then
			POLICY_KEY_FILE_NAME="${array[i+1]}"
		fi
		if [[ ${array[i]} = "-cfn" ]]; then
			POLICY_CERT_FILE_NAME="${array[i+1]}"
		fi
		if [[ ${array[i]} = "-psn" ]]; then
			POLICY_STORE_NAME="${array[i+1]}"
		fi
		if [[ ${array[i]} = "-csn" ]]; then
			CRYPTSTORE_NAME="${array[i+1]}"
		fi
		if [[ ${array[i]} = "-et" ]]; then
			ENCLAVE_TYPE="${array[i+1]}"
		fi
		if [[ ${array[i]} = "-dd" ]]; then
			DATA_DIR="${array[i+1]}"
		fi
		if [[ ${array[i]} = "-sea" ]]; then
			SYMMETRIC_ENCRYPTION_ALGORITHM="${array[i+1]}"
		fi
		if [[ ${array[i]} = "-aen" ]]; then
			ASYMMETRIC_ENCRYPTION_ALGORITHM="${array[i+1]}"
		fi
		if [[ ${array[i]} = "-pn" ]]; then
			PROGRAM_NAME="${array[i+1]}"
		fi
		if [[ ${array[i]} = "-vmn" ]]; then
			VM_NAME="${array[i+1]}"
		fi
		if [[ ${array[i]} = "-tt" ]]; then
			TEST_TYPE="${array[i+1]}"
		fi
		if [[ ${array[i]} = "-cut" ]]; then
			COMPILE_UTILITIES="${array[i+1]}"
		fi
		if [[ ${array[i]} = "-ccf" ]]; then
			COMPILE_CF="${array[i+1]}"
		fi
		if [[ ${array[i]} = "-pfn" ]]; then
			POLICY_FILE_NAME="${array[i+1]}"
		fi
		if [[ ${array[i]} = "-psa" ]]; then
			POLICY_SERVER_ADDRESS="${array[i+1]}"
		fi
		if [[ ${array[i]} = "-psp" ]]; then
			POLICY_SERVER_PORT="${array[i+1]}"
		fi
		if [[ ${array[i]} = "-ksa" ]]; then
			KEY_SERVER_ADDRESS="${array[i+1]}"
		fi
		if [[ ${array[i]} = "-ksp" ]]; then
			KEY_SERVER_PORT="${array[i+1]}"
		fi
		if [[ ${array[i]} = "-op" ]]; then
			OPERATION="${array[i+1]}"
		fi
		if [[ ${array[i]} = "-clean" ]]; then
			CLEAN="${array[i+1]}"
		fi
		if [[ ${array[i]} = "-loud" ]]; then
			VERBOSE="${array[i+1]}"
		fi
		if [[ ${array[i]} = "-et1 " ]]; then
			DEPLOYMENT_ENCLAVE_TYPE="${array[i+1]}"
		fi
		if [[ ${array[i]} = "-et2" ]]; then
			DEPLOYED_ENCLAVE_TYPE="${array[i+1]}"
		fi
	done

	POLICY_CERT_FILE_NAME=$POLICY_CERT_FILE_NAME.$DOMAIN_NAME
	POLICY_STORE_NAME=$POLICY_STORE_NAME.$DOMAIN_NAME
	CRYPTSTORE_NAME=$CRYPTSTORE_NAME.$DOMAIN_NAME
}

# ------------------------------------------------------------------------------------------



function do-run() {
	echo " "
	echo "do-run"

	if [[ $DEPLOYMENT_ENCLAVE_TYPE != "simulated-enclave"  ]] ; then
		echo "Unsupported deployment enclave type: $DEPLOYMENT_ENCLAVE_TYPE"
		exit
	fi

	echo "Calling"
	echo "$CERTIFIER_ROOT/vm_model_tools/src/cf_utility.exe \
	  --cf_utility_help=false \
	  --init_trust=true \
	  --print_cryptstore=true \
	  --enclave_type=$DEPLOYMENT_ENCLAVE_TYPE \
	  --policy_domain_name=$DOMAIN_NAME \
	  --policy_key_cert_file=$POLICY_CERT_FILE_NAME \
	  --policy_store_filename=$POLICY_STORE_NAME \
	  --encrypted_cryptstore_filename=$CRYPTSTORE_NAME \
	  --symmetric_key_algorithm=aes-256-gcm  \
	  --public_key_algorithm=rsa-2048 \
	  --data_dir="$EXAMPLE_DIR/" \
	  --certifier_service_URL=$POLICY_SERVER_ADDRESS \
	  --service_port=$POLICY_SERVER_PORT --print_level=1 \
	  --trust_anchors=$EXAMPLE_DIR/cf_data/my_certs"
	echo " "

	echo "Program 1"
	$CERTIFIER_ROOT/vm_model_tools/src/cf_utility.exe \
	  --cf_utility_help=false \
	  --init_trust=true \
	  --print_cryptstore=true \
	  --enclave_type=$DEPLOYMENT_ENCLAVE_TYPE  \
	  --policy_domain_name=$DOMAIN_NAME \
	  --policy_key_cert_file=$POLICY_CERT_FILE_NAME \
	  --policy_store_filename=$POLICY_STORE_NAME \
	  --encrypted_cryptstore_filename=$CRYPTSTORE_NAME \
	  --symmetric_key_algorithm=aes-256-gcm  \
	  --public_key_algorithm=rsa-2048 \
	  --data_dir="$EXAMPLE_DIR/" \
	  --certifier_service_URL=$POLICY_SERVER_ADDRESS \
	  --service_port=$POLICY_SERVER_PORT --print_level=1
	echo " "

	sleep 3

	echo "Calling"
	echo "$CERTIFIER_ROOT/vm_model_tools/src/cf_utility.exe \
	  --cf_utility_help=false \
	  --init_trust=false \
	  --generate_symmetric_key=true \
	  --keyname=primary-store-encryption-key \
	  --enclave_type=$DEPLOYMENT_ENCLAVE_TYPE  \
	  --policy_domain_name=$DOMAIN_NAME \
	  --policy_key_cert_file=$POLICY_CERT_FILE_NAME \
	  --policy_store_filename=$POLICY_STORE_NAME \
	  --encrypted_cryptstore_filename=$CRYPTSTORE_NAME \
	  --symmetric_key_algorithm=aes-256-gcm  \
	  --public_key_algorithm=rsa-2048 \
	  --data_dir='$EXAMPLE_DIR/' \
	  --certifier_service_URL=$POLICY_SERVER_ADDRESS \
	  --service_port=$POLICY_SERVER_PORT --print_level=1"

	echo " "
	echo " Alternatively add \
	--trust_anchors=$CERTIFIER_ROOT/vm_model_tools/examples/scenario1/cf_data/my_certs"
	echo " "

	echo "Program 2"
	$CERTIFIER_ROOT/vm_model_tools/src/cf_utility.exe \
	  --cf_utility_help=false \
	  --init_trust=false \
	  --generate_symmetric_key=true \
	  --keyname=primary-store-encryption-key \
	  --enclave_type=$DEPLOYMENT_ENCLAVE_TYPE \
	  --policy_domain_name=$DOMAIN_NAME \
	  --policy_key_cert_file=$POLICY_CERT_FILE_NAME \
	  --policy_store_filename=$POLICY_STORE_NAME \
	  --encrypted_cryptstore_filename=$CRYPTSTORE_NAME \
	  --symmetric_key_algorithm=aes-256-gcm  \
	  --public_key_algorithm=rsa-2048 \
	  --data_dir="$EXAMPLE_DIR/" \
	  --certifier_service_URL=$POLICY_SERVER_ADDRESS \
	  --service_port=$POLICY_SERVER_PORT --print_level=1 \
	  --trust_anchors=$EXAMPLE_DIR/cf_data/my_certs
	echo ""
}

# -----------------------------------------------------------------------------------------------

echo "Processing arguments"
process-args
echo "Arguments processed"

if [[ $VERBOSE -eq 1 ]]; then
        print-variables
fi

echo " "
echo "Certify me"

if [ $OPERATION  == "run" ] ; then
  do-run
fi

echo "Certification complete "
echo " "
