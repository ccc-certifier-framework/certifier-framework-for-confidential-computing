#!/bin/bash

#########################################################################################
# util-args.sh shell argument processing 
#########################################################################################

source ./util-arg-processing.inc

# ------------------------------------------------------------------------------------------


# This script will print the above options if called with -print as first argument.
#echo "Start"

if [[ $1 = "-print" ]]; then
	print-options
else
	process-args
	print-variables
fi

