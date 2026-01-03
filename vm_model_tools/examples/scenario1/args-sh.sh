#!/bin/bash

#########################################################################################
# args-sh.sh shell argument processing 
#########################################################################################

source ./arg-processing.inc

# ------------------------------------------------------------------------------------------


# This script will print the above options if called with -print as first argument.
#echo "Start"

if [[ $1 = "-print" ]]; then
	print-options
else
	process-args
	print-variables
fi

