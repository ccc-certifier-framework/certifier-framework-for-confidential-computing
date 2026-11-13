#!/bin/bash

#########################################################################################
# Sample startup script in the vm
#########################################################################################

wait 3

# First, just hello world
startup_program.exe

# Later do the key provisioning test after starting the certifier on the
# deployment machine.
# We have to set the variables (get domain name from etc/domains):
$ALLARGS="-tt real -bss 0 -ccf 0 -loud 1 -dn dom0 - op run " \
   "-pn cf-utility -pk 1 -et1 'simulated-enclave' -et2 'sev-enclave' "
#   certify-deployment-machine.sh $ALLARGS
#   generate-and-store-secret-for-deployment.sh $ALLARGS
#   obtain-application-secrets.sh $ALLARGS

