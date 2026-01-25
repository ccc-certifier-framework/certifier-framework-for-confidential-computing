#!/bin/bash

#########################################################
# clean-files.sh, Removes data files created by run
#########################################################

# This script removes the policy stores, cryptstores and application
# and service data used by the tests.  Run this first if you
# want to restart tests.

echo "Removing runtime data files"
rm policy_store.dom0* cryptstore.dom0*
pushd provisioning
rm ./*
popd
pushd service
rm ./*
popd
pushd cf_data
rm ./*
popd
rm cf_utility.measurement sev_cf_utility.measurement
echo "Removed runtime data files"


