#!/bin/bash

#########################################################
# clean-files.sh, Removes data files created by run
#########################################################

# This script removes the policy stores, cryptstores and application
# and service data used by the tests.  Run this first if you
# want to restart tests.

# --------------------------------------------------------------------------------

echo "Removing runtime data files"
if [[ ! -e "$EXAMPLE_DIR" ]] ; then
  echo "EXAMPLE_DIR missing or not set"
  exit
fi

pushd $EXAMPLE_DIR
  rm policy_store.dom0* cryptstore.dom0* quote_cert.crt ekchain.bin
  rm measurement cf_utility.measurement sev_cf_utility.measurement

  if [[ ! -e "./provisioning" ]] ; then
    echo "provisioning directory missing or not set"
    exit
  fi
  pushd provisioning
    rm ./*
  popd
  if [[ ! -e "./service" ]] ; then
    echo "service directory missing or not set"
    exit
  fi
  pushd service
   rm ./*
  popd
  if [[ ! -e "./cf_data" ]] ; then
    echo "cf_data directory missing or not set"
    exit
  fi
  pushd cf_data
    rm ./*
  popd
popd

echo "Removed runtime data files"

# --------------------------------------------------------------------------------

