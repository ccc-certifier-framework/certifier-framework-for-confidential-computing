#!/bin/bash

echo "Removing files"
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
echo "Removed files"


