#!/bin/bash

DIR="$(dirname "$0")/../build/Release"

if [ ! -d "$DIR" ] ; then
    echo "$DIR does not exist"
    exit 1
fi

cd "$DIR"

if [ ../Debug/mpl_lambda_pseudo -nt ./mpl_lambda_pseudo ] ; then
    echo "DEBUG build is newer than RELEASE build, using DEBUG build"
    cd ../Debug
fi

PI=3.141592653589793
PI_2=1.570796326794897

COORDINATOR="$1"

if [ -z "$COORDINATOR" ] ; then
    echo "please specify the coordinator's address"
    exit 1
fi

./mpl_robot \
    --scenario fetch \
    --algorithm cforest \
    --coordinator "$COORDINATOR" \
    --jobs 8 \
    --env AUTOLAB.dae \
    --env-frame=0.57,-0.90,0.00,0,0,-$PI_2 \
    --goal=-1.07,0.16,0.88,0,0,0 \
    --goal-radius=0.01,0.01,0.01,0.01,0.01,$PI \
    --start=0.1,$PI_2,$PI_2,0,$PI_2,0,$PI_2,0 \
    --time-limit 300 \
    --check-resolution 0.01
