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

START=0.18132,0.249076,0.153913,1.47009,1.48902,-0.125871,-1.74715,-1.45724
# GOAL=0.38615,-1.08792,0.0778814,-1.02092,-0.820869,3.05061,-0.295709,-1.93488
GOAL=0.70,-0.65,1.3,0,0,0
GOALR=0.01,0.01,0.01,0.01,$PI,$PI
# --goal-radius=0.01,0.01,0.01,0.01,0.01,$PI \
    
./mpl_robot \
    --scenario fetch \
    --algorithm rrt \
    --coordinator "$COORDINATOR" \
    --jobs 1 \
    --env resources/AUTOLAB.dae \
    --env-frame=0.48,1.09,0.00,0,0,-$PI_2 \
    --goal=$GOAL \
    --goal-radius=$GOALR \
    --start=$START \
    --time-limit 120 \
    --check-resolution 0.01
