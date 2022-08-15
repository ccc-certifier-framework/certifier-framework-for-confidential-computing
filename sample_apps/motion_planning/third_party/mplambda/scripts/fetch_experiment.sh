#!/bin/bash

cd "$(dirname "$0")/../build/Release"

SCENE="fetch"

COORDINATOR="$1"
INTERATIONS="$2"
SCENARIO="fetch"
ALGORITHM="rrt"
JOBS=1

if [ -z "$INTERATIONS" ] ; then
    echo "please specify the coordinator and number of iterations (in that order)"
    exit 1
fi

PI=3.141592653589793
PI_2=1.570796326794897

DIR="experiments/${SCENE}/${SCENARIO}_${ALGORITHM}_${JOBS}"
mkdir -p $DIR

for ((i=1; i<=$INTERATIONS; ++i)); do 
    echo "--- Iteration $i of $INTERATIONS ---"
    ./mpl_robot \
        --scenario "$SCENARIO" \
        --algorithm "$ALGORITHM" \
        --coordinator "$COORDINATOR" \
        --jobs 1 \
        --env resources/AUTOLAB.dae \
        --env-frame=0.57,-0.90,0.00,0,0,-$PI_2 \
        --goal=-1.07,0.16,0.88,0,0,0 \
        --goal-radius=0.01,0.01,0.01,0.01,0.01,$PI \
        --start=0.1,$PI_2,$PI_2,0,$PI_2,0,$PI_2,0 \
        --time-limit 300 \
        --check-resolution 0.01 \
    > "${DIR}/$(printf "%03d.out" $i)" 2>&1 &
    if (($i % 100 == 0)) ; then
        wait
    fi
done
wait
