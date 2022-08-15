#!/bin/bash

cd "$(dirname "$0")/../build/Release"

SCENE="apartment"

COORDINATOR="$1"
SCENARIO="$2"
ALGORITHM="$3"
JOBS="$4"
TIME_LIMIT="$5"
INTERATIONS="$6"

if [ -z "$INTERATIONS" ] ; then
    echo "please specify the coordinator, scenario, algorithm, number of jobs, time limit, and number of iterations (in that order)"
    exit 1
fi


DIR="experiments/${SCENE}/${SCENARIO}_${ALGORITHM}_${JOBS}_${TIME_LIMIT}"
mkdir -p $DIR

for ((i=1; i<=$INTERATIONS; ++i)); do 
    echo "--- Iteration $i of $INTERATIONS ---"
    ./mpl_robot \
        --scenario "$SCENARIO" \
        --algorithm "$ALGORITHM" \
        --coordinator "$COORDINATOR" \
        --jobs $JOBS \
        --env resources/se3/Apartment_env.dae \
        --robot resources/se3/Apartment_robot.dae \
        --start 0,0,0,-1,241.81,106.15,36.46 \
        --goal 0,0,0,-1,-31.19,-99.85,36.46 \
        --min -73.76,-179.59,-0.03 \
        --max 295.77,168.26,90.39 \
        --time-limit $TIME_LIMIT \
        --check-resolution 0.1 \
    > "${DIR}/$(printf "%03d.out" $i)" 2>&1 & 
    if (($i % 100 == 0)) ; then
        wait
    fi
done
