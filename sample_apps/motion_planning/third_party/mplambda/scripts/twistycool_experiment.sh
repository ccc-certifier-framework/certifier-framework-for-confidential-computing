#!/bin/bash

cd "$(dirname "$0")/../build/Release"

SCENE="twistycool"

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
        --env resources/se3/Twistycool_env.dae \
        --robot resources/se3/Twistycool_robot.dae \
        --start 0,1,0,0,270,160,-200 \
        --goal 0,1,0,0,270,160,-400 \
        --min 53.46,-21.25,-476.86 \
        --max 402.96,269.25,-91.0 \
        --time-limit $TIME_LIMIT \
        --check-resolution 0.1 \
    > "${DIR}/$(printf "%03d.out" $i)" 2>&1 &
    if (($i % 100 == 0)) ; then
        wait
    fi
done
