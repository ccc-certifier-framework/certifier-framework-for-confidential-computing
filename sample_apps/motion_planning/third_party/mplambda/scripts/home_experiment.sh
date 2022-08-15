#!/bin/bash

cd "$(dirname "$0")/../build/Release"

SCENE="home"

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
        --env resources/se3/Home_env.dae \
        --robot resources/se3/Home_robot.dae \
        --start 0,1,0,0,252.95,-214.95,46.19 \
        --goal 0,1,0,0,262.95,75.05,46.19 \
        --min -383.802642822,-371.469055176,-0.196851730347 \
        --max 324.997131348,337.893371582,142.332290649 \
        --time-limit $TIME_LIMIT \
        --check-resolution 0.1 \
    > "${DIR}/$(printf "%03d.out" $i)" 2>&1 &
    if (($i % 100 == 0)) ; then
        wait
    fi
done
