#!/bin/bash

cd "$(dirname "$0")/../build/Release"

COORDINATOR="$1"

if [ -z "$COORDINATOR" ] ; then
    echo "please specify the coordinator's address"
    exit 1
fi

./mpl_robot \
    --scenario se3 \
    --algorithm cforest \
    --coordinator "$COORDINATOR" \
    --jobs 10 \
    --env se3/Twistycool_env.dae \
    --robot se3/Twistycool_robot.dae \
    --start 0,1,0,0,270,160,-200 \
    --goal 0,1,0,0,270,160,-400 \
    --min 53.46,-21.25,-476.86 \
    --max 402.96,269.25,-91.0 \
    --time-limit 120 \
    --check-resolution 0.1
