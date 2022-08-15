#!/bin/bash

cd "$(dirname "$0")/../build/Lambda"

COORDINATOR="$1"

if [ -z "$COORDINATOR" ] ; then
    echo "please specify the coordinator's address"
    exit 1
fi

./mpl_robot \
    --scenario se3 \
    --algorithm rrt \
    --coordinator "$COORDINATOR" \
    --jobs 10 \
    --env resources/se3/Home_env.dae \
    --robot resources/se3/Home_robot.dae \
    --start 0,1,0,0,252.95,-214.95,46.19 \
    --goal 0,1,0,0,262.95,75.05,46.19 \
    --min -383.802642822,-371.469055176,-0.196851730347 \
    --max 324.997131348,337.893371582,142.332290649 \
    --time-limit 150 \
    --check-resolution 0.1

