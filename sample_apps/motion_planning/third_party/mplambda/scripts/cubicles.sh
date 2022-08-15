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
    --env resources/se3/cubicles_env.dae \
    --robot resources/se3/cubicles_robot.dae \
    --start 0,1,0,0,-4.96,-40.62,70.57 \
    --goal 0,1,0,0,200.0,-40.62,70.57 \
    --min -508.88,-230.13,-123.75 \
    --max 319.62,531.87,101.0 \
    --time-limit 10 \
    --check-resolution 0.1

