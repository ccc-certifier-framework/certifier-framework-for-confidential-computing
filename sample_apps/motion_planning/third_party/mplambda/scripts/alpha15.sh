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
    --env resources/se3/alpha_env-1.5.dae \
    --robot resources/se3/alpha_robot.dae \
    --start 0,1,0,0,-21.91,-4.11,-14.14 \
    --goal 0,1,0,0,-21.91,-4.11,68.86 \
    --min -281.64,-119.64,-176.86 \
    --max 189.05,189.18,174.86 \
    --time-limit 15 \
    --check-resolution 0.1
