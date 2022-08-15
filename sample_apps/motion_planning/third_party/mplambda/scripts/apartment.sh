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
    --env resources/se3/Apartment_env.dae \
    --robot resources/se3/Apartment_robot.dae \
    --start 0,0,0,-1,241.81,106.15,36.46 \
    --goal 0,0,0,-1,-31.19,-99.85,36.46 \
    --min -73.76,-179.59,-0.03 \
    --max 295.77,168.26,90.39 \
    --time-limit 150 \
    --check-resolution 0.1

