#!/bin/bash

pushd ./src/test
  ./util_tests.sh -cu 1 -pk 1 -clean 0 -rt 1 -recertify 1 -loud 1
popd

