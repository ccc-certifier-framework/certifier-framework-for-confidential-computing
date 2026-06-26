#!/bin/bash

pushd ./src/test
  ./util-tests.sh -cu 1 -cp 1 -pk 1 -clean 1 -rt 1 -recertify 1 -loud 1
popd

