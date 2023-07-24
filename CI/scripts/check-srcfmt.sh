#!/bin/bash
# Copyright 2018-2023 VMware, Inc.
# SPDX-License-Identifier: Apache-2.0
# #############################################################################
# Check source-code formatting, basically per Google style, fine-tuned to our
# code layout preferences as specified in .clang-format rules.
# #############################################################################

set -eu -o pipefail

CLANG_FMT_TOOL=$(which clang-format-11)

# Establish root-dir for Certifier library.
pushd "$(dirname "$0")" > /dev/null 2>&1

cd ../../

# shellcheck disable=SC2046
CERTIFIER_ROOT="$(pwd)"; export CERTIFIER_ROOT

popd > /dev/null 2>&1

pushd ${CERTIFIER_ROOT} > /dev/null 2>&1

set -x
# shellcheck disable=SC2046
${CLANG_FMT_TOOL} -i $(find . \( -name "*.[ch]" -o -name "*.cc" \) -print | grep -v -E 'third_party|protobufs-bin|\.pb.cc|\.pb.h')
set +x

popd > /dev/null 2>&1
