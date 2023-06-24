#!/bin/bash
# #############################################################################
# Check 'gofmt' on all Go-files in the source code. If anything fails, exit
# with a non-zero $rc, and print an informational error message.
# #############################################################################

pushd "$(dirname "$0")" > /dev/null 2>&1 || exit

cd ../../

CERTIFIER_ROOT="$(pwd)"

popd > /dev/null 2>&1 || exit

files=$(gofmt -l "${CERTIFIER_ROOT}")
[ -z "$files" ]
rc=$?
if [ $rc -ne 0 ]; then
    echo "Run 'gofmt -w' on these files to update them in-place with default gofmt formatting:"
    for file in $files; do echo "  ${file}"; done
fi

exit $rc
