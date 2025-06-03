#!/bin/bash
# #############################################################################
# Source code analysis with cppcheck. If anything fails, exit
# with a non-zero $rc, and print an informational error message.
# #############################################################################

pushd "$(dirname "$0")" > /dev/null 2>&1 || exit

cd ../../

CERTIFIER_ROOT="$(pwd)"

popd > /dev/null 2>&1 || exit

cppcheck --error-exitcode=1 -i third_party -i thirdparty -i json/tests -i json/json-schema-validator \
	-i json/docs -i acl_lib --suppress=normalCheckLevelMaxBranches ${CERTIFIER_ROOT}
rc=$?

if [ $rc -ne 0 ]; then
    echo "cppcheck static analysis failed. Run cppcheck --error-exitcode=1 -i third_party --suppress=normalCheckLevelMaxBranches CERTIFIER_ROOT to get more details."
fi

cppcheck --error-exitcode=1 -i acl_lib/test_acl.cc --suppress=normalCheckLevelMaxBranches ${CERTIFIER_ROOT}/acl_lib
rc=$?

if [ $rc -ne 0 ]; then
    echo "cppcheck static analysis failed. Run cppcheck --error-exitcode=1 -i third_party --suppress=normalCheckLevelMaxBranches CERTIFIER_ROOT to get more details."
fi

cppcheck --error-exitcode=1 --suppress=normalCheckLevelMaxBranches --suppress=syntaxError ${CERTIFIER_ROOT}/acl_lib/test_acl.cc
rc=$?

if [ $rc -ne 0 ]; then
    echo "cppcheck static analysis failed. Run cppcheck --error-exitcode=1 -i third_party --suppress=normalCheckLevelMaxBranches CERTIFIER_ROOT to get more details."
fi

exit $rc
