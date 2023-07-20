# #####################################################################################
# Copyright (c) 2021-23, VMware Inc, and the Certifier Authors.  All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ##############################################################################
"""
Basic pytests to exercise Certifier Tests shared library.

Test cases probe into and directly exercise a few built-in methods available
through the shared library, just as a way of sanity verification of the shared
library.

certifier_tests.cc has a collection of C++ unit-tests for different
sub-systems. This Python driver invokes those tests to ensure that
the Python bindings still work correctly.

"""
from inspect import getmembers, isbuiltin, ismodule

# To resolve library references, run as: PYTHONPATH=../.. pytest <filename>.py
import libcertifier_tests as libct

# pylint: disable=c-extension-no-member

# ##############################################################################
# To see output, run: pytest --capture=tee-sys -v
def test_getmembers_of_certifier_tests():
    """
    Test basic coherence of Certifier Tests's shared module imported here.
    """
    assert ismodule(libct) is True

    cft_builtin_methods = getmembers(libct, isbuiltin)
    cft_builtin_names = [ item[0] for item in cft_builtin_methods]

    # Verify existence of few key methods of Certifier tests from diff .h files
    # If we find one, we expect build would have picked up all other test fns
    # from that <test>.cc file.
    for item in [  'test_seal'              # From primitive_tests.h
                 , 'test_signed_claims'     # From claims_tests.h
                 , 'test_protect'           # From store_tests.h
                 , 'test_policy_store'
                 , 'test_init_and_recover_containers'
                 , 'test_encrypt'           # From support_tests.h
                ]:
        assert item in cft_builtin_names

    print( )

    for item in cft_builtin_methods:
        print(' - ', item[0]) # item[1])

# ##############################################################################
def test_exec_certifier_tests():
    """
    Execute all Certifier tests from the shared library.
    This test-case drives execution of all C++ unit-tests in one single swoop.

    Certifier gtest unit-tests are all carefully constructed to have a
    single interface: <test-case-name>(bool print_all)
    So, here, we simply execute all test-case methods found, as a way to
    verify that basic functionality still works and can be exercised through
    these Python bindings.
    """
    cft_builtin_methods = getmembers(libct, isbuiltin)

    for item in cft_builtin_methods:
        print(' \n**** Execute pytest: ', item[0], ' ****\n\n', flush=True)
        # pylint: disable-next=exec-used
        exec('libct.' + item[0] + '(True)')
