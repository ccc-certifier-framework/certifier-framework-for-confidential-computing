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
Basic pytests for the Certifier Framework Python module. These tests verify
the public interfaces exposed from include/certifier_framework.h through the
SWIG-generated certifier_framework.py module.

Test cases in this file exercise only those interfaces that require basic
types, such as int or string, and do not rely on any other class definitions
which may be exposed through other interfaces / Python modules.

As an example, set_policy_key() is not tested here as it requires the
definition for 'class key_message', which is only available in another
generated Python module.
"""

# To resolve references to module, run as: PYTHONPATH=../.. pytest <filename>.py
# import certifier_pb2 as cert_pbi

import os
from inspect import getmembers, isclass, ismodule
import time
import pytest
import certifier_framework as cfm

CertPyTestsDir       = os.path.dirname(os.path.realpath(__file__))
CERT_CLIENT_HOST     = 'localhost'
CERT_CLIENT_APP_PORT = 8123
CERT_SERVER_HOST     = 'localhost'
CERT_SERVER_APP_PORT = 8124

# ##############################################################################
# To see output, run: pytest --capture=tee-sys -v
def test_cfm_getmembers_of_certifier_framework():
    """
    Test basic coherence of Certifier Framework's Python module imported here.
    """
    assert ismodule(cfm) is True

    cfm_classes = getmembers(cfm, isclass)
    cfm_class_names = [ item[0] for item in cfm_classes]

    # Verify existence of few key methods of Certifier Framework
    for item in [  'cc_trust_manager'
                 , 'policy_store'
                 , 'secure_authenticated_channel'
                 , 'store_entry'
                ]:
        assert item in cfm_class_names

    print( )

    for class_name in cfm_class_names:
        print(' -', class_name)

# ##############################################################################
# To see output, run: pytest --capture=tee-sys -v
def test_store_entry():
    """ Basic test of class store_entry{} """

    store_entry = cfm.store_entry()
    store_entry._print()

# ##############################################################################
def test_policy_store():
    """
    Basic test of interfaces on an empty class policy_store{}.
    All apis should work, but return nothing or False.
    """
    pstore = cfm.policy_store()

    # Store should be empty upon creation
    nentries = pstore.get_num_entries()
    assert nentries == 0

    # Should not be able to find any entry ... store is empty
    entry_num = pstore.find_entry('some-tag', 'string')
    assert entry_num < 0

    tag_not_found = pstore.tag(0)
    assert tag_not_found is None

    type_not_found = pstore.type(0)
    assert type_not_found is None

    no_entry = pstore.get_entry(0)
    assert no_entry is None

    no_delete = pstore.delete_entry(0)
    assert no_delete is False

    print()
    pstore._print()

# ##############################################################################
def test_policy_store_add_find_single_entry():
    """
    Test policy_store() adding a single entry and find entry interfaces.
    Test tag() and type() interfaces.
    """
    pstore = cfm.policy_store()

    tag1   = 'tag-1'
    type1  = 'string'
    value1 = 'Entry-1'
    result = pstore.update_or_insert(tag1, type1, value1)
    assert result is True

    # find on non-existent entry should return invalid index.
    assert pstore.find_entry('unknown-tag', type1) < 0

    entry1_idx = pstore.find_entry(tag1, type1)
    assert entry1_idx == 0

    # assert pstore.tag(entry1_idx) == tag1
    print('Tag is: ', str(pstore.tag(entry1_idx)))

    # Retrieve newly inserted entry and validate its contents
    this_entry = cfm.store_entry()
    this_entry = pstore.get_entry(entry1_idx)
    assert this_entry.tag_ == tag1
    assert this_entry.type_ == type1
    assert this_entry.value_ == value1

# ##############################################################################
def test_policy_store_update_or_insert():
    """
    Test policy_store() update contents of a single entry and validate find()'s return.
    """
    pstore = cfm.policy_store()

    tag1   = 'tag-1'
    type1  = 'string'
    value1 = 'Entry-1'
    result = pstore.update_or_insert(tag1, type1, value1)
    assert result is True

    # Insert another entry, so we can check that update()'s getting the right one
    tag2   = 'tag-2'
    type2  = 'string'
    value2 = 'Entry-2'
    result = pstore.update_or_insert(tag2, type2, value2)
    assert result is True

    assert pstore.get_num_entries() == 2

    # Unique on (tag, type), so this will update existing entry
    newvalue1 = 'Updated-Entry-1'
    result = pstore.update_or_insert(tag1, type1, newvalue1)
    assert result is True

    entry1_idx = pstore.find_entry(tag1, type1)
    assert entry1_idx == 0

    # Retrieve newly inserted entry and validate its contents
    this_entry = cfm.store_entry()
    this_entry = pstore.get_entry(entry1_idx)
    assert this_entry.tag_   == tag1
    assert this_entry.type_  == type1
    assert this_entry.value_ != value1
    assert this_entry.value_ == newvalue1

# ##############################################################################
def test_policy_store_put():
    """
    Test updating value of a single entry using the put() interface.
    """
    pstore = cfm.policy_store()

    tag1   = 'tag-1'
    type1  = 'string'
    value1 = 'Entry-1'
    result = pstore.update_or_insert(tag1, type1, value1)
    assert result is True

    # Insert another entry, so we can check that update()'s getting the right one
    tag2   = 'tag-2'
    type2  = 'string'
    value2 = 'Entry-2'
    result = pstore.update_or_insert(tag2, type2, value2)
    assert result is True

    assert pstore.get_num_entries() == 2

    entry1_idx = pstore.find_entry(tag1, type1)
    assert entry1_idx == 0

    newvalue1 = 'Updated-Entry-1'
    result = pstore.put(entry1_idx, newvalue1)
    assert result is True

    # Retrieve newly inserted entry and validate its contents
    this_entry = cfm.store_entry()
    this_entry = pstore.get_entry(entry1_idx)
    assert this_entry.tag_   == tag1
    assert this_entry.type_  == type1
    assert this_entry.value_ != value1
    assert this_entry.value_ == newvalue1

    # Verify that the other entry is undisturbed
    entry2_idx = pstore.find_entry(tag2, type2)
    assert entry2_idx == 1

    # Retrieve newly inserted entry and validate its contents
    this_entry = cfm.store_entry()
    this_entry = pstore.get_entry(entry2_idx)
    assert this_entry.tag_   == tag2
    assert this_entry.type_  == type2
    assert this_entry.value_ == value2

# ##############################################################################
def test_policy_store_get():
    """
    Test retrieving value of a single entry using the get() interface.
    """
    pstore = cfm.policy_store()

    tag1   = 'tag-1'
    type1  = 'string'
    value1 = 'Entry-1'
    result = pstore.update_or_insert(tag1, type1, value1)
    assert result is True

    entry1_idx = pstore.find_entry(tag1, type1)
    assert entry1_idx == 0

    (result, found_val) = pstore.get(entry1_idx)
    assert result is True
    assert found_val == value1

# ##############################################################################
def test_policy_store_delete_single_entry():
    """
    Insert a few entries. Verify that we can delete a specific entry.
    """
    pstore = cfm.policy_store()

    tag1   = 'tag-1'
    type1  = 'string'
    value1 = 'Entry-1'
    result = pstore.update_or_insert(tag1, type1, value1)
    assert result is True

    tag2   = 'tag-2'
    type2  = 'string'
    value2 = 'Entry-2'
    result = pstore.update_or_insert(tag2, type2, value2)
    assert result is True

    tag3   = 'tag-3'
    type3  = 'string'
    value3 = 'Entry-3'
    result = pstore.update_or_insert(tag3, type3, value3)
    assert result is True

    nentries = 3
    assert pstore.get_num_entries() == nentries

    # Deleting non-existing entry should fail
    assert pstore.delete_entry(nentries) is False

    del_idx = pstore.find_entry(tag2, type2)
    result = pstore.delete_entry(del_idx)
    assert result is True

    nentries -= 1

    assert pstore.get_num_entries() == nentries

# ##############################################################################
def test_policy_store_serialize():
    """
    Exercise the Serialize() interface of policy_store.
    """
    pstore = cfm.policy_store()

    tag1   = 'tag-1'
    type1  = 'string'
    value1 = 'Entry-1'
    result = pstore.update_or_insert(tag1, type1, value1)
    assert result is True

    # Insert another entry, so we can check that update()'s getting the right one
    tag2   = 'tag-2'
    type2  = 'string'
    value2 = 'Entry-2'
    result = pstore.update_or_insert(tag2, type2, value2)
    assert result is True

    assert pstore.get_num_entries() == 2

    (result, serialized) = pstore.Serialize()
    assert result is True
    assert len(serialized) > 0
    # Does not quite work due to some embedded non-printable chars in stream
    # print("Serialized Policy Store contents: ,", serialized, "'")

# ##############################################################################
# Test cases for class cc_trust_manager()
# ##############################################################################

# ##############################################################################
def test_cc_trust_manager():
    """ Basic exerciser of methods for an empty cc_trust_manager() object."""

    cctd = cfm.cc_trust_manager()
    assert cctd.cc_all_initialized() is False

    # Should fail with garbage key-algorithm names
    public_key_alg = "public-key-alg"
    symmetric_key_alg = "symmetric-key-alg"
    result = cctd.cold_init(public_key_alg, symmetric_key_alg,
                          "Home-domain-name", "home-host-name",
                          8121, "service-host", CERT_CLIENT_APP_PORT)
    assert result is False

    asn1_cert = 'some-asn1-certificate-junk-test-string'.encode()
    assert cctd.init_policy_key(asn1_cert) is False

# ##############################################################################
def test_cc_trust_manager_simulated_enclave():
    """
    Basic exerciser of methods for an cc_trust_manager() object for a simulated
    enclave. Go through bootstrapping interfaces, using a pre-generated policy
    certificate from a file.
    """
    cctd = cfm.cc_trust_manager('simulated-enclave', 'authentication',
                                CertPyTestsDir + '/data/policy_store')
    assert cctd.cc_all_initialized() is False

    # Open the Certificate binary file for reading
    # It is sufficient to just read this file as a binary byte stream.
    # Python's byte-stream's (byte *, length) pair is consistent with
    # the interface's signature.
    with open(CertPyTestsDir + '/data/policy_cert_file.bin', 'rb') as cert_file:
        cert_bin = cert_file.read()

    result = cctd.init_policy_key(cert_bin)
    assert result is True

    # Should succeed with valid key algorithm names, after policy key has been
    # initialized
    public_key_alg = "rsa-2048"
    symmetric_key_alg = "aes-256-cbc-hmac-sha256"
    result = cctd.cold_init(public_key_alg, symmetric_key_alg,
                            'test-app-home_domain',
                            CERT_CLIENT_HOST, CERT_CLIENT_APP_PORT,
                            CERT_SERVER_HOST, CERT_SERVER_APP_PORT)

    assert result is True

# ##############################################################################
@pytest.mark.needs_cert_service()
def test_cc_trust_manager_get_certified():
    """
    Exercise the steps up through "get-certified" for a simulated enclave:
      - Initialize a new trust data object
      - Initialize policy key, using hard-coded certificates (for testing)
      - python_initialize_simulated_enclave()
      - cold_init()
      - get_certified(): warm_restart(), certify_me()
    """
    cctd = cfm.cc_trust_manager('simulated-enclave', 'authentication',
                                CertPyTestsDir + '/data/policy_store')
    assert cctd.cc_all_initialized() is False

    result = cc_trust_manager_get_certified(cctd)
    assert result is True

# ##############################################################################
@pytest.mark.needs_cert_service()
def test_run_app_as_a_client_init_client_ssl():
    """
    Exercise the steps up through "run-app-as-client". This subsumes the setup
    stuff done in test_cc_trust_manager_get_certified(), followed by:
      - Setting up secure_authenticated_channel channel
      - channel.init_client_ssl()

    Needs following items to succeed:
      - Patch-fix applied by fix_swig_wrap.sh, to manage handling of Unicode
        surrogate chars
    """
    cctd = cfm.cc_trust_manager('simulated-enclave', 'authentication',
                             CertPyTestsDir + '/data/policy_store')
    assert cctd.cc_all_initialized() is False

    # Performs cold_init() and also does warm_restart()
    result = cc_trust_manager_get_certified(cctd)
    assert result is True

    my_role = 'client'
    channel = cfm.secure_authenticated_channel(my_role)
    print(' ... Secure channel', my_role, 'instantiated.')
    assert channel.role_ == my_role

    result = cctd.cc_auth_key_initialized_ and cctd.cc_policy_info_initialized_
    assert result is True
    print(' ... cctd.trust data is initialized.')

    result = cctd.primary_admissions_cert_valid_
    assert result is True
    print(' ... cctd.primary admissions cert is valid.')

    # *************************************************************************
    # SEE SWIG ISSUE: https://github.com/swig/swig/issues/1916
    # Change generated code in SWIG_AsCharPtrAndSize() to:
    # obj = PyUnicode_AsEncodedString(obj, "utf-8", "surrogateescape");
    # *************************************************************************
    result = channel.init_client_ssl(CERT_SERVER_HOST, CERT_SERVER_APP_PORT,
                                     cctd.serialized_policy_cert_,
                                     cctd.private_auth_key_,
                                     cctd.serialized_primary_admissions_cert_)

    # This is expected to fail as we will not be able to setup a SSL connection
    # to the server-process. (Server process hasn't been started in this test.)
    assert result is False
    print(' ... channel.init_client_ssl() failed, as expected.')

# ##############################################################################
@pytest.mark.needs_cert_service()
def test_run_app_as_a_client_init_client_ssl_with_trust_manager():
    """
    Exercise the steps up through "run-app-as-client". This subsumes the setup
    stuff done in test_cc_trust_manager_get_certified(), followed by:
      - Setting up secure_authenticated_channel channel
      - channel.init_client_ssl()
      - Uses const cc_trust_manager &mgr interface.
    """
    cctd = cfm.cc_trust_manager('simulated-enclave', 'authentication',
                                CertPyTestsDir + '/data/policy_store')
    assert cctd.cc_all_initialized() is False

    # Performs cold_init() and also does warm_restart()
    result = cc_trust_manager_get_certified(cctd)
    assert result is True

    my_role = 'client'
    channel = cfm.secure_authenticated_channel(my_role)
    print(' ... Secure channel', my_role, 'instantiated.')
    assert channel.role_ == my_role

    result = cctd.cc_auth_key_initialized_ and cctd.cc_policy_info_initialized_
    assert result is True
    print(' ... cctd.trust data is initialized.')

    result = cctd.primary_admissions_cert_valid_
    assert result is True
    print(' ... cctd.primary admissions cert is valid.')

    # *************************************************************************
    # NOTE: This interface does not seem to run into the SWIG ISSUE:
    #   https://github.com/swig/swig/issues/1916
    # *************************************************************************
    result = channel.init_client_ssl(CERT_SERVER_HOST, CERT_SERVER_APP_PORT,
                                     cctd)

    # This is expected to fail as we will not be able to setup a SSL connection
    # to the server-process. (Server process hasn't been started in this test.)
    assert result is False
    print(' ... channel.init_client_ssl() with cc_trust_manager &mgr interface '
          + 'failed, as expected.')

# ##############################################################################
@pytest.mark.needs_cert_service()
@pytest.mark.check_leaks()
def test_run_app_as_a_server():
    """
    Exercise the "run-app-as-server" step, to start up a server process.
    Execute the steps that would be taken in a real workflow, to verify that
    the interfaces basically work, without actually getting into an SSL-connect
    accept server-loop.

    Needs following items to succeed:
      - Patch-fix applied by fix_swig_wrap.sh, to manage handling of Unicode
        surrogate chars
    """
    cctd = cfm.cc_trust_manager('simulated-enclave', 'authentication',
                             CertPyTestsDir + '/data/policy_store')
    assert cctd.cc_all_initialized() is False

    # Performs cold_init() and also does warm_restart()
    result = cc_trust_manager_get_certified(cctd)
    assert result is True
    print(' cc_trust_manager_get_certified() succeeded. cc_all_initialized() is True.')

    result = cctd.warm_restart()
    assert result is True
    print(' warm_restart() succeeded.')

    my_role = 'server'
    channel = cfm.secure_authenticated_channel(my_role)
    print(' ... Secure channel', my_role, 'instantiated.')
    assert channel.role_ == my_role

    result = cctd.cc_auth_key_initialized_ and cctd.cc_policy_info_initialized_
    assert result is True
    print(' ... cctd.trust data is initialized.')

    result = cctd.primary_admissions_cert_valid_
    assert result is True
    print(' ... cctd.primary admissions cert is valid.')

    # Needs patch-fix to workaround SWIG ISSUE:
    # https://github.com/swig/swig/issues/1916
    result = channel.init_server_ssl(CERT_SERVER_HOST, CERT_SERVER_APP_PORT,
                                     cctd.serialized_policy_cert_,
                                     cctd.private_auth_key_,
                                     cctd.serialized_primary_admissions_cert_)
    assert result is True

    # Extended sleep needed to ensure that socket is released cleanly
    # when tests are run on CI machines.
    sleep_for_secs = 120
    print(' ... channel.init_server_ssl() succeeded. Now sleep for',
          sleep_for_secs, 'seconds ...')
    time.sleep(sleep_for_secs)

    # Method provides a testing hook to dispatch method with NULL func-hdlr arg
    # so that we basically exercise the rest of the code-flow of this interface.
    result = cfm.server_dispatch(CERT_SERVER_HOST, CERT_SERVER_APP_PORT,
                                 cctd.serialized_policy_cert_,
                                 cctd.private_auth_key_,
                                 cctd.serialized_primary_admissions_cert_,
                                 None)
    assert result is True
    print(' ... cfm.server_dispatch() succeeded.')

# ##############################################################################
@pytest.mark.needs_cert_service()
@pytest.mark.check_leaks()
def test_run_app_as_a_server_with_trust_manager():
    """
    Exercise the "run-app-as-server" step, to start up a server process.
    Execute the steps that would be taken in a real workflow, to verify that
    the interfaces basically work, without actually getting into an SSL-connect
    accept server-loop.
      - Uses const cc_trust_manager &mgr interface.

    Needs following items to succeed:
      - Patch-fix applied by fix_swig_wrap.sh, to manage handling of Unicode
        surrogate chars
    """
    cctd = cfm.cc_trust_manager('simulated-enclave', 'authentication',
                                CertPyTestsDir + '/data/policy_store')
    assert cctd.cc_all_initialized() is False

    # Performs cold_init() and also does warm_restart()
    result = cc_trust_manager_get_certified(cctd)
    assert result is True
    print(' cc_trust_manager_get_certified() succeeded. cc_all_initialized() is True.')

    result = cctd.warm_restart()
    assert result is True
    print(' warm_restart() succeeded.')

    my_role = 'server'
    channel = cfm.secure_authenticated_channel(my_role)
    print(' ... Secure channel', my_role, 'instantiated.')
    assert channel.role_ == my_role

    result = cctd.cc_auth_key_initialized_ and cctd.cc_policy_info_initialized_
    assert result is True
    print(' ... cctd.trust data is initialized.')

    result = cctd.primary_admissions_cert_valid_
    assert result is True
    print(' ... cctd.primary admissions cert is valid.')

    # Does not need patch-fix to workaround SWIG ISSUE. (Overload resolution
    # seems to be happening w/o need for fix_swig_wrap.sh .)
    result = channel.init_server_ssl(CERT_SERVER_HOST, CERT_SERVER_APP_PORT,
                                     cctd)
    assert result is True

    # Extended sleep needed to ensure that socket is released cleanly
    # when tests are run on CI machines.
    sleep_for_secs = 120
    print(' ... channel.init_server_ssl() succeeded. Now sleep for',
          sleep_for_secs, 'seconds ...')
    time.sleep(sleep_for_secs)

    # Method provides a testing hook to dispatch method with NULL func-hdlr arg
    # so that we basically exercise the rest of the code-flow of this interface.
    # Needs patch-fix to workaround SWIG ISSUE:
    #   https://github.com/swig/swig/issues/1916
    result = cfm.server_dispatch(CERT_SERVER_HOST, CERT_SERVER_APP_PORT,
                                 cctd.serialized_policy_cert_,
                                 cctd.private_auth_key_,
                                 cctd.serialized_primary_admissions_cert_,
                                 None)
    assert result is True
    print(' ... cfm.server_dispatch() with cc_trust_manager &mgr interface succeeded.')

# ##############################################################################
@pytest.mark.needs_cert_service()
@pytest.mark.check_leaks()
def test_trust_manager_write_private_key_to_file():
    """
    Exercise the utility method to write out the private key to a file.
    """
    cctd = cfm.cc_trust_manager('simulated-enclave', 'authentication',
                                CertPyTestsDir + '/data/policy_store')
    assert cctd.cc_all_initialized() is False

    # Performs cold_init() and also does warm_restart()
    result = cc_trust_manager_get_certified(cctd)
    assert result is True
    print(' cc_trust_manager_get_certified() succeeded. cc_all_initialized() is True.')

    result = cctd.cc_auth_key_initialized_ and cctd.cc_policy_info_initialized_
    assert result is True
    print(' ... cctd.trust data is initialized.')

    # Negative test: Writing to a non-existent file should fail cleanly
    pvt_key_filename = CertPyTestsDir + '/Junk-XXX-data/test_write_private_key_to_file.key'
    result = cctd.write_private_key_to_file(pvt_key_filename)
    assert result is False

    pvt_key_filename = CertPyTestsDir + '/data/test_write_private_key_to_file.key'
    result = cctd.write_private_key_to_file(pvt_key_filename)
    assert result is True

    print(' ... cctd.write_private_key_to_file succeeded:', pvt_key_filename)

# ##############################################################################
# Work-horse function: Implements the steps taken with cc_trust_manager() object.
# ##############################################################################
# pylint: disable=too-many-locals
def cc_trust_manager_get_certified(cctd):

    """
    Do-it-all method to go through the steps that the 'get-certified' action in
    sample apps performs. This test-case needs a consistent set of the
    following files, usually generated by exercising simple_app scenario:
        - attest_key_file.bin
        - platform_attest_endorsement.bin
        - example_app.measurement

    Returns boolean, cc_trust_manager()->cc_all_initialized(); Expected to be true.
    """
    # Open the Certificate binary file for reading
    cert_file_bin = CertPyTestsDir + '/data/policy_cert_file.bin'
    with open(cert_file_bin, 'rb') as cert_file:
        cert_bin = cert_file.read()

    result = cctd.init_policy_key(cert_bin)
    assert result is True
    print(' ... cctd.init_policy_key() succeeded. Initialized serialized_policy_cert_ ')

    # Another attempted fix was to read using this interface, which will read-in
    # data as string, with special-case handling of Unicode surrogate chars.
    # This did not work in all cases. Some tests still failed; in some cases
    # we ended up reading incomplete data.
    # pylint: disable-next=line-too-long
    # with open(attest_key_file_name, encoding="utf-8", errors="surrogateescape") as attest_key_file:

    # Open hard-coded key / platform endorsement & app-measurement files
    # and read-in data as a bytestream.
    attest_key_file_name = CertPyTestsDir + '/data/attest_key_file.bin'
    with open(attest_key_file_name, 'rb') as attest_key_file:
        attest_key_bin = attest_key_file.read()

    example_app_measurement_file_name = CertPyTestsDir + '/data/example_app.measurement'
    with open(example_app_measurement_file_name, 'rb') as example_app_measurement_file:
        example_app_measurement = example_app_measurement_file.read()

    attest_endorsement_file_name = CertPyTestsDir + '/data/platform_attest_endorsement.bin'
    with open(attest_endorsement_file_name, 'rb') as attest_endorsement_file:
        platform_attest_endorsement_bin = attest_endorsement_file.read()

    result = cctd.python_initialize_simulated_enclave(attest_key_bin,
                                                      example_app_measurement,
                                                      platform_attest_endorsement_bin)
    assert result is True
    print(' ... cctd.python_initialize_simulated_enclave() succeeded.')

    # Should succeed with valid key algorithm names, after policy key has been
    # initialized
    public_key_alg    = "rsa-2048"
    symmetric_key_alg = "aes-256-cbc-hmac-sha256"
    result = cctd.cold_init(public_key_alg, symmetric_key_alg,
                            'test-app-home_domain',
                            CERT_CLIENT_HOST, CERT_CLIENT_APP_PORT,
                            CERT_SERVER_HOST, CERT_SERVER_APP_PORT)
    assert result is True
    print(' ... cctd.cold_init() succeeded.')

    result = cctd.warm_restart()
    assert result is True
    print(' ... cctd.warm_restart() succeeded.')

    result = cctd.certify_me()
    assert result is True
    print(' ... cctd.certify_me() succeeded.')

    result =  cctd.cc_all_initialized()
    print(' ... cctd.cc_all_initialized() succeeded.')
    return result

# ##############################################################################
def test_cc_trust_manager_add_or_update_new_domain():
    """
    Basic exercise of add_or_update_new_domain() interface, w/fake arguments.
    """
    cctd = cfm.cc_trust_manager('simulated-enclave', 'authentication',
                             CertPyTestsDir + '/data/policy_store')

    result = cctd.add_or_update_new_domain('test-app-home_domain',
                                           'sample-certificate-but-works',
                                           CERT_CLIENT_HOST, CERT_CLIENT_APP_PORT,
                                           CERT_SERVER_HOST, CERT_SERVER_APP_PORT)
    assert result is True

# ##############################################################################
def test_cc_trust_manager_certify_secondary_domain():
    """
    Basic exercise of certify_secondary_domain() interface, w/fake arguments.
    """
    cctd = cfm.cc_trust_manager('simulated-enclave', 'authentication',
                             CertPyTestsDir + '/data/policy_store')

    # Security domain does not exist.
    result = cctd.certify_secondary_domain('secondary-security-domain')
    assert result is False

    new_domain = 'test-app-home_domain'
    result = cctd.add_or_update_new_domain(new_domain,
                                           'sample-certificate-but-works',
                                           CERT_CLIENT_HOST, CERT_CLIENT_APP_PORT,
                                           CERT_SERVER_HOST, CERT_SERVER_APP_PORT)
    assert result is True

    # Now, domain is newly added; but certification should fail.
    result = cctd.certify_secondary_domain(new_domain)
    assert result is False

# ##############################################################################
def test_certifiers_init_certifiers_data():
    """
    Basic exercise of certifiers()->init_certifiers_data()
    """
    cctd = cfm.cc_trust_manager()
    cc_cert = cfm.certifiers(cctd)

    result = cc_cert.init_certifiers_data('test-app-home_domain',
                                     'sample-certificate-but-works',
                                     CERT_CLIENT_HOST, CERT_CLIENT_APP_PORT,
                                     CERT_SERVER_HOST, CERT_SERVER_APP_PORT)
    assert result is True

    result = cc_cert.get_certified_status()
    assert result is False
