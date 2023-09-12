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
Basic pytests for Certifier Framework shared library, libcertifier_framework.so

Test cases probe into and directly exercise a few built-in methods available
through the shared library, just as a way of sanity verification of the
interfaces exported from the shared library.

All test cases are named 'test_cfslib_*' => Certfier Framework Shared Library

The methods exported via this shared library are the public interfaces
declared in include/certifier_framework.h .
"""
from inspect import getdoc, getmembers, isbuiltin, isclass, ismodule

# To resolve library references, run as: PYTHONPATH=../.. pytest <filename>.py
import libcertifier_framework as libcf

# pylint: disable=c-extension-no-member

# ##############################################################################
# To see output, run: pytest --capture=tee-sys -v
def test_cfslib_getmembers_of_libcertifier_framework():
    """
    Test basic coherence of Certifier Framework's shared module imported here.
    """
    assert ismodule(libcf) is True

    ccf_builtin_methods = getmembers(libcf, isbuiltin)
    ccf_builtin_names = [ item[0] for item in ccf_builtin_methods]

    # Verify existence of few key methods of Certifier Framework
    for item in [  'protect_blob'
                 , 'reprotect_blob'
                 , 'Seal'
                 , 'Unseal'
                 , 'cc_trust_manager_certify_me'
                 , 'cc_trust_manager_init_policy_key'
                 , 'policy_store_get_num_entries'
                 , 'policy_store_Deserialize'
                 , 'policy_store_Serialize'
                 , 'policy_store__print'
                ]:
        assert item in ccf_builtin_names

    print( )

    for item in ccf_builtin_methods:
        print(' -', item[0], item[1])

# ##############################################################################
def test_cfslib_cc_trust_manager_default_ctor():
    """
    Basic exerciser for an empty cc_trust_manager() object.
    """
    cctd = libcf.new_cc_trust_manager()
    result = libcf.cc_trust_manager_cc_all_initialized(cctd)
    assert result is False

    libcf.delete_cc_trust_manager(cctd)

# ##############################################################################
def test_cfslib_cc_trust_manager():
    """
    Instantiate a cc_trust_manager() object with some arguments.
    """
    cctd = libcf.new_cc_trust_manager('simulated-enclave', 'authentication', 'policy_store')

    result = libcf.cc_trust_manager_cc_all_initialized(cctd)
    assert result is False

    libcf.delete_cc_trust_manager(cctd)

# ##############################################################################
def test_cfslib_cc_trust_manager_add_or_update_new_domain():
    """
    Exercise add_or_update_new_domain(), which will create a new certified_domain()
    object. Dismantiling this cc_trust_manager() will test the destructor of that
    object which should correctly release memory for new certified-domains.
    """
    cctd = libcf.new_cc_trust_manager()

    result = libcf.cc_trust_manager_add_or_update_new_domain(cctd,
                                                             'test-security-domain',
                                                             'test-dummy-certificate',
                                                             'localhost', 8121,
                                                             'localhost', 8123)
    assert result is True

    libcf.delete_cc_trust_manager(cctd)

# ##############################################################################
def test_cfslib_cc_trust_manager_certify_secondary_domain_not_found():
    """
    Exercise certify_secondary_domain(). (Verifies fix to handle a secondary
    domain that is not found; leading to null domain ptr.)
    """
    cctd = libcf.new_cc_trust_manager()

    result = libcf.cc_trust_manager_add_or_update_new_domain(cctd,
                                                             'test-security-domain',
                                                             'test-dummy-certificate',
                                                             'localhost', 8121,
                                                             'localhost', 8123)
    assert result is True

    result = libcf.cc_trust_manager_certify_secondary_domain(cctd,
                                                             'non-existent-secondary-domain')
    assert result is False

    libcf.delete_cc_trust_manager(cctd)

# ##############################################################################
def test_cfslib_store_entry_basic():
    """
    This test case exercises basic interfaces to store_entry() class.
    """
    store_entry = libcf.new_store_entry()
    libcf.store_entry__print(store_entry)
    libcf.delete_store_entry(store_entry)

# ##############################################################################
def test_cfslib_policy_store_basic():
    """
    This test case exercises basic interfaces to policy_store() class.
    """
    policy_store = libcf.new_policy_store()

    assert isclass(policy_store) is False
    print("policy_store:", getdoc(policy_store))

    # Capacity of store in terms of # of entries that can be stored
    assert libcf.policy_store_max_num_ents__get(policy_store) == libcf.policy_store_MAX_NUM_ENTRIES

    # Verify that we have not stored anything, yet. So all counts should be 0
    assert libcf.policy_store_num_ents__get(policy_store) == 0

    libcf.policy_store__print(policy_store)

    libcf.delete_policy_store(policy_store)

# ##############################################################################
def test_cfslib_policy_store_update_or_insert():
    """
    Exercise basic update_or_insert() to add 2 entries. Verify # of entries.
    Exercise basic print.
    """
    policy_store = libcf.new_policy_store()

    result = libcf.policy_store_update_or_insert(policy_store, 'tag-1', 'string', 'some-data-1')
    assert result is True

    result = libcf.policy_store_update_or_insert(policy_store, 'tag-2', 'string', 'some-data-2')
    assert result is True

    assert libcf.policy_store_num_ents__get(policy_store) == 2

    print()
    libcf.policy_store__print(policy_store)

    libcf.delete_policy_store(policy_store)

# ##############################################################################
def test_cfslib_policy_store_find_entry():
    """
    Exercise find_entry() interface and verify correctness.
    """
    policy_store = libcf.new_policy_store()

    tag1 = 'tag-1'
    type1 = 'string'
    data1 = 'some-data1'

    libcf.policy_store_update_or_insert(policy_store, tag1, type1, data1)

    tag2 = 'this-is-tag-2'
    type2 = 'string'
    data2 = 'entry2-has-some-data2'

    libcf.policy_store_update_or_insert(policy_store, tag2, type2, data2)

    tag3 = 'another-is-tag-3'
    type3 = 'string'
    data3 = 'another-entry-has-some-data3'

    libcf.policy_store_update_or_insert(policy_store, tag3, type3, data3)

    assert libcf.policy_store_num_ents__get(policy_store) == 3

    entry_found = libcf.policy_store_find_entry(policy_store, tag2, type2)
    assert entry_found == 1

    entry_found = libcf.policy_store_find_entry(policy_store, tag3, type3)
    assert entry_found == 2

    # Verify interface for non-existent entry
    no_tag = 'tag-not-found'
    no_type = 'type-not-found'
    no_entry = libcf.policy_store_find_entry(policy_store, no_tag, no_type)
    assert no_entry < 0

    libcf.delete_policy_store(policy_store)

# ##############################################################################
def test_cfslib_policy_store_delete_entry():
    """
    Exercise delete_entry() interface and verify correctness.
    """
    policy_store = libcf.new_policy_store()

    tag1 = 'tag-1'
    type1 = 'string'
    data1 = 'some-data1'

    libcf.policy_store_update_or_insert(policy_store, tag1, type1, data1)

    tag2 = 'this-is-tag-2'
    type2 = 'string'
    data2 = 'entry2-has-some-data2'

    libcf.policy_store_update_or_insert(policy_store, tag2, type2, data2)

    # Should be able to successfully delete an entry that was found
    entry_found = libcf.policy_store_find_entry(policy_store, tag1, type1)
    result = libcf.policy_store_delete_entry(policy_store, entry_found)
    assert result is True

    # After deleting one entry, one should be left
    nentries = libcf.policy_store_num_ents__get(policy_store)
    assert nentries == 1

    # Verify interface for non-existent entry
    result = libcf.policy_store_delete_entry(policy_store, nentries)
    assert result is False

    libcf.delete_policy_store(policy_store)

# ##############################################################################
def test_cfslib_cc_trust_manager_authentication():
    """
    Exercise few interfaces of class cc_trust_manager()
    """
    trust_data = libcf.new_cc_trust_manager("simulated_enclave", 'attestation', 'fake_policy_store')
    assert libcf.cc_trust_manager_cc_all_initialized(trust_data) is False

    # The interface using (const string , ..) args is ignored thru SWIG
    # interfaces (due to issues with handling Unicode data w/surrogate chars.)
    # Instead, execute the interface that receives byte-streams as arguments.
    # pylint: disable-next=line-too-long
    result = libcf.cc_trust_manager_python_initialize_simulated_enclave(trust_data,
                                                b'attest_key_bin_byte_stream',
                                                b'measurement_bin_byte_stream',
                                                b'attest_endorsement_bin_byte_stream')
    assert result is False
    libcf.delete_cc_trust_manager(trust_data)

# ##############################################################################
def test_cfslib_secure_authenticated_channel():
    """
    Exercise few interfaces of class secure_authenticated_channel()
    """
    sac_role = 'client'
    sac = libcf.new_secure_authenticated_channel(sac_role)

    result = libcf.secure_authenticated_channel_load_client_certs_and_key(sac)
    assert result is False

    peer_id = ''
    result = libcf.secure_authenticated_channel_get_peer_id(sac, peer_id)
    assert result is True
    print("Peer-ID: '", peer_id, "'")

    libcf.delete_secure_authenticated_channel(sac)
