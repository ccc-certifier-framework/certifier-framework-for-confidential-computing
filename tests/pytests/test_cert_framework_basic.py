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
test_cert_framework_basic.py - Basic pytests for Certifier Framework shared library.
"""
from inspect import getdoc, getmembers, isbuiltin, isclass, ismodule

# To resolve library references, run as: PYTHONPATH=../.. pytest <filename>.py
import libcertifier_framework as libcf

# pylint: disable=c-extension-no-member

# ##############################################################################
# To see output, run: pytest --capture=tee-sys -v
def test_getmembers_of_cc_framework():
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
                 , 'cc_trust_data_certify_me'
                 , 'cc_trust_data_init_policy_key'
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
def test_cf_policy_store_basic():
    """
    This test case shows ways to exercise basic interfaces in Py-bindings.
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
def test_cf_policy_store_update_or_insert():
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
def test_cf_policy_store_find_entry():
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
def test_cf_policy_store_delete_entry():
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
