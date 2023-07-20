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

import certifier_framework as cfm

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

    result = pstore.is_policy_key_valid()
    assert result is False

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

    policy_key = pstore.get_policy_key()
    assert policy_key is None

    no_delete = pstore.delete_entry(0)
    assert no_delete is False

    print()
    pstore._print()

# ##############################################################################
def test_make_key_message():
    """
    Exercise C++ interface to make a key_message{} object.
    RESOLVE: This stub case seems to work ... figure out where to go next with this.
    """
    # key_msg = cert_pbi.key_message()
    assert 1 == 1 + 0

# ##############################################################################
def test_add_find_single_entry():
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
def test_update_or_insert():
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
def test_delete_single_entry():
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
# Test cases for class cc_trust_data()
# ##############################################################################

# ##############################################################################
def test_cc_trust_data():
    """ Basic exerciser of methods for an empty cc_trust_data() object."""

    cctd = cfm.cc_trust_data()
    assert cctd.cc_all_initialized() is False

    public_key_alg = "public-key-alg"
    symmetric_key_alg = "symmetric-key-alg"
    assert cctd.cold_init(public_key_alg, symmetric_key_alg) is False

    # RESOLVE: Fix this test case.
    # asn1_cert_size = 1024
    # asn1_cert = bytearray("some-asn1-certificate-junk-test-string", 'utf-8')
    asn1_cert = "some-asn1-certificate-junk-test-string".encode()
    print(asn1_cert)
    # assert cctd.init_policy_key(asn1_cert_size, asn1_cert) is False
