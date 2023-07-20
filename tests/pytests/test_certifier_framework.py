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
Basic pytests for Certifier Framework Python module.

"""

# To resolve references to module, run as: PYTHONPATH=../.. pytest <filename>.py
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
def test_add_find_single_entry():
    """
    Test adding a single entry and find entry interfaces.
    """
    pstore = cfm.policy_store()

    tag1 = 'tag-1'
    type1 = 'string'
    value1 = 'Entry-1'
    result = pstore.update_or_insert(tag1, type1, value1)
    assert result is True

    # find on non-existent entry should return invalid index.
    assert pstore.find_entry('unknown-tag', type1) < 0

    entry1_idx = pstore.find_entry(tag1, type1)
    assert entry1_idx == 0

    # Retrieve newly inserted entry and validate its contents
    this_entry = cfm.store_entry()
    this_entry = pstore.get_entry(entry1_idx)
    assert this_entry.tag_ == tag1
    assert this_entry.type_ == type1
    assert this_entry.value_ == value1

# ##############################################################################
def test_update_single_entry():
    """
    Test updating contents of a single entry and validate find()'s return.
    """
    pstore = cfm.policy_store()

    tag1 = 'tag-1'
    type1 = 'string'
    value1 = 'Entry-1'
    result = pstore.update_or_insert(tag1, type1, value1)
    assert result is True

    # Insert another entry, so we can check that find()'s getting the right one
    tag2 = 'tag-1'
    type2 = 'string'
    value2 = 'Entry-1'
    result = pstore.update_or_insert(tag2, type2, value2)
    assert result is True

    newvalue1 = 'Updated-Entry-1'
    result = pstore.update_or_insert(tag1, type1, newvalue1)
    assert result is True

    entry1_idx = pstore.find_entry(tag1, type1)
    assert entry1_idx == 0

    # Retrieve newly inserted entry and validate its contents
    this_entry = cfm.store_entry()
    this_entry = pstore.get_entry(entry1_idx)
    assert this_entry.tag_ == tag1
    assert this_entry.type_ == type1
    assert this_entry.value_ != value1
    assert this_entry.value_ == newvalue1
