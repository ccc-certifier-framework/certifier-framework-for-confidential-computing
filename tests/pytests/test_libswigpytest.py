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
Basic pytests to exercise stripped-down Certifier Framework interfaces
packaged as part of testing code: swigpytest.h & swigpytest.cc .
These are built to create the libswigpytest.so, whose interfaces are
exercised in this test case.

This Python test invokes those interfaces to test that the SWIG interface
rules correctly allow the Python bindings to work.

"""
from inspect import getmembers, isbuiltin, ismodule

# To resolve library references, run as: PYTHONPATH=../.. pytest <filename>.py
import libswigpytest as libswigpy   # The shared library
import swigpytest as swigpyt        # The Python module

# pylint: disable=c-extension-no-member

CERT_CLIENT_HOST     = 'localhost'
CERT_CLIENT_APP_PORT = 8123

# ##############################################################################
# To see output, run: pytest --capture=tee-sys -v
def test_getmembers_of_libswigpytest():
    """
    Test basic coherence of libswigpytest.so imported here
    """
    assert ismodule(libswigpy) is True

    swigpyt_builtin_methods = getmembers(libswigpy, isbuiltin)
    swigpyt_builtin_names = [ item[0] for item in swigpyt_builtin_methods]

    # Verify existence of few key methods of Certifier interfaces from .h file.
    for item in [  'new_cc_trust_data'
                 , 'new_secure_authenticated_channel'
                 , 'delete_cc_trust_data'
                 , 'delete_secure_authenticated_channel'
                ]:
        assert item in swigpyt_builtin_names

    print( )

    for item in swigpyt_builtin_methods:
        print(' - ', item[0]) # item[1])

# ##############################################################################
def test_cc_trust_data_lib_default():
    """
    Basic exerciser of methods for an empty cc_trust_data() object.
    No SWIG interface rules are required for this test case to pass as we are
    invoking a default constructor w/ no arguments.
    """

    cctd = libswigpy.new_cc_trust_data()
    root_cert = libswigpy.cc_trust_data_serialized_policy_cert__get(cctd)
    assert root_cert == 'Unknown-root-cert'

    libswigpy.delete_cc_trust_data(cctd)

# ##############################################################################
def test_secure_authenticated_channel_init_client_ssl_default():
    """
    Exerciser of init_client_ssl() method for a secure_authenticated_channel()
    object to verify interface for const string &asn1_root_cert.

    No SWIG interface rules are required for this test case to pass, as:
     - we are invoking a default construtor w/ no arguments
     - init_client_ssl() is defined to take 'const string&'. So typemap
       rules are not needed.
    """
    sac = swigpyt.secure_authenticated_channel()
    assert sac.role_ == 'Undefined-role'

    pvt_key_cert = 'Private key certificate'
    # Arg is interpreted as: const string &asn1_root_cert
    result = sac.init_client_ssl(pvt_key_cert)
    assert result is True

    # User's root-cert should not have been changed by the method.
    assert sac.asn1_root_cert_ == pvt_key_cert

# ##############################################################################
def test_secure_authenticated_channel_init_client_ssl_input_output():
    """
    Exerciser of init_client_ssl() method for a secure_authenticated_channel()
    object to verify interface for string &asn1_root_cert_io.

    SWIG interface rules are required for this test case to pass, as we need a
    way to specify that 'string &asn1_root_cert_io' is also used to return a
    certificate (output string).
    """
    sac = swigpyt.secure_authenticated_channel()
    assert sac.role_ == 'Undefined-role'

    pvt_key_cert = 'Private key certificate'
    # Arg is const string &asn1_root_cert; Same as _default case, above.
    result = sac.init_client_ssl(pvt_key_cert)
    assert result is True

    # Arg is now interpreted as: 'string &asn1_root_cert_io'
    # Input private-key-cert should have been changed by the method.
    result, pvt_key_cert = sac.init_client_ssl(pvt_key_cert, CERT_CLIENT_APP_PORT)
    assert pvt_key_cert == 'New root Certificate'

# ##############################################################################
def test_secure_authenticated_channel_init_client_ssl_default_2args():
    """
    Exerciser of init_client_ssl() method for a secure_authenticated_channel()
    object to verify interface for const string &asn1_root_cert.

    No SWIG interface rules are required for this test case to pass, as:
     - we are invoking a default construtor w/ no arguments
     - init_client_ssl() is defined to take 'const string&'. So typemap
       rules are not needed.
    """
    sac = swigpyt.secure_authenticated_channel()
    assert sac.role_ == 'Undefined-role'

    pvt_key_cert = 'Private key certificate'
    # Arg is interpreted as: const string &asn1_root_cert
    result = sac.init_client_ssl(CERT_CLIENT_APP_PORT, pvt_key_cert)
    assert result is True

    # User's root-cert should not have been changed by the method.
    assert sac.asn1_root_cert_ == pvt_key_cert

# ##############################################################################
def test_secure_authenticated_channel_lib():
    """
    Basic exerciser of methods for a secure_authenticated_channel() object.
    """
    sac_role = 'client'
    sac = libswigpy.new_secure_authenticated_channel(sac_role)

    assert libswigpy.secure_authenticated_channel_role__get(sac) == sac_role

    libswigpy.delete_secure_authenticated_channel(sac)

# ##############################################################################
def test_secure_authenticated_channel_default():
    """
    Basic exerciser of methods for a secure_authenticated_channel() object
    using interfaces from the Python module
    """
    sac_role = 'client'
    sac = swigpyt.secure_authenticated_channel(sac_role)

    assert sac.role_ == sac_role

# ##############################################################################
def test_secure_authenticated_channel_init_client_ssl_basic():
    """
    Exerciser of init_client_ssl() method for a secure_authenticated_channel()
    object using interfaces from the Python module. init_client_ssl()
     - Does not need typemap rules for 'const string &host_name' and for
       'int port'
     - We need a typemap rule for 'string &asn1_root_cert'
    """
    sac_role = 'client'
    sac = swigpyt.secure_authenticated_channel(sac_role)

    user_root_cert_inp = 'user-input root certificate'
    user_root_cert = user_root_cert_inp

    # Last arg is string & asn1_root_cert, SWIG'ed as string * INOUT
    result, user_root_cert = sac.init_client_ssl('localhost', 8123,
                                                  user_root_cert)
    assert result is True
    assert sac.asn1_root_cert_ == user_root_cert_inp

    # User's root-cert should have been changed by the method.
    assert user_root_cert == 'New root Certificate'

# ##############################################################################
def test_secure_authenticated_channel_init_client_ssl_simple_app():
    """
    Exerciser of init_client_ssl() method for a secure_authenticated_channel()
    as it's done in simple_app/example_app.cc .
    Here, we invoke the method to initialize the
    cc_trust_data()->serialized_policy_cert_ member.
     - We need an INOUT typemap rule for 'string &asn1_root_cert'
    """
    sac_role = 'client'
    sac = swigpyt.secure_authenticated_channel(sac_role)

    user_root_cert = 'fake root certificate'

    # 3rd arg is string & asn1_root_cert, SWIG'ed as string * INOUT
    result, user_root_cert = sac.init_client_ssl('localhost', 8123,
                                                  user_root_cert,
                                                  'private-key-cert')
    assert result is True
    # User's root-cert should have been changed by the method.
    assert user_root_cert == 'New root Certificate'
    assert sac.asn1_pvt_key_cert_ == 'private-key-cert'

    # Now, try the call as it's done in simple-app, using the field from
    # cc_trust_data(). That should be uninitialized.
    cctd = swigpyt.cc_trust_data()
    assert cctd.serialized_policy_cert_ == 'Unknown-root-cert'

    sac.asn1_pvt_key_cert_ = 'Uninitialized'
    # In this call, we are only using cctd.serialized_policy_cert_ as input but are
    # not changing its value.
    result, tmp_asn1_root_cert = sac.init_client_ssl('localhost', 8123,
                                                      cctd.serialized_policy_cert_,
                                                      'private-key-cert')
    assert result is True
    assert sac.asn1_pvt_key_cert_ == 'private-key-cert'
    assert tmp_asn1_root_cert == 'New root Certificate'
    assert cctd.serialized_policy_cert_ == 'Unknown-root-cert'

    sac.asn1_pvt_key_cert_ = 'Uninitialized'
    # This is the way to call to use cctd.serialized_policy_cert_ as input/output field.
    result, cctd.serialized_policy_cert_ = sac.init_client_ssl('localhost', 8123,
                                                               cctd.serialized_policy_cert_,
                                                               'private-key-cert')
    assert result is True
    assert sac.asn1_pvt_key_cert_ == 'private-key-cert'
    assert cctd.serialized_policy_cert_ == 'New root Certificate'
