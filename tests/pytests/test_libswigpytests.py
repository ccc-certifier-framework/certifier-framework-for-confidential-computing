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
packaged as part of testing code: swigpytests.h & swigpytests.cc .
These are built to create the libswigpytest.so, whose interfaces are
exercised in this test case.

This Python test invokes those interfaces to test that the SWIG interface
rules correctly allow the Python bindings to work.

Some of these test cases cross-check a method-name, left as a bread crumb by
the method invoked thru SWIG/C++ mapping gyrations. To debug failing tests,
check for the string asserted == sac.swig_wrap_fn_name_ in the swigpytests.cc
file. That will give you the 'expected' C++ method name that should have been
executed. Then, debug why the swigpytests.i mapping rules ended up picing a
different wrapper C++ method to execute.

"""
import os
from inspect import getmembers, isbuiltin, ismodule
import pytest

# To resolve library references, run as: PYTHONPATH=../.. pytest <filename>.py
import libswigpytests as libswigpy   # The shared library
import swigpytests as swigpyt        # The Python module

# pylint: disable=c-extension-no-member

CertPyTestsDir       = os.path.dirname(os.path.realpath(__file__))
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
# pylint: disable-next=line-too-long
def test_cc_trust_data_initialize_simulated_enclave_w_unicode_surrogate_chars():
    """
    Exerciser of initialize_simulated_enclave() method for a
    cc_trust_data() class. We use a real attestation key binary file
    to verify if the Python bindings to pass-in a string arg with
    Unicode surrogate chars will work.
    The SWIG-python interfaces run into an error which prevents this
    case from succeeding.

    Ref: https://docs.python.org/3/howto/unicode.html
    """
    cctd = swigpyt.cc_trust_data()

    # Open the hard-coded attest key file for reading
    attest_key_file_name = CertPyTestsDir + '/data/attest_key_file.bin'

    # Different variations to open file and read its contents:
    # - This will fail even with the fix for Python Unicode chars handling
    # with open(attest_key_file_name, 'rb') as key_file:

    # - The read itself will fail, with below exception. So we do not get
    #   far enough to exercise the Python Unicode fix.
    with pytest.raises(UnicodeDecodeError):
        with open(attest_key_file_name, encoding='utf-16') as key_file:
            attest_key_bin = key_file.read()

    # Another attempted fix was to read using this interface, which will read-in
    # data as string, with special-case handling of Unicode surrogate chars.
    # This did not work in all cases. Some tests still failed; in some cases
    # we ended up reading incomplete data.
    # with open(attest_key_file_name, encoding="utf-8", errors="surrogateescape") as key_file:

    with open(attest_key_file_name, 'rb') as key_file:
        attest_key_bin = key_file.read()

    attest_endorsement_file_name      = CertPyTestsDir + '/data/platform_attest_endorsement.bin'
    with open(attest_endorsement_file_name, 'rb') as attest_endorsement_file:
        platform_attest_endorsement_bin = attest_endorsement_file.read()

    example_app_measurement_file_name = CertPyTestsDir + '/data/example_app.measurement'
    with open(example_app_measurement_file_name, 'rb') as example_app_measurement_file:
        example_app_measurement = example_app_measurement_file.read()

    # Arg is const string &serialized_attest_key, but this will fail
    # with:
    # pylint: disable-next=line-too-long
    # TypeError: in method 'cc_trust_data_initialize_simulated_enclave', argument 2 of type 'string const &'
    # without the manual fix to the generated SWIG wrapper code.

    # All these variations will all also fail one way or the other w/
    # above patch fix.
    # decoded_attest_key_bin_utf8 = attest_key_bin.decode("utf-8", errors="surrogateescape")
    # print(decoded_attest_key_bin_utf8)

    # result = cctd.initialize_simulated_enclave(attest_key_bin.decode("utf-8", errors="surrogateescape"))
    # result = cctd.initialize_simulated_enclave(decoded_attest_key_bin_utf8)

    # result = cctd.initialize_simulated_enclave(str(attest_key_bin));

    # This seems to work!
    result = cctd.initialize_simulated_enclave(platform_attest_endorsement_bin,
                                               attest_key_bin,
                                               example_app_measurement)
    assert result is True

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

    # Verify that the right C++ method was invoked thru Swig gyrations
    assert sac.swig_wrap_fn_name_ == 'init_client_ssl-const-string-asn1_root_cert'

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

    # Verify that the right C++ method was invoked thru Swig gyrations
    assert sac.swig_wrap_fn_name_ == 'init_client_ssl-const-string-asn1_root_cert'

    # Arg is now interpreted as: 'string &asn1_root_cert_io'
    # Input private-key-cert should have been changed by the method.
    result, pvt_key_cert = sac.init_client_ssl(pvt_key_cert, CERT_CLIENT_APP_PORT)
    assert pvt_key_cert == 'New root Certificate'

    # Verify that the right C++ method was invoked thru Swig gyrations
    assert sac.swig_wrap_fn_name_ == 'init_client_ssl-const-string-asn1_root_cert_io-port'

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

    # Verify that the right C++ method was invoked thru Swig gyrations
    assert sac.swig_wrap_fn_name_ == 'init_client_ssl-port-const-string-asn1_root_cert'

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

    # Verify that the right C++ method was invoked thru Swig gyrations
    assert sac.swig_wrap_fn_name_ == 'init_client_ssl-host_name-port-string-asn1_root_cert_io'

# ##############################################################################
def test_secure_authenticated_channel_init_client_ssl_simple_app():
    """
    Exerciser of init_client_ssl() method for a secure_authenticated_channel()
    as it's done in simple_app/example_app.cc .
    Here, we invoke the method to initialize the
    cc_trust_data()->serialized_policy_cert_ member.
     - We need an INOUT typemap rule for 'string &asn1_root_cert_io'
    """
    sac_role = 'client'
    sac = swigpyt.secure_authenticated_channel(sac_role)

    user_root_cert = 'fake root certificate'

    # 3rd arg is string & asn1_root_cert_io, SWIG'ed as string * INOUT
    result, user_root_cert = sac.init_client_ssl(CERT_CLIENT_HOST,
                                                 CERT_CLIENT_APP_PORT,
                                                 user_root_cert,
                                                 'private-key-cert')
    assert result is True
    # User's root-cert should have been changed by the method.
    assert user_root_cert == 'New root Certificate'
    assert sac.asn1_my_cert_ == 'private-key-cert'

    # Verify that the right C++ method was invoked thru Swig gyrations
    # pylint: disable-next=line-too-long
    exp_swig_fn_name = 'init_client_ssl-host_name-port-string-asn1_root_cert_io-const-string-asn1_my_cert_pvtkey'
    assert sac.swig_wrap_fn_name_ == exp_swig_fn_name

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
    assert sac.asn1_my_cert_ == 'private-key-cert'
    assert tmp_asn1_root_cert == 'New root Certificate'
    assert cctd.serialized_policy_cert_ == 'Unknown-root-cert'
    assert sac.swig_wrap_fn_name_ == exp_swig_fn_name

    sac.asn1_pvt_key_cert_ = 'Uninitialized'
    # This is the way to call to use cctd.serialized_policy_cert_ as input/output field.
    result, cctd.serialized_policy_cert_ = sac.init_client_ssl('localhost', 8123,
                                                               cctd.serialized_policy_cert_,
                                                               'private-key-cert')
    assert result is True
    assert sac.asn1_my_cert_ == 'private-key-cert'
    assert cctd.serialized_policy_cert_ == 'New root Certificate'
    assert sac.swig_wrap_fn_name_ == exp_swig_fn_name

# ##############################################################################
# pylint: disable-next=line-too-long
def test_secure_authenticated_channel_init_client_ssl_cert_w_unicode_surrogate_chars():
    """
    Exerciser of init_client_ssl() method for a secure_authenticated_channel()
    as it's done in simple_app/example_app.cc . But, here, we use a real
    certificate (stashed in pytests/data dir). This certificate contains
    Unicode surrogate chars.
    """
    sac_role = 'client'
    sac = swigpyt.secure_authenticated_channel(sac_role)

    # Open the Certificate binary file for reading
    policy_cert_file_name = CertPyTestsDir + '/data/policy_cert_file.bin'

    # This by itself or with str() fix below will not work. We get Python
    # run-time error reporting:
    # pylint: disable-next=line-too-long
    # TypeError: Wrong number or type of arguments for overloaded function 'secure_authenticated_channel_init_client_ssl'.
    # with open(policy_cert_file_name, encoding="utf-8", errors="surrogateescape") as cert_file:

    # This, along with str() conversion below, seems to work ok.
    with open(policy_cert_file_name, 'rb') as cert_file:
        cert_bin = cert_file.read()

    exp_swig_fn_name = 'init_client_ssl-const-string-asn1_root_cert'
    # Arg is const string &asn1_root_cert; Same as _default case, above.
    result = sac.init_client_ssl(str(cert_bin))
    assert result is True
    assert sac.swig_wrap_fn_name_ == exp_swig_fn_name

# ##############################################################################
# pylint: disable-next=line-too-long
def test_secure_authenticated_channel_init_client_ssl_cert_bytestream_w_unicode_surrogate_chars():
    """
    Exerciser of init_client_ssl() method for a secure_authenticated_channel()
    as it's done in simple_app/example_app.cc . But, here, we use a real
    certificate (stashed in pytests/data dir). This certificate contains
    Unicode surrogate chars.
    """
    sac_role = 'client'
    sac = swigpyt.secure_authenticated_channel(sac_role)

    # Open the Certificate binary file for reading
    policy_cert_file_name = CertPyTestsDir + '/data/policy_cert_file.bin'

    # This by itself or with str() fix below will not work. We get Python
    # run-time error reporting:
    # pylint: disable-next=line-too-long
    # TypeError: Wrong number or type of arguments for overloaded function 'secure_authenticated_channel_init_client_ssl'.
    # with open(policy_cert_file_name, encoding="utf-8", errors="surrogateescape") as cert_file:

    # This, along with str() conversion below, seems to work ok.
    with open(policy_cert_file_name, 'rb') as cert_file:
        cert_bin = cert_file.read()

    # pylint: disable-next=line-too-long
    exp_swig_fn_name = 'init_client_ssl-byte_start-asn1_root_cert-int-asn1_root_cert_size'
    # Arg is const string &asn1_root_cert; Same as _default case, above.
    result = sac.python_init_client_ssl(cert_bin)
    assert result is True
    assert sac.swig_wrap_fn_name_ == exp_swig_fn_name
