// swigpytests.i- SWIG interface to generate Python bindings
// *****************************************************************************
// SWIG interfaces to test out small samples of C++ code and headers
// to understand and build pytests to exercise different interfaces.
//
// The tests verifying these interfaces are in test_libswigpytests.py
//
// These SWIG interface rules and interfaces in .h file are carefully
// constructed to verify different combinations. Any changes to these rules
// or to the signature of the .h interfaces (const, names of arg, ...) will
// most likely cause individual test cases to fail.
// *****************************************************************************

%module swigpytests
%include "std_string.i"

// Needed to invoke initialize_simulated_enclave() and other interfaces that take
// (byte *, int) supplied by Python bytestream arg.
%include <pybuffer.i>
%pybuffer_binary(const byte *measurement, int measurement_size);
%pybuffer_binary(const byte* serialized_attest_endorsement_claim, int attest_endorsement_claim_size);
%pybuffer_binary(const byte * serialized_attest_key, int attest_key_size);

// For python_init_client_ssl() that supports byte-stream interface
%pybuffer_binary(const byte * asn1_root_cert, int asn1_root_cert_size);

// Test: test_secure_authenticated_channel_lib()
//       test_secure_authenticated_channel_default()
%apply string * INPUT  { string &role };            // secure_authenticated_channel() constructor

// You don't really need this rule as 'const string &arg' is passed-in by default as input string.
// Test: test_secure_authenticated_channel_init_client_ssl_default()
//       test_secure_authenticated_channel_init_client_ssl_default_2args()
// %apply string * INPUT  { const string &asn1_root_cert };  // secure_authenticated_channel().init_client_ssl()

// Test: test_secure_authenticated_channel_init_client_ssl_input_output()
%apply string * INOUT  { string &asn1_root_cert_io };  // secure_authenticated_channel().init_client_ssl()

%{
#include "swigpytests.h"
%}

%include "swigpytests.h"
