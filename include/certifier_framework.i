// certifier_framework.i- SWIG interface to generate Python bindings
// *****************************************************************************
// The core Certifier Framework APIs are exposed through Swig generated
// Python bindings. Those interfaces are exercised thru these pytests:
//
//  - test_libcertifier_framework.py
//  - test_certifier_framework.py
//
// ... and a few others as they are developed.
// This interface file makes that glue possible through the build process(es).
// *****************************************************************************

%module certifier_framework
%include "std_string.i"

// Needed to invoke init_policy_key() and other interfaces that take
// (byte *, int) supplied by Python bytestream arg.
%include <pybuffer.i>

// These mappings are required for invoking python_initialize_simulated_enclave()
// through Python apps
%pybuffer_binary(const byte *serialized_attest_key, int attest_key_size);
%pybuffer_binary(const byte *measurement, int measurement_size);
%pybuffer_binary(const byte *serialized_attest_endorsement, int attest_key_signed_claim_size);

%pybuffer_binary(byte* asn1_cert, int asn1_cert_size);   // cc_trust_data()->init_policy_key()

// ----------------------------------------------------------------------------
// Ignore few overloaded interfaces so that there is no need to exercise the
// disambiguation code in SWIG-generated wrapper module(s). Otherwise,
// while trying to select the right interface to invoke based on the
// arguments supplied, we run afoul of the limitation registered under
// SWIG issue https://github.com/swig/swig/issues/1916
// ----------------------------------------------------------------------------
%ignore initialize_simulated_enclave(const string &serialized_attest_key,
                                     const string &measurement,
                                     const string &serialized_attest_endorsement);

// ----------------------------------------------------------------------------
// NOTE: We might need to apply this directive if any Python invocations
//       run into issues while SWIG tries to disambiguate overloaded
//       interfaces. For now, these ignore clauses are found to be not
//       needed while running all test cases in test_certifier_framework.py
//
// %ignore init_client_ssl(const string &host_name, int port, const cc_trust_manager &mgr);
// %ignore init_server_ssl(const string &host_name, int port, const cc_trust_manager &mgr);

// Xform interfaces returning a string output param to return string * <function>
%apply string * OUTPUT { string *v };            // policy_store()->get()
%apply string * OUTPUT { string *psout };        // policy_store()->Serialize()

%apply string * INPUT  { string& role };         // secure_authenticated_channel() constructor
%apply string * INPUT  { string * out_peer_id }; // secure_authenticated_channel()->get_peer_id()

%{
#include "certifier_framework.h"
%}

%include "certifier_framework.h"
