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

// Needed to invoke init_policy_key() using Python bytestream arg.
%include <pybuffer.i>
%pybuffer_binary(byte* asn1_cert, int asn1_cert_size)   // cc_trust_data()->init_policy_key()

// Xform interfaces returning a string output param to return string * <function>
%apply string * OUTPUT { string *v };            // policy_store()->get()
%apply string * OUTPUT { string *psout };        // policy_store()->Serialize()

%apply string * INPUT  { string& role };         // secure_authenticated_channel() constructor
%apply string * INPUT  { string * out_peer_id }; // secure_authenticated_channel()->get_peer_id()

/* Convert from Python --> C */
%typemap(in) const string {

    // $1 =  PyUnicode_AsEncodedString($input, "utf-8", "surrogateescape");

    std::string *ptr = (std::string *)0;

    $result = PyUnicode_AsEncodedString($input, "utf-8", "surrogateescape");

    if (!SWIG_IsOK($result)) {
      SWIG_exception_fail(SWIG_ArgError($result), "in method '" "server_dispatch" "', argument " "3"" of type '" "string const &""'"); 
    }
    if (!ptr) {
      SWIG_exception_fail(SWIG_ValueError, "invalid null reference " "in method '" "server_dispatch" "', argument " "3"" of type '" "string const &""'"); 
    }
    $result = ptr;
}
%apply const string { const string &asn1_root_cert };

%{
#include "certifier_framework.h"
%}

%include "certifier_framework.h"
