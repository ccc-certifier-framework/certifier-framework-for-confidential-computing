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
// %inline %{
// using namespace std;
// %}
// using std::string;

// %begin %{
// #define SWIG_PYTHON_2_UNICODE
// %}

// Needed to invoke init_policy_key() using Python bytestream arg.
%include <pybuffer.i>
%pybuffer_binary(byte* asn1_cert, int asn1_cert_size)   // cc_trust_data()->init_policy_key()

// Xform interfaces returning a string output param to return string * <function>
%apply string * OUTPUT { string *v }             // policy_store()->get()
%apply string * OUTPUT { string *psout }         // policy_store()->Serialize()

%apply string * INPUT  { string& role};          // secure_authenticated_channel() constructor

// %apply string * INPUT  { string& asn1_root_cert};// secure_authenticated_channel()->init_client_ssl()
// %apply const std::string& {std::string* foo};

// %apply const std::string& { string& asn1_root_cert};// secure_authenticated_channel()->init_client_ssl()

// %apply string * INOUT { string& asn1_root_cert };// secure_authenticated_channel()->init_client_ssl()

// %apply string * INPUT  { string * out_peer_id};  // secure_authenticated_channel()->get_peer_id()

// %typemap(in, numinputs=0) std::string& asn1_root_cert (std::string temp) {
//     $1 = &temp;
// }

// %typemap(argout) std::string& {
//     $result = PyUnicode_FromString($1->c_str());
// }

// Define a typemap for handling string& parameter
// %typemap(in, numinputs=0) std::string& (std::string temp) %{
//     $1 = &temp;
// %}

// Define a typemap for returning strings by reference
// %typemap(out) std::string& {
//     $result = SWIG_From_std_string(*$1);
// }

%{
#include "certifier_framework.h"
%}

%include "certifier_framework.h"
