// certifier_framework.i- SWIG interface to generate Python bindings
// *****************************************************************************
// The core Certifier Framework APIs are exposed through Swig generated
// Python bindings. Those interfaces are exercised thru the
// test_cert_framework_basic.py pytest.
// This interface file makes that glue possible through the build process(es).
// *****************************************************************************

%module certifier_framework
%include "std_string.i"

// Xform interfaces returning a string output param to return string * as a function
%apply string *OUTPUT { string *v }                 // get()
%apply string *OUTPUT { string *psout }             // Serialize()

%{
#include "certifier_framework.h"
%}

%include "certifier_framework.h"
