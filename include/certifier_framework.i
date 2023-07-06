// certifier_framework.i- SWIG interface to generate Python bindings
// *****************************************************************************
// The core Certifier Framework APIs are exposed through Swig generated
// Python bindings. Those interfaces are exercised thru the
// test_cert_framework_basic.py pytest.
// This interface file makes that glue possible through the build process(es).
// *****************************************************************************

%module libcertifier_framework
%include "std_string.i"

%{
#include "certifier_framework.h"
%}

%include "certifier_framework.h"
