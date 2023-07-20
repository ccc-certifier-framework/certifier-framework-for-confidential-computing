// certifier_tests.i- SWIG interface to generate Python bindings to Certifier unit tests
// *****************************************************************************
// A large-ish collection of Certifier tests, defined in certifier_tests.cc and
// related *_tests.cc files, are exposed through Swig generated Python bindings.
// This interface file makes that glue possible through the build process(es).
//
// All those Certifier tests are invoked thru pytest, test_libcertifier_tests.py .
// *****************************************************************************

%module certifier_tests

%{
#include "certifier_tests.h"
%}

// This list is be repeated in this order in certifier_tests.i,
// which defines the SWIG interface for the Python bindings for the
// certifier_tests.so shared library. Otherwise, compilation of the
// generated wrap.cc file will run into unresolved references.
//
%include "primitive_tests.h"
%include "claims_tests.h"
%include "store_tests.h"
%include "support_tests.h"
%include "x509_tests.h"

