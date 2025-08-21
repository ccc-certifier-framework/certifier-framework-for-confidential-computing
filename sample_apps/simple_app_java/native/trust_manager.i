%module(directors="1") trust_manager

%{
#include "trust_manager/trust_manager.h"
#include "cf_shims.h"
%}

// Java package for generated classes:
%package(org.certifier);

// Tell SWIG to generate directors & JNI for C++
%feature("director") TrustManager;

// Expose the class itself:
%include "std_string.i"
%include "std_vector.i"

namespace std {
    %template(StringVector) vector<string>;
}

%include "trust_manager/trust_manager.h"

// --- Add shim functions to access flags ---
%inline %{
extern "C" {
  int cf_tm_auth_key_initialized(TrustManager* tm);
  int cf_tm_primary_admissions_cert_valid(TrustManager* tm);
}
%}
