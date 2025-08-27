%module trust_manager

%{
#include "trust_manager/trust_manager.h"
#include "cf_shims.h"
%}

%package(org.certifier)

%include "std_string.i"
%include "std_vector.i"

%include "trust_manager/trust_manager.h"

// Shim functions (so Java can read the flags)
%inline %{
extern "C" {
  int cf_tm_auth_key_initialized(TrustManager* tm);
  int cf_tm_primary_admissions_cert_valid(TrustManager* tm);
}
%}
