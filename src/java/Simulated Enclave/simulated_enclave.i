%module simulated_enclave

%{
#include "simulated_enclave.h"
%}

%include "std_string.i"

// Wraps functions from simulated_enclave.h
bool simulated_init();
bool simulated_attest(std::string* out);
bool simulated_get_platform_cert(std::string* out_cert);
bool simulated_get_measurement(std::string* out_measurement);
