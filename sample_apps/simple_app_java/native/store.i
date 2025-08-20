%module store

%{
#include "store/store.h"
%}

%package(org.certifier);

%include "std_string.i"
%include "std_vector.i"

%include "store/store.h"
