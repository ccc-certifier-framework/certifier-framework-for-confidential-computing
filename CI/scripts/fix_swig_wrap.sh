#!/bin/bash
# #############################################################################
# Simple script to fix SWIG-generated cc file to implement the fix suggested
# by SWIG issue https://github.com/swig/swig/issues/1916
#
# Invoking Python wrappers to pass strings containing Unicode data
# with surrogate characters runs into some conversion errors.
#
# The fix suggested by above issue is to replace:
#    obj = PyUnicode_AsUTF8String(obj);
# to obj = PyUnicode_AsEncodedString(obj, "utf-8", "surrogateescape");
#
# seems to workaround this issue. This script implements this string
# replacement in the generated wrap*.cc file.

# This script exists as other attempts to define SWIG-typemaps to implement
# the workaound-fix in user-defined typemap()-ing code ran into other
# compilation issues in the generated code.
# This replacement is needed for these reasons:
#
#  - Even though the C++ variants of certain overloaded interfaces like
#    init_client_ssl(), init_server_ssl() are ignored, the data for
#    certain arguments [e.g., string &asn1_root_cert in these methods]
#    contains Unicode surrogate chars. We need to apply this workaround-fix
#    in order for the Python invocation to even succeed argument passing,
#    even with the %ignore specifier in the SWIG.i interface file.
#
# #############################################################################

set -Eeuo pipefail

# Setup script globals, to establish curdir and root path to Certifier code base
Me=$(basename "$0")

set -x

perl -i -p -e 's/obj = PyUnicode_AsUTF8String\(obj\);/obj = PyUnicode_AsEncodedString\(obj, "utf-8", "surrogateescape"\);/' $*
