#!/bin/bash
# #############################################################################
# Simple script to take a list of input tokens and replace the algorithm name
# with a specified new-name. This script receives a mapping data-file which
# specifies the prefix of the new name.
#
# Example:
#   "aes-128"   -> Enc_method_aes_128
#   "sha256"    -> Digest_method_sha256
#
# This replacement rule is specified by a line as follows in the map file:
#
# Enc_method:"aes-128"
# Digest_method:"sha-256"
#
# This script will drive the text substitution.
# #############################################################################
set -Eeuo pipefail

# Setup script globals, to establish curdir and root path to Certifier code base
Me=$(basename "$0")

# Expect to run this script from Certifier source root dir
# shellcheck disable=SC2046
CERT_SRC_ROOT="$(pwd)"; export CERT_SRC_ROOT

# Base name of generated file(s)
CERT_GEN_FILE_BASE="certifier_algorithms"
CERT_HDR_GUARD="CERTIFIER_ALGORITHMS"

# ##################################################################
# Print help / usage
# ##################################################################
function usage_help() {
    echo "Usage: $Me [-h | --help] <algorithm-map-file-name>"
}

# ##################################################################
function gen_copyright() {
echo "//  Copyright (c) 2021-22, VMware Inc, and the Certifier Authors.  All rights
//  reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
"
}

# ##################################################################
function gen_definitions() {
    ftype="$1"  # 'dotc' or 'doth'
    tag="$2"
    map_file="$3"
    namelen="$4"

    # Grab title line for this category of algorithm names from map file
    cat_title=$(grep -E "^# ${tag}" ${map_file} | cut -f2 -d':')

    echo "/*"
    echo " * ${cat_title}"
    echo " */"

    fmtext=""
    if [ "${ftype}" = "doth" ]; then fmtext="extern "; fi

    for map in $(cat ${map_file} | grep -E "^${tag}" | grep -v -E "#"); do

        orig=$(echo "${map}" | cut -f2 -d':')
        from=$(echo "${orig}" | cut -f2 -d':' | sed 's/-/_/g' | sed 's/"//g' )
        category=$(echo ${map} | cut -f1 -d':')
        to="${category}_${from}"

        # Construct .h / .c file entries, as in:
        # .h -> extern const char *Enc_method_aes_128;
        # .c -> const char * Enc_method_aes_128                   = "aes-128";
        fmtstr="${fmtext}const char *"
        if [ "${ftype}" = "dotc" ]; then
            fmtstr="${fmtstr} %-${namelen}s = ${orig}"
        else
            fmtstr="${fmtstr}%s"
        fi
        fmtstr="${fmtstr};\n"

        # echo "$fmtstr"
        echo "${to}" | awk -va_fmt="${fmtstr}" '{printf a_fmt, $1}'
    done
    echo " "
}

# ##################################################################
# main() begins here
# ##################################################################

# Simple command-line arg processing. Expect mapping file-name
if [ $# -eq 0 ] || [ "$1" == "--help" ] || [ "$1" == "-h" ]; then
    usage_help
    exit 1
fi

map_file="$1"

# Can supply file(s) to process on command-line. Otherwise, script will
# plough thru source dirs, looking for files where source string appears.
shift

# ###########################################################################
# Iterate thru each "<prefix>:<string>" pairs, and apply to source files
# ###########################################################################
Max_enc_method_nlen=0
Max_digest_nlen=0
Max_mac_nlen=0

if [ $# -gt 0 ]; then
    # shellcheck disable=SC2086,SC2048
    list_of_files=$*
else
    list_of_files=$(find "${CERT_SRC_ROOT}" -name "*.cc" -print)
fi

for map in $(cat ${map_file} | grep -v -E "#"); do

    orig=$(echo "${map}" | cut -f2 -d':')
    from=$(echo "${orig}" | cut -f2 -d':' | sed 's/-/_/g' | sed 's/"//g' )
    category=$(echo ${map} | cut -f1 -d':')
    to="${category}_${from}"
    # echo "${map} : ${orig} -> ${to}"

    # Establish max name-lengths of generated string
    len_to=${#to}
    if [ "${category}" = "Enc_method" ]; then
        if [ ${len_to} -gt ${Max_enc_method_nlen} ]; then
            Max_enc_method_nlen=${len_to}
        fi
    elif [ "${category}" = "Digest_method" ]; then
        if [ ${len_to} -gt ${Max_digest_nlen} ]; then
            Max_digest_nlen=${len_to}
        fi
    elif [ "${category}" = "Integrity_method" ]; then
        if [ ${len_to} -gt ${Max_mac_nlen} ]; then
            Max_mac_nlen=${len_to}
        fi
    fi

    perl -i -p -e "s/${orig}/${to}/" ${list_of_files}
done

# echo "Enc_method=${Max_enc_method_nlen}, Digest_method=${Max_digest_nlen}, Integrity_method=${Max_mac_nlen}"


# ###########################################################################
# Generate the corresponding .h / .c-files listing the algorigthm names.
# ###########################################################################
dotc_file="${CERT_SRC_ROOT}/src/${CERT_GEN_FILE_BASE}.cc"

gen_copyright > "${dotc_file}"

echo "
// clang-format off
" >> "${dotc_file}"

gen_definitions "dotc" "Enc_method" "${map_file}" ${Max_enc_method_nlen} >> "${dotc_file}"
gen_definitions "dotc" "Digest_method" "${map_file}" ${Max_digest_nlen} >> "${dotc_file}"
gen_definitions "dotc" "Integrity_method" "${map_file}" ${Max_mac_nlen} >> "${dotc_file}"

echo "// clang-format on
" >> "${dotc_file}"

doth_file="${CERT_SRC_ROOT}/include/${CERT_GEN_FILE_BASE}.h"

gen_copyright > "${doth_file}"

echo "
#ifndef __${CERT_HDR_GUARD}_H__
#define __${CERT_HDR_GUARD}_H__
" >> "${doth_file}"

gen_definitions "doth" "Enc_method" "${map_file}" ${Max_enc_method_nlen} >> "${doth_file}"
gen_definitions "doth" "Digest_method" "${map_file}" ${Max_digest_nlen} >> "${doth_file}"
gen_definitions "doth" "Integrity_method" "${map_file}" ${Max_mac_nlen} >> "${doth_file}"

echo "#endif // __${CERT_HDR_GUARD}_H__" >> "${doth_file}"

