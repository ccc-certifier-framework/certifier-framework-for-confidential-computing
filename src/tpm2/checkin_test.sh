#
#    Copyright 2026 John Manferdelli, All Rights Reserved.
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#       http://www.apache.org/licenses/LICENSE-2.0
#    or in the the file LICENSE-2.0.txt in the top level sourcedirectory
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License
#    File: tpm2_support.mak

#ifndef CERTIFIER_ROOT
CERTIFIER_ROOT=../..
#endif
TPM_DIR=$(CERTIFIER_ROOT)/src/tpm2
#ifndef EXE_DIR
EXE_DIR=$(TPM_DIR)
#endif
#ifndef GOOGLE_INCLUDE
GOOGLE_INCLUDE=/usr/local/include/google
#endif
#ifndef LOCAL_LIB
LOCAL_LIB=/usr/local/lib
#endif
#ifndef TARGET_MACHINE_TYPE
TARGET_MACHINE_TYPE= x64
#endif

# compile
make clean -f tpm2_support.mak
make -f tpm2_support.mak

# set up directory for siimulator start

# install simulator if its not here


./clean-tpm-simulator.sh
./start-tpm-simulator.sh

