# Copyright 2014 Google Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required(VERSION 2.8.12)
project(tpm2 C CXX ASM)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
find_package(Protobuf REQUIRED)
include_directories(${PROTOBUF_INCLUDE_DIRS})

# Keep a set of common flags and include directories for evmm and bootstrap.
set(WARNING_FLAGS "-Wall -Wno-strict-aliasing -Wno-deprecated")
set(LANG_FLAGS "-std=c++11")
set(CMAKE_C_FLAGS "${WARNING_FLAGS}")
set(CMAKE_CXX_FLAGS "${WARNING_FLAGS} ${LANG_FLAGS}")

set(CMAKE_C_FLAGS_DEBUG "-g -O1")
set(CMAKE_C_FLAGS_RELEASE "-g -O3")
set(CMAKE_CXX_FLAGS_DEBUG ${CMAKE_C_FLAGS_DEBUG})
set(CMAKE_CXX_FLAGS_RELEASE ${CMAKE_C_FLAGS_RELEASE})

set(TPM2_PROTO
    tpm2.proto
   )

PROTOBUF_GENERATE_CPP(PROTO_SRCS PROTO_HDRS ${TPM2_PROTO})

set(TPM2_SOURCES
	tpm2_lib.cc
	conversions.cc
	openssl_helpers.cc
	quote_protocol.cc
   )

set(TPM2_HEADERS
	conversions.h
	openssl_helpers.h
	quote_protocol.h
	tpm12.h
	tpm20.h
	tpm2_lib.h
	tpm2_types.h
   )

include_directories(${CMAKE_SOURCE_DIR})
include_directories(${CMAKE_SOURCE_DIR}/../third_party/google-glog/src)
include_directories(${CMAKE_SOURCE_DIR}/../third_party/gflags/src)

# This is added to get the right path for the protobuf generated header files.
include_directories(${CMAKE_BINARY_DIR})

add_library(tpm2 STATIC
    ${PROTO_SRCS}
    ${PROTO_HDRS}
    ${TPM2_SOURCES}
    ${TPM2_HEADERS}
   )

# TODO(tmroeder): add checks for OpenSSL, libvirt, and libtspi.
target_link_libraries(tpm2
    gflags
    protobuf
    crypto
    ssl
   )

add_executable(tpm2_util tpm2_util.cc)
target_link_libraries(tpm2_util tpm2)

add_executable(GeneratePolicyKey GeneratePolicyKey.cc)
target_link_libraries(GeneratePolicyKey tpm2)

add_executable(CloudProxySignEndorsementKey CloudProxySignEndorsementKey.cc)
target_link_libraries(CloudProxySignEndorsementKey tpm2)

add_executable(GetEndorsementKey GetEndorsementKey.cc)
target_link_libraries(GetEndorsementKey tpm2)

add_executable(SelfSignPolicyCert SelfSignPolicyCert.cc)
target_link_libraries(SelfSignPolicyCert tpm2)

add_executable(CreateAndSaveCloudProxyKeyHierarchy CreateAndSaveCloudProxyKeyHierarchy.cc)
target_link_libraries(CreateAndSaveCloudProxyKeyHierarchy tpm2)

add_executable(RestoreCloudProxyKeyHierarchy RestoreCloudProxyKeyHierarchy.cc)
target_link_libraries(RestoreCloudProxyKeyHierarchy tpm2)

add_executable(ClientGenerateProgramKeyRequest ClientGenerateProgramKeyRequest.cc)
target_link_libraries(ClientGenerateProgramKeyRequest tpm2)

add_executable(ServerSignProgramKeyRequest ServerSignProgramKeyRequest.cc)
target_link_libraries(ServerSignProgramKeyRequest tpm2)

add_executable(ClientGetProgramKeyCert ClientGetProgramKeyCert.cc)
target_link_libraries(ClientGetProgramKeyCert tpm2)

add_executable(SigningInstructions SigningInstructions.cc)
target_link_libraries(SigningInstructions tpm2)

