#  Copyright (c) 2021-22, VMware Inc, and the Certifier Authors.  All rights reserved.
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

cc_library(
    name = "openssl",
    hdrs = glob(["**/include/openssl/*.h"]),
    linkopts = [ "-L/usr/lib/x86_64-linux-gnu", "-lssl", "-lcrypto"],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "cc_helpers",
    hdrs = glob([
        "include/*.h",
        "**/include/google/protobuf*.h",
    ]),
    includes = [ "include" ],
    srcs = [
             "src/certifier.cc",
             "src/support.cc",
             "src/simulated_enclave.cc",
             "src/application_enclave.cc",
             "src/cc_helpers.cc",
             "sample_apps/asylo_secure_grpc/certifier.pb.cc",
    ],
    deps = [ ":openssl",
	     # For Asylo protobuf
             #":certifier_asylo_cc_proto",
    ],
    copts = [
        "-Iinclude",
        "-DASYLO_CERTIFIER",
        "-DBORING_SSL",
    ],
    linkopts = [ "-L/usr/local/lib", "-lprotobuf"],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "untrusted",
    hdrs = glob([
        "include/*.h",
        "sample_apps/asylo_secure_grpc/certifier.pb.h",
    ]),
    includes = [ "include" ],
    srcs = [ "sample_apps/asylo_secure_grpc/asylo_untrusted.cc",
             "sample_apps/asylo_secure_grpc/certifier.pb.cc",
    ],
    deps = [ ":openssl",
             ":cc_helpers",
	     # For Asylo protobuf
             #":certifier_asylo_cc_proto",
             "@com_google_googletest//:gtest",

    ],
    copts = [
        "-Iinclude",
        "-DASYLO_CERTIFIER",
        "-DBORING_SSL",
    ],
    #linkopts = [ "-L/usr/local/lib", "-lprotobuf"],
    visibility = ["//visibility:public"],
)


# For Asylo protobuf
#proto_library(
#    name = "certifier_asylo_proto",
#    srcs = ["src/certifier.proto"],
#    visibility = ["//visibility:public"],
#)

#cc_proto_library(
#    name = "certifier_asylo_cc_proto",
#    visibility = ["//visibility:public"],
#    deps = ["certifier_asylo_proto"],
#)

cc_library(
    name = "trusted",
    hdrs = glob([
        "include/*.h",
        "include/policy_key.cc",
        "src/asylo/asylo_api.h",
    ]),
    includes = [ "include" ],
    srcs = [ "sample_apps/asylo_secure_grpc/asylo_trusted.cc",
             "src/certifier.cc",
             "src/support.cc",
             "src/simulated_enclave.cc",
             "src/application_enclave.cc",
             "src/cc_helpers.cc",
             "src/test_support.cc",
             "src/asylo/asylo_api.cc",
             "sample_apps/asylo_secure_grpc/certifier.pb.cc",
    ],
    deps = [
	     # For Asylo protobuf
             #":certifier_asylo_cc_proto",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/synchronization",
        "@com_github_grpc_grpc//:grpc++",
        "@com_github_grpc_grpc//:grpc++_reflection",
        "@com_google_googletest//:gtest",
        "@com_google_protobuf//:protobuf",
        "@com_google_asylo//asylo/grpc/util:grpc_server_launcher",
        "@com_google_asylo//asylo/identity/platform/sgx:sgx_identity_cc_proto",
    ],
    copts = [
        "-Iinclude",
        "-DASYLO_CERTIFIER",
        "-DBORING_SSL",
    ],
    visibility = ["//visibility:public"],
)
