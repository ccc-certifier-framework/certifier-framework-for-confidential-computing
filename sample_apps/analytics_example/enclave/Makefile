# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

include ../config.mk

CFLAGS=$(shell pkg-config oeenclave-$(C_COMPILER) --cflags)
CXXFLAGS=$(shell pkg-config oeenclave-$(CXX_COMPILER) --cflags) -DOE_CERTIFIER 
LDFLAGS=$(shell pkg-config oeenclave-$(CXX_COMPILER) --libs)
INCDIR=$(shell pkg-config oeenclave-$(C_COMPILER) --variable=includedir)
LIBDIR:= $(shell pkg-config oeenclave-$(C_COMPILER) --variable=libdir)/openenclave
CRYPTO_LDFLAGS=$(shell pkg-config oeenclave-$(COMPILER) --variable=${OE_CRYPTO_LIB}libs)
PROTO=../../../openenclave_test/protobufs-bin/bin/protoc
PROTO_INCL=-I../../../openenclave_test/protobufs-bin/include
PROTO_LIB=-L../../../openenclave_test/protobufs-bin/lib -lprotobuf -loeenclave -loelibcxx -loelibc -loesyscall -loecore -loesyscall -loecore -loehostsock -loehostresolver

# CERTIFIER_ROOT will be certifier-framework-for-confidential-computing/ dir
CERTIFIER_ROOT = ../../..

CERT_SRC = $(CERTIFIER_ROOT)/src
CERT_INCL=-I$(CERTIFIER_ROOT)/include -I$(CERT_SRC)
CP = $(CERTIFIER_ROOT)/certifier_service/certprotos

DATAFRAME_INCL=-I../third_party/DataFrame/include
DATAFRAME_LIB=../third_party/DataFrame/build/libDataFrame.a 

#
# Seal plug-ins are searched in two steps.
#
OE_SEAL_PLUGINS?= gcmaes
OE_SDK_BUILD_TYPES?= Release RelWithDebInfo MinSizeRel Debug

# Step 1 - Determine BUILD_TYPE (hence the directory containing seal plug-ins)
SEAL_PLUGIN_DIR:= $(or $(firstword $(wildcard $(addsuffix /,	\
	$(addprefix $(LIBDIR)/enclave/objects-,$(OE_SDK_BUILD_TYPES))))),	\
	$(error Cannot determine CMAKE_BUILD_TYPE. Object paths:	\
		$(shell find $(LIBDIR)/enclave -type d -name objects-*)))

# Step 2 - Locate seal plug-in object files.
SEAL_PLUGINS:= $(foreach p,$(OE_SEAL_PLUGINS),$(or	\
	$(wildcard $(SEAL_PLUGIN_DIR)oeseal_$p/*.o),	\
	$(wildcard $(SEAL_PLUGIN_DIR)oeseal_$p-lvi-cfg/*.o),	\
	$(error Seal plug-in \'$p\' missing in $(SEAL_PLUGIN_DIR))))

all:
	$(MAKE) build
	$(MAKE) keys
	$(MAKE) sign

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	oeedger8r ../attestation.edl --trusted --trusted-dir ./ \
		--search-path $(INCDIR) \
		--search-path $(INCDIR)/openenclave/edl/sgx
	$(PROTO) --cpp_out=. --proto_path=$(CP) $(CP)/certifier.proto
	$(CXX) -g -Wno-shift-op-parentheses -c $(CXXFLAGS) $(INCLUDES) $(PROTO_INCL) $(CERT_INCL) $(DATAFRAME_INCL) -I. -I.. -std=c++17 -DOE_API_VERSION=2 ecalls.cc $(CERT_SRC)/support.cc $(CERT_SRC)/test_support.cc $(CERT_SRC)/simulated_enclave.cc $(CERT_SRC)/application_enclave.cc $(CERT_SRC)/certifier.cc $(CERT_SRC)/certifier_proofs.cc ./certifier.pb.cc $(CERT_SRC)/openenclave/attestation.cc $(CERT_SRC)/openenclave/sealing.cc $(CERT_SRC)/cc_helpers.cc $(CERT_SRC)/cc_useful.cc
	$(CC) -g -c $(CFLAGS) $(CINCLUDES) -I.. -DOE_API_VERSION=2 ./attestation_t.c
	$(CXX) -o enclave ecalls.o attestation_t.o certifier.pb.o certifier.o certifier_proofs.o support.o test_support.o simulated_enclave.o attestation.o sealing.o application_enclave.o cc_helpers.o cc_useful.o $(SEAL_PLUGINS) $(DATAFRAME_LIB) $(LDFLAGS) $(CRYPTO_LDFLAGS) $(PROTO_LIB)  -loehostfs
	strip enclave

sign:
	oesign sign -e enclave -c enc.conf -k private.pem

clean:
	rm -f *.o enclave enclave.signed attestation_t.* attestation_args.h *.pem certifier.pb.* 

keys:
	openssl genrsa -out private.pem -3 3072
	openssl rsa -in private.pem -pubout -out public.pem
