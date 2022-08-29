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
CERT_SRC=../../../src
CERT_INCL=-I../../../include -I../../../src  -I../eigen3/
DATAFRAME_INCL=-I../third_party/DataFrame/include -I../third_party/mplambda/include  
#DATAFRAME_LIB=../third_party/DataFrame/build/libDataFrame.a 
DATAFRAME_LIB=../third_party/build/libmpl.a ../third_party/build/assimp/lib/libassimp.a ../third_party/build/assimp/contrib/zlib/libzlibstatic.a ../third_party/build/fcl/lib/libfcl.a ../third_party/build/libccd/src/libccd.a
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
	$(PROTO) -I$(CERT_SRC) --cpp_out=. $(CERT_SRC)/certifier.proto
	$(PROTO) -I$(CERT_SRC) --cpp_out=$(CERT_SRC) $(CERT_SRC)/certifier.proto
	$(PROTO) -I../proto/ --cpp_out=. ../proto/mp_options.proto
	$(CXX) -g -Wno-shift-op-parentheses -c $(CXXFLAGS) $(INCLUDES) $(PROTO_INCL) $(CERT_INCL) $(DATAFRAME_INCL) -I. -I.. -std=c++17 -DOE_API_VERSION=2 ecalls.cc $(CERT_SRC)/support.cc $(CERT_SRC)/test_support.cc $(CERT_SRC)/simulated_enclave.cc $(CERT_SRC)/application_enclave.cc $(CERT_SRC)/certifier.cc certifier.pb.cc mp_options.pb.cc $(CERT_SRC)/openenclave/attestation.cc $(CERT_SRC)/openenclave/sealing.cc
	$(CC) -g -c $(CFLAGS) $(CINCLUDES) -I.. -DOE_API_VERSION=2 ./attestation_t.c
	$(CXX) -o enclave ecalls.o attestation_t.o certifier.pb.o mp_options.pb.o certifier.o support.o test_support.o simulated_enclave.o attestation.o sealing.o application_enclave.o $(SEAL_PLUGINS) $(DATAFRAME_LIB) $(LDFLAGS) $(CRYPTO_LDFLAGS) $(PROTO_LIB)  -loehostfs
	strip enclave

sign:
	oesign sign -e enclave -c enc.conf -k private.pem

clean:
	rm -f *.o enclave enclave.signed attestation_t.* attestation_args.h *.pem certifier.pb.* mp_options.pb.* 

keys:
	openssl genrsa -out private.pem -3 3072
	openssl rsa -in private.pem -pubout -out public.pem
