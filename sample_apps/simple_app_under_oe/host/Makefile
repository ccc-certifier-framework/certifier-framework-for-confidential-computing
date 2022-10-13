# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

include ../config.mk
CFLAGS=$(shell pkg-config oehost-$(C_COMPILER) --cflags)
CXXFLAGS=$(shell pkg-config oehost-$(CXX_COMPILER) --cflags)
LDFLAGS=$(shell pkg-config oehost-$(CXX_COMPILER) --libs)
INCDIR=$(shell pkg-config oehost-$(C_COMPILER) --variable=includedir)

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	oeedger8r ../attestation.edl --untrusted \
		--search-path $(INCDIR) \
		--search-path $(INCDIR)/openenclave/edl/sgx
	$(CC) -g -c $(CFLAGS) $(CINCLUDES) attestation_u.c
	$(CXX) -g -c $(CXXFLAGS) $(INCLUDES) -std=c++11 host.cc
	$(CXX) -o host host.o attestation_u.o $(LDFLAGS)

clean:
	rm -f host host.o attestation_u.o attestation_u.c attestation_u.h attestation_args.h
