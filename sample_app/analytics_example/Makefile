# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

.PHONY: all build clean run

OE_CRYPTO_LIB := openssl
export OE_CRYPTO_LIB

all: build

build:
	$(MAKE) -C enclave
	$(MAKE) -C host

clean:
	$(MAKE) -C enclave clean
	$(MAKE) -C host clean
	rm -rf app1_data app2_data provisioning service policy_key.cc

run:
	host/host enclave/enclave.signed

dummy_mrenclave:
	oesign dump --enclave-image=./enclave/enclave.signed