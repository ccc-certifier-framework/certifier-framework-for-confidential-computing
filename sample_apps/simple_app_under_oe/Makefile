# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

.PHONY: all build clean run

OE_CRYPTO_LIB := openssl
export OE_CRYPTO_LIB
MEASUREMENT_INIT := measurement_init.exe

all: build

build:
	$(MAKE) -C enclave
	$(MAKE) -C host
	$(MEASUREMENT_INIT) --in_file=./enclave/enclave --out_file=/tmp/binary_trusted_measurements_file.bin

clean:
	$(MAKE) -C enclave clean
	$(MAKE) -C host clean

cleanall: clean
	rm -rf app1_data app2_data provisioning service policy_key.cc
	rm /tmp/binary_trusted_measurements_file.bin

run:
	host/host enclave/enclave

dummy_mrenclave:
	oesign dump --enclave-image=./enclave/enclave.signed
