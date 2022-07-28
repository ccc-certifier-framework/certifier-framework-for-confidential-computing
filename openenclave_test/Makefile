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
	rm /tmp/binary_trusted_measurements_file.bin
run:
	host/host enclave/enclave.signed

dump_mrenclave:
	oesign dump --enclave-image=./enclave/enclave.signed
	@echo "\e[1;31m Invoke measurement_init.exe --mrenclave=xxx --out_file=/tmp/binary_trusted_measurements_file.bin\e[1;m"
	@echo "\e[1;31m Replace 'xxx' with the mrenclave string from the output above\e[1;m"
	@echo "\e[1;31m Build measurement_init.exe with make -f cert_utility.mak measurement_init.exe in utilities directory\e[1;m"
