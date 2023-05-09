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

clean:
	$(MAKE) -C enclave clean
	$(MAKE) -C host clean

cleanall: clean
	rm -rf app1_data app2_data provisioning service policy_key.cc
	rm -rf binary_trusted_measurements_file.bin

dump_mrenclave:
	oesign dump --enclave-image=./enclave/enclave.signed
	@echo "\e[1;31m Build measurement_init.exe with make -f cert_utility.mak measurement_init.exe in utilities directory\e[1;m"
	@echo "\e[1;31m Invoke measurement_init.exe --mrenclave=xxx --out_file=binary_trusted_measurements_file.bin\e[1;m"
	@echo "\e[1;31m Replace 'xxx' with the mrenclave string from the output above\e[1;m"
	@echo "\e[0;m"
