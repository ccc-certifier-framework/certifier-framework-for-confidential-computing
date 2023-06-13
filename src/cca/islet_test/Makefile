#
#   File: src/cca/islet_test/Makefile
#
GPP=g++
ISLET_PATH = ../../../third_party/islet
ISLET_INCLUDE= -I$(ISLET_PATH)/include
ISLET_LDFLAGS= -L$(ISLET_PATH)/remote/out/x86_64-unknown-linux-gnu/debug/ -lislet_sdk

.PHONY: all
all: attest_seal_test

CFLAGS += $(ISLET_INCLUDE)
LDFLAGS += $(ISLET_LDFLAGS)

.PHONY: attest_seal_test
attest_seal_test: attest_seal_test.cc
	@echo "Compiling $<"
	@$(GPP) $< $(CFLAGS) $(LDFLAGS) -o $@
	@LD_LIBRARY_PATH=$(ISLET_PATH)/remote/out/x86_64-unknown-linux-gnu/debug ./$@

.PHONY: shim_test
shim_test: shim_test.cc ../cca_shim.cc
	@echo "Compiling $<"
	@$(GPP) $^ $(CFLAGS) $(LDFLAGS) -o $@
	@LD_LIBRARY_PATH=$(ISLET_PATH)/remote/out/x86_64-unknown-linux-gnu/debug ./$@

.PHONY: test
test: attest_seal_test shim_test

.PHONY: clean
clean:
	@echo "removing executable files"
	@rm -rf attest_seal_test
