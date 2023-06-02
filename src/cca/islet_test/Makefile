GPP=g++
ISLET_PATH = ../../../third_party/islet
ISLET_INCLUDE= -I$(ISLET_PATH)/include
ISLET_LDFLAGS= -L$(ISLET_PATH)/lib -lislet_sdk

.PHONY: all
all: attest_seal_test

CFLAGS += $(ISLET_INCLUDE)
LDFLAGS += $(ISLET_LDFLAGS)

.PHONY: attest_seal_test
attest_seal_test: attest_seal_test.cc
	@$(GPP) $< $(CFLAGS) $(LDFLAGS) -o $@
	@LD_LIBRARY_PATH=$(ISLET_PATH)/lib ./$@

.PHONY: shim_test
shim_test: shim_test.cc ../cca_shim.cc
	@$(GPP) $^ $(CFLAGS) $(LDFLAGS) -o $@
	@LD_LIBRARY_PATH=$(ISLET_PATH)/lib ./$@

.PHONY: test
test: attest_seal_test shim_test

.PHONY: clean
clean:
	@rm -rf attest_seal_test
