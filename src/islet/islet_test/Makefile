# #############################################################################
# File: src/cca/islet_test/Makefile
# #############################################################################

CC=g++
GPP=g++
PROTO=protoc

# CERTIFIER_ROOT will be certifier-framework-for-confidential-computing/ dir
CERTIFIER_ROOT = ../../..

# Symbol to CERTIFIER_ROOT/src/ dir
ifndef SRC_DIR
SRC_DIR=../..
endif

ifndef OBJ_DIR
OBJ_DIR=.
endif

ifndef LOCAL_LIB
LOCAL_LIB=/usr/local/lib
endif

CP = $(CERTIFIER_ROOT)/certifier_service/certprotos

S = $(SRC_DIR)
O = $(OBJ_DIR)
CCAS = $(S)/cca
US = .

I = $(SRC_DIR)/../include
ISLET_PATH = ../../../third_party/islet
ISLET_INCLUDE= -I $(ISLET_PATH)/include
ISLET_LDFLAGS= -L $(ISLET_PATH)/lib -lislet_sdk

CERTIFIER_INCLUDE= -I ../../../include

# List of dependent objects
dobj = $(O)/certifier.pb.o $(O)/shim_test.o $(O)/islet_shim.o $(O)/support.o

.PHONY: all
all: attest_seal_test

# Compilation of protobuf files could run into some errors, so avoid using
# # -Werror for those targets
CFLAGS_NOERROR = -I $(I) -O3 -g -Wall -std=c++11 -Wno-unused-variable -D X64 -Wno-deprecated-declarations -D CCA_CERTIFIER
CFLAGS += $(CFLAGS_NOERROR) -Werror $(ISLET_INCLUDE) $(CERTIFIER_INCLUDE)

LDFLAGS = $(ISLET_LDFLAGS) -L $(LOCAL_LIB) -lprotobuf -L /usr/local/opt/openssl@1.1/lib/ -lcrypto -lssl

.PHONY: attest_seal_test
attest_seal_test: attest_seal_test.cc
	@echo "Compiling $<"
	@$(GPP) $< $(CFLAGS) $(LDFLAGS) -o $@
	LD_LIBRARY_PATH=$(ISLET_PATH)/lib ./$@

.PHONY: shim_test
shim_test: $(dobj)
	@echo "\nLinking $@"
	$(GPP) -o $@ $^ $(LDFLAGS)
	@echo "\nExecute $@:"
	LD_LIBRARY_PATH=$(ISLET_PATH)/lib ./$@

$(O)/shim_test.o: shim_test.cc
	@echo "\nCompiling $<"
	$(CC) $(CFLAGS) -c $< -o $@

$(O)/islet_shim.o: ../islet_shim.cc
	@echo "\nCompiling $<"
	$(CC) $(CFLAGS) -c $< -o $@

$(O)/support.o: $(S)/support.cc $(I)/support.h
	@echo "\nCompiling $<"
	$(CC) $(CFLAGS) -c $< -o $@

# Dependencies on protobuf and other Certifier files
$(US)/certifier.pb.cc: $(CP)/certifier.proto
	@echo "\nGenerate protobuf files"
	$(PROTO) --proto_path=$(CP) --cpp_out=$(US) $<
	mv $(US)/certifier.pb.h $(I)

$(I)/certifier.pb.h: $(US)/certifier.pb.cc

$(O)/certifier.pb.o: $(US)/certifier.pb.cc $(I)/certifier.pb.h
	@echo "\nCompiling $<"
	$(CC) $(CFLAGS_NOERROR) -c $< -o $@

.PHONY: test
test: attest_seal_test shim_test

.PHONY: clean
clean:
	@echo "removing generated files"
	rm -rf $(I)/certifier.pb.h $(US)/certifier.pb.h $(US)/certifier.pb.cc
	@echo "removing object files"
	rm -rf $(O)/*.o
	@echo "removing executable files"
	rm -rf shim_test attest_seal_test
