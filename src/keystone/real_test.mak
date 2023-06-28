# #############################################################################
# File: src/keystone/shim_test.mak
# #############################################################################

# See sample_apps/simple_app_under_keystone/instructions.md

# CERTIFIER_ROOT will be certifier-framework-for-confidential-computing/ dir
CERTIFIER_ROOT = ../..

ifndef SRC_DIR
SRC_DIR=..
endif
ifndef INC_DIR
INC_DIR=../../include
endif
ifndef OBJ_DIR
OBJ_DIR=./riscv64
endif
ifndef EXE_DIR
EXE_DIR=./riscv64
endif

ifndef KEYSTONE_ROOT_DIR
    KEYSTONE_ROOT_DIR = /keystone
endif
ifndef RISCV_SUPPORT
    RISCV_SUPPORT = ./packages
endif

# all the Keystone headers, srcs, and libs
KEYSTONE_SDK_INCLUDE = $(KEYSTONE_ROOT_DIR)/sdk/build64/include
KEYSTONE_SDK_LIB_DIR = $(KEYSTONE_ROOT_DIR)/sdk/build64/lib
KEYSTONE_SDK_LIBS = -lkeystone-host -lkeystone-eapp -lkeystone-edge -lkeystone-verifier
KEYSTONE_RT_INCLUDE = $(KEYSTONE_ROOT_DIR)/runtime/include
KEYSTONE_RT_SRC = $(KEYSTONE_ROOT_DIR)/runtime
KEYSTONE_FLAGS = -DUSE_PAGE_CRYPTO -DKEYSTONE_PRESENT

# RISC-V cross compiler
CC = riscv64-unknown-linux-gnu-g++
LINK = riscv64-unknown-linux-gnu-g++
# flags from Keystone
INCLUDE = -I$(KEYSTONE_SDK_INCLUDE) -I$(KEYSTONE_RT_INCLUDE)
LDFLAGS = -static -L$(KEYSTONE_SDK_LIB_DIR) $(KEYSTONE_SDK_LIBS)

# Certifier-related
ifndef TARGET_MACHINE_TYPE
TARGET_MACHINE_TYPE= RISCV64
endif

CP = $(CERTIFIER_ROOT)/certifier_service/certprotos

S= $(SRC_DIR)/keystone
O= $(OBJ_DIR)
I= $(INC_DIR)

INCLUDE+=-I$(I) -I$(RISCV_SUPPORT)/include -I .

ifdef ENABLE_SEV
CFLAGS+=$(INCLUDE) -O3 -g -Wall -std=c++11 -Wno-unused-variable -D X64 -D SEV_SNP -Wno-deprecated-declarations
CFLAGS1+=$(INCLUDE) -O1 -g -Wall -std=c++11 -Wno-unused-variable -D X64 -D SEV_SNP -Wno-deprecated-declarations
else
CFLAGS+=$(INCLUDE) -O3 -g -Wall -std=c++11 -Wno-unused-variable -D X64 -Wno-deprecated-declarations
CFLAGS1+=$(INCLUDE) -O1 -g -Wall -std=c++11 -Wno-unused-variable -D X64 -Wno-deprecated-declarations
endif

# Point this to the right place, if you have to, based on your machine's install:
PROTO=$(RISCV_SUPPORT)/bin/protoc
AR=ar
# LDFLAGS+= -L$(RISCV_SUPPORT)/lib -lprotobuf -lssl -lcrypto -ldl # this one is fragile
LDFLAGS+= $(RISCV_SUPPORT)/lib/libprotobuf.a $(RISCV_SUPPORT)/lib/libssl.a $(RISCV_SUPPORT)/lib/libcrypto.a -ldl

dobj = $(O)/certifier.pb.o $(O)/certifier.o $(O)/certifier_proofs.o  	  	  	   \
       $(O)/support.o $(O)/application_enclave.o $(O)/simulated_enclave.o  	  	   \
       $(O)/cc_helpers.o $(O)/cc_useful.o $(O)/keystone_api.o $(O)/keystone_test.o \
	   $(O)/keystone_aes.o

all:	$(EXE_DIR)/keystone_test.exe
clean:
	@echo "removing generated files"
	rm -rf $(S)/certifier.pb.cc $(S)/certifier.pb.h $(I)/certifier.pb.h
	@echo "removing object files"
	rm -rf $(O)/*.o
	@echo "removing executable files"
	rm -rf $(EXE_DIR)/keystone_test.exe

$(S)/certifier.pb.cc $(I)/certifier.pb.h: $(CP)/certifier.proto
	$(PROTO) --proto_path=$(CP) --cpp_out=$(S) $<
	mv $(S)/certifier.pb.h $(I)

$(EXE_DIR)/keystone_test.exe: $(dobj) | $(O)
	@echo "linking certifier library"
	$(LINK) -o $(EXE_DIR)/keystone_test.exe $(dobj) $(LDFLAGS)

$(O)/keystone_test.o: $(S)/keystone_test.cc $(I)/certifier.pb.h $(I)/certifier.h | $(O)
	@echo "compiling keystone_test.cc"
	$(CC) $(CFLAGS) -c -o $(O)/keystone_test.o $(S)/keystone_test.cc

$(O)/keystone_api.o: $(S)/keystone_api.cc $(I)/certifier.pb.h $(I)/certifier.h | $(O)
	@echo "compiling keystone_api.cc"
	$(CC) $(CFLAGS) $(KEYSTONE_FLAGS) -c -o $(O)/keystone_api.o $(S)/keystone_api.cc

$(O)/keystone_aes.o: $(KEYSTONE_RT_SRC)/crypto/aes.c | $(O)
	@echo "compiling keystone_aes.c"
	mkdir -p $(O)
	$(CC) $(CFLAGS) $(KEYSTONE_FLAGS) -c -o $(O)/keystone_aes.o $(KEYSTONE_RT_SRC)/crypto/aes.c

$(O)/certifier.pb.o: $(S)/certifier.pb.cc $(I)/certifier.pb.h | $(O)
	@echo "compiling certifier.pb.cc"
	$(CC) $(CFLAGS) -Wno-array-bounds -c -o $(O)/certifier.pb.o $<

$(O)/certifier.o: $(SRC_DIR)/certifier.cc $(I)/certifier.pb.h $(I)/certifier.h | $(O)
	@echo "compiling certifier.cc"
	$(CC) $(CFLAGS) -c -o $(O)/certifier.o $(SRC_DIR)/certifier.cc

$(O)/certifier_proofs.o: $(SRC_DIR)/certifier_proofs.cc $(I)/certifier.pb.h $(I)/certifier.h | $(O)
	@echo "compiling certifier_proofs.cc"
	$(CC) $(CFLAGS) -c -o $(O)/certifier_proofs.o $(SRC_DIR)/certifier_proofs.cc

$(O)/support.o: $(SRC_DIR)/support.cc $(I)/support.h | $(O)
	@echo "compiling support.cc"
	$(CC) $(CFLAGS) -c -o $(O)/support.o $(SRC_DIR)/support.cc

$(O)/simulated_enclave.o: $(SRC_DIR)/simulated_enclave.cc $(I)/simulated_enclave.h | $(O)
	@echo "compiling simulated_enclave.cc"
	$(CC) $(CFLAGS) -c -o $(O)/simulated_enclave.o $(SRC_DIR)/simulated_enclave.cc

$(O)/application_enclave.o: $(SRC_DIR)/application_enclave.cc $(I)/application_enclave.h | $(O)
	@echo "compiling application_enclave.cc"
	$(CC) $(CFLAGS) -c -o $(O)/application_enclave.o $(SRC_DIR)/application_enclave.cc

$(O)/cc_helpers.o: $(SRC_DIR)/cc_helpers.cc $(I)/cc_helpers.h | $(O)
	@echo "compiling cc_helpers.cc"
	$(CC) $(CFLAGS) -c -o $(O)/cc_helpers.o $(SRC_DIR)/cc_helpers.cc

$(O)/cc_useful.o: $(SRC_DIR)/cc_useful.cc $(I)/cc_useful.h | $(O)
	@echo "compiling cc_useful.cc"
	$(CC) $(CFLAGS) -c -o $(O)/cc_useful.o $(SRC_DIR)/cc_useful.cc

$(O):
	mkdir -p $(O)

