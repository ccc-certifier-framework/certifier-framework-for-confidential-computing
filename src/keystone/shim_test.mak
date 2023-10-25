# #############################################################################
# File: src/keystone/shim_test.mak
# #############################################################################

# CERTIFIER_ROOT will be certifier-framework-for-confidential-computing/ dir
CERTIFIER_ROOT = ../..

ifndef SRC_DIR
SRC_DIR=..
endif
ifndef INC_DIR
INC_DIR=../../include
endif
ifndef OBJ_DIR
OBJ_DIR=.
endif
ifndef EXE_DIR
EXE_DIR=.
endif

#ifndef GOOGLE_INCLUDE
#GOOGLE_INCLUDE=/usr/local/include/google
#endif

ifndef LOCAL_LIB
    LOCAL_LIB=/usr/local/lib
endif

ifndef TARGET_MACHINE_TYPE
TARGET_MACHINE_TYPE= x64
endif

CP = $(CERTIFIER_ROOT)/certifier_service/certprotos

S= $(SRC_DIR)/keystone
O= $(OBJ_DIR)
I= $(INC_DIR)
CL=..

INCLUDE=-I $(I) -I/usr/local/opt/openssl@1.1/include/ -I .

CFLAGS = $(INCLUDE) -O3 -g -D X64 -std=c++11 -Wall -Wno-unused-variable -Wno-deprecated-declarations

ifdef ENABLE_SEV
CFLAGS += -D SEV_SNP
endif

CC=g++
LINK=g++

# Point this to the right place, if you have to, based on your machine's install:
# PROTO=/usr/local/bin/protoc
PROTO=protoc
AR=ar
#export LD_LIBRARY_PATH=/usr/local/lib
LDFLAGS= -L $(LOCAL_LIB) -lprotobuf -lgtest -lgflags -lpthread -L/usr/local/opt/openssl@1.1/lib/ -lcrypto -lssl

dobj = $(O)/certifier.pb.o $(O)/certifier.o $(O)/certifier_proofs.o        \
       $(O)/support.o $(O)/application_enclave.o $(O)/simulated_enclave.o  \
       $(O)/cc_helpers.o $(O)/cc_useful.o $(O)/keystone_shim.o $(O)/keystone_test.o

all:	$(EXE_DIR)/keystone_test.exe
clean:
	@echo "removing generated files"
	rm -rf $(S)/certifier.pb.cc $(S)/certifier.pb.h $(I)/certifier.pb.h
	@echo "removing object files"
	rm -rf $(O)/*.o
	@echo "removing generated emulated_keystone files"
	rm -rf ./emulated_keystone_*
	@echo "removing executable files"
	rm -rf $(CL)/keystone_test.exe

$(I)/certifier.pb.h: $(S)/certifier.pb.cc
$(S)/certifier.pb.cc: $(CP)/certifier.proto
	$(PROTO) --proto_path=$(CP) --cpp_out=$(@D) $<
	mv $(@D)/certifier.pb.h $(I)

$(EXE_DIR)/keystone_test.exe: $(dobj)
	@echo "\nlinking $@"
	$(LINK) $(dobj) $(LDFLAGS) -o $(@D)/$@

$(O)/keystone_test.o: $(S)/keystone_test.cc $(I)/certifier.pb.h $(I)/certifier.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -c -o $(@D)/$@ -c $<

$(O)/keystone_shim.o: $(S)/keystone_shim.cc $(I)/certifier.pb.h $(I)/certifier.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -c -o $(@D)/$@ -c $<

$(O)/certifier.pb.o: $(S)/certifier.pb.cc $(I)/certifier.pb.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -Wno-array-bounds -o $(@D)/$@ -c $<

$(O)/certifier.o: $(SRC_DIR)/certifier.cc $(I)/certifier.pb.h $(I)/certifier.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -c -o $(@D)/$@ -c $<

$(O)/certifier_proofs.o: $(SRC_DIR)/certifier_proofs.cc $(I)/certifier.pb.h $(I)/certifier.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -c -o $(@D)/$@ -c $<

$(O)/support.o: $(SRC_DIR)/support.cc $(I)/support.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -c -o $(@D)/$@ -c $<

$(O)/simulated_enclave.o: $(SRC_DIR)/simulated_enclave.cc $(I)/simulated_enclave.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -c -o $(@D)/$@ -c $<

$(O)/application_enclave.o: $(SRC_DIR)/application_enclave.cc $(I)/application_enclave.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -c -o $(@D)/$@ -c $<

$(O)/cc_helpers.o: $(SRC_DIR)/cc_helpers.cc $(I)/cc_helpers.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -c -o $(@D)/$@ -c $<

$(O)/cc_useful.o: $(SRC_DIR)/cc_useful.cc $(I)/cc_useful.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -c -o $(@D)/$@ -c $<

