# #############################################################################
# File: src/keystone/shim_test.mak
# #############################################################################

# CERTIFIER_ROOT will be certifier-framework-for-confidential-computing/ dir
#ifndef CERTIFIER_ROOT
CERTIFIER_ROOT = ../..
#endif

ifndef SRC_DIR
SRC_DIR=..
endif
ifndef INC_DIR
INC_DIR=$(CERTIFIER_ROOT)/include
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
SE= $(SRC_DIR)/simulated-enclave
AE=$(SRC_DIR)/application-enclave
T=$(SRC_DIR)/tpm2
CL=..

INCLUDE = -I$(INC_DIR) -I/usr/local/opt/openssl@1.1/include/ -I. -I$(T)

NEWPROTOBUF=1
TPM=1
ifndef NEWPROTOBUF
CFLAGS = $(INCLUDE) -g -Wall -std=c++11 -Wno-unused-variable -D X64 -Wno-deprecated-declarations
else
CFLAGS = $(INCLUDE) -g -Wall -std=c++17 -Wno-unused-variable -D X64 -Wno-deprecated-declarations
endif

ifdef ENABLE_SEV
CFLAGS += -D SEV_SNP
endif
CFLAGS += -Wno-error=strict-aliasing

CC=g++
LINK=g++

# Point this to the right place, if you have to, based on your machine's install:
# PROTO=/usr/local/bin/protoc
PROTO=protoc
AR=ar

ifndef NEWPROTOBUF
#export LD_LIBRARY_PATH=/usr/local/lib
LDFLAGS = -L $(LOCAL_LIB) -lprotobuf -lgtest -lgflags -lpthread -L/usr/local/opt/openssl@1.1/lib/ -lcrypto -lssl -luuid
LDFLAGS_SWIGPYTEST = -L $(LOCAL_LIB) -l protobuf
else
LDFLAGS = -L $(LOCAL_LIB) `pkg-config --cflags --libs protobuf` -lgtest -lgflags -lpthread -L/usr/local/opt/openssl@1.1/lib/ -lcrypto -lssl -luuid
LDFLAGS_SWIGPYTEST = -L $(LOCAL_LIB) `pkg-config --cflags --libs protobuf`
endif

dobj = $(O)/certifier.pb.o $(O)/certifier.o $(O)/certifier_proofs.o        \
       $(O)/support.o $(O)/application_enclave.o $(O)/simulated_enclave.o  \
       $(O)/cc_helpers.o $(O)/cc_useful.o $(O)/keystone_shim.o $(O)/keystone_test.o
tpm_obj = $(O)/tpm2.pb.o $(O)/tpm2_lib.o $(O)/openssl_help.o \
        $(O)/convert.o $(O)/tpm2_support.o
dobj += $(tpm_obj)

all:	$(EXE_DIR)/keystone_test.exe
clean:
	@echo "removing generated files"
	rm -rf $(S)/certifier.pb.cc $(S)/certifier.pb.h $(I)/certifier.pb.h || true
	@echo "removing object files"
	rm -rf $(O)/*.o || true
	@echo "removing generated emulated_keystone files"
	rm -rf ./emulated_keystone_* || true
	@echo "removing executable files"
	rm -rf $(CL)/keystone_test.exe || true

$(I)/certifier.pb.h $(S)/certifier.pb.cc: $(CP)/certifier.proto
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

$(O)/certifier.o: $(SRC_DIR)/certifier.cc $(I)/certifier.pb.h $(I)/certifier.h $(T)/tpm2.pb.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -c -o $(@D)/$@ -c $<

$(O)/certifier_proofs.o: $(SRC_DIR)/certifier_proofs.cc $(I)/certifier.pb.h $(I)/certifier.h $(T)/tpm2.pb.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -c -o $(@D)/$@ -c $<

$(O)/support.o: $(SRC_DIR)/support.cc $(I)/support.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -c -o $(@D)/$@ -c $<

$(O)/simulated_enclave.o: $(SE)/simulated_enclave.cc $(I)/simulated_enclave.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -c -o $(@D)/$@ -c $<

$(O)/application_enclave.o: $(AE)/application_enclave.cc $(I)/application_enclave.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -c -o $(@D)/$@ -c $<

$(O)/cc_helpers.o: $(SRC_DIR)/cc_helpers.cc $(I)/cc_helpers.h $(T)/tpm2.pb.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -c -o $(@D)/$@ -c $<

$(O)/cc_useful.o: $(SRC_DIR)/cc_useful.cc $(I)/cc_useful.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -c -o $(@D)/$@ -c $<

$(O)/tpm2_lib.o: $(T)/tpm2_lib.cc
	@echo "compiling tpm2_lib.cc"
	$(CC) $(CFLAGS) -c -o $(O)/tpm2_lib.o $(T)/tpm2_lib.cc

$(T)/tpm2.pb.cc $(T)/tpm2.pb.h: $(T)/tpm2.proto
	@echo "creating protobuf files"
	$(PROTO) -I=$(T) --cpp_out=$(T) $(T)/tpm2.proto

$(O)/convert.o: $(T)/convert.cc
	@echo "compiling convert.cc"
	$(CC) $(CFLAGS) -c -o $(O)/convert.o $(T)/convert.cc

$(O)/openssl_help.o: $(T)/openssl_help.cc
	@echo "compiling openssl_help.cc"
	$(CC) $(CFLAGS) -c -o $(O)/openssl_help.o $(T)/openssl_help.cc

$(O)/tpm2_support.o: $(T)/tpm2_support.cc $(T)/tpm2.pb.cc $(I)/certifier.pb.h
	@echo "compiling tpm2_support.cc"
	$(CC) $(CFLAGS) -c -o $(O)/tpm2_support.o $(T)/tpm2_support.cc

$(O)/tpm2.pb.o: $(T)/tpm2.pb.cc $(T)/tpm2.pb.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

