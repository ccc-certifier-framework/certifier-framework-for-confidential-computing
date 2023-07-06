#    
#    File: certifier.mak

ENABLE_SEV=1

# CERTIFIER_ROOT will be certifier-framework-for-confidential-computing/ dir
CERTIFIER_ROOT = ..

ifndef SRC_DIR
SRC_DIR=.
endif
ifndef INC_DIR
INC_DIR=../include
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

LOCAL_LIB=/usr/local/lib

ifndef TARGET_MACHINE_TYPE
TARGET_MACHINE_TYPE= x64
endif

CP = $(CERTIFIER_ROOT)/certifier_service/certprotos

S= $(SRC_DIR)
O= $(OBJ_DIR)
I= $(INC_DIR)
CL=..

INCLUDE=-I $(I) -I/usr/local/opt/openssl@1.1/include/ -I $(S)/sev-snp

CFLAGS_COMMON = $(INCLUDE) -g -Wall -std=c++11 -Wno-unused-variable -D X64 -Wno-deprecated-declarations

CFLAGS  = $(CFLAGS_COMMON) -O3

ifdef ENABLE_SEV
CFLAGS  += -D SEV_SNP
endif

CC=g++
LINK=g++

# Point this to the right place, if you have to, based on your machine's install:
# PROTO=/usr/local/bin/protoc
PROTO=protoc
AR=ar
#export LD_LIBRARY_PATH=/usr/local/lib
LDFLAGS= -L $(LOCAL_LIB) -lprotobuf -lgtest -lgflags -lpthread -L/usr/local/opt/openssl@1.1/lib/ -lcrypto -lssl

# ----------------------------------------------------------------------
# Define list of objects for common case which will be extended for
# ENABLE_SEV build mode.
# ----------------------------------------------------------------------
dobj = $(O)/certifier.pb.o $(O)/certifier.o $(O)/certifier_proofs.o        \
       $(O)/support.o $(O)/application_enclave.o $(O)/simulated_enclave.o  \
       $(O)/cc_helpers.o $(O)/cc_useful.o $(O)/keystone_shim.o

ifdef ENABLE_SEV
dobj += $(O)/sev_support.o $(O)/sev_report.o
endif

all:	$(CL)/certifier.a
clean:
	@echo "removing generated files"
	rm -rf $(S)/certifier.pb.h $(I)/certifier.pb.h $(S)/certifier.pb.cc
	@echo "removing object files"
	rm -rf $(O)/*.o
	@echo "removing executable files"
	rm -rf $(CL)/certifier.a

$(CL)/certifier.a: $(dobj)
	@echo "linking certifier library"
	$(AR) rcs $(CL)/certifier.a $(dobj)

$(I)/certifier.pb.h: $(S)/certifier.pb.cc
$(S)/certifier.pb.cc: $(CP)/certifier.proto
	$(PROTO) --cpp_out=$(S) --proto_path $(<D) $<
	mv $(S)/certifier.pb.h $(I)

$(O)/certifier_tests.o: $(S)/certifier_tests.cc $(I)/certifier.pb.h $(I)/certifier.h $(S)/test_support.cc
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(O)/certifier.pb.o: $(S)/certifier.pb.cc $(I)/certifier.pb.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -Wno-array-bounds -o $(@D)/$@ -c $<

$(O)/certifier.o: $(S)/certifier.cc $(I)/certifier.pb.h $(I)/certifier.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(O)/certifier_proofs.o: $(S)/certifier_proofs.cc $(I)/certifier.pb.h $(I)/certifier.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(O)/support.o: $(S)/support.cc $(I)/support.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(O)/simulated_enclave.o: $(S)/simulated_enclave.cc $(I)/simulated_enclave.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(O)/application_enclave.o: $(S)/application_enclave.cc $(I)/application_enclave.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(O)/cc_helpers.o: $(S)/cc_helpers.cc $(I)/cc_helpers.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(O)/cc_useful.o: $(S)/cc_useful.cc $(I)/cc_useful.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(O)/keystone_shim.o: $(S)/keystone/keystone_shim.cc $(S)/keystone/keystone_api.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

ifdef ENABLE_SEV
SEV_S=$(S)/sev-snp

$(O)/sev_support.o: $(SEV_S)/sev_support.cc \
                    $(I)/certifier.h $(I)/support.h $(SEV_S)/attestation.h  \
                    $(SEV_S)/sev_guest.h  $(SEV_S)/snp_derive_key.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(O)/sev_report.o: $(SEV_S)/sev_report.cc \
                   $(I)/certifier.h $(I)/support.h $(SEV_S)/attestation.h  \
                   $(SEV_S)/sev_guest.h  $(SEV_S)/snp_derive_key.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<
endif
