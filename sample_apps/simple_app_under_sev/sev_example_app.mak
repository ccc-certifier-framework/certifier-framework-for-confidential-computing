#    
#    File: sev_example_app.mak

# CERTIFIER_ROOT will be certifier-framework-for-confidential-computing/ dir
CERTIFIER_ROOT = ../..

ifndef SRC_DIR
SRC_DIR=../..
endif
ifndef OBJ_DIR
OBJ_DIR=.
endif
ifndef EXE_DIR
EXE_DIR=.
endif
#ifndef GOOGLE_INCLUDE
#GOOGLE_INCLUDE=/usr/local/include/g
#endif
ifndef LOCAL_LIB
LOCAL_LIB=/usr/local/lib
endif
ifndef TARGET_MACHINE_TYPE
TARGET_MACHINE_TYPE= x64
endif

CP = $(CERTIFIER_ROOT)/certifier_service/certprotos

S= $(SRC_DIR)/src
O= $(OBJ_DIR)
US=.
I= $(SRC_DIR)/include
INCLUDE=-I. -I $(I) -I/usr/local/opt/openssl@1.1/include/ -I $(S)/sev-snp
COMMON_SRC = $(CERTIFIER_ROOT)/sample_apps/common

# Inherit -D<flags> provided externally
CFLAGS := $(CFLAGS)
CFLAGS += $(INCLUDE) -O3 -g -Wall -std=c++11 -Wno-unused-variable -D X64 -D SEV_SNP -Wno-deprecated-declarations
CFLAGS += -DSEV_SIMPLE_APP

CC=g++
LINK=g++
#PROTO=/usr/local/bin/protoc
PROTO=protoc
AR=ar
#export LD_LIBRARY_PATH=/usr/local/lib
LDFLAGS= -L $(LOCAL_LIB) -lprotobuf -lgtest -lgflags -lpthread -L/usr/local/opt/openssl@1.1/lib/ -lcrypto -lssl -luuid

# Note:  You can omit all the files below in d_obj except $(O)/example_app.o,
#  if you link in the certifier library certifier.a.
dobj = $(O)/sev_example_app.o $(O)/certifier.pb.o $(O)/certifier.o \
       $(O)/certifier_proofs.o $(O)/support.o $(O)/application_enclave.o \
       $(O)/simulated_enclave.o  $(O)/sev_support.o $(O)/sev_cert_table.o \
       $(O)/sev_report.o $(O)/cc_helpers.o $(O)/cc_useful.o

all:	sev_example_app.exe
clean:
	@echo "removing generated files"
	rm -rf $(US)/certifier.pb.cc $(US)/certifier.pb.h $(I)/certifier.pb.h
	@echo "removing object files"
	rm -rf $(O)/*.o
	@echo "removing executable file"
	rm -rf $(EXE_DIR)/sev_example_app.exe

$(EXE_DIR)/sev_example_app.exe: $(dobj)
	@echo "\nlinking executable $@"
	$(LINK) $(dobj) $(LDFLAGS) -o $(@D)/$@

$(I)/certifier.pb.h: $(US)/certifier.pb.cc
$(US)/certifier.pb.cc: $(CP)/certifier.proto
	$(PROTO) --proto_path=$(<D) --cpp_out=$(@D) $<
	mv $(@D)/certifier.pb.h $(I)

$(O)/certifier.pb.o: $(US)/certifier.pb.cc $(I)/certifier.pb.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -Wno-array-bounds -o $(@D)/$@ -c $<

$(O)/sev_example_app.o: $(COMMON_SRC)/example_app.cc $(I)/certifier.h $(US)/certifier.pb.cc
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

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

$(O)/cc_helpers.o: $(S)/cc_helpers.cc $(I)/certifier.h $(US)/certifier.pb.cc
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(O)/cc_useful.o: $(S)/cc_useful.cc $(I)/cc_useful.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

SEV_S=$(S)/sev-snp

$(O)/sev_support.o: $(SEV_S)/sev_support.cc \
                    $(I)/certifier.h $(I)/support.h $(SEV_S)/attestation.h \
                    $(SEV_S)/sev_guest.h $(SEV_S)/snp_derive_key.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(O)/sev_cert_table.o: $(SEV_S)/sev_cert_table.cc \
                    $(SEV_S)/sev_cert_table.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(O)/sev_report.o: $(SEV_S)/sev_report.cc \
                   $(I)/certifier.h $(I)/support.h $(SEV_S)/attestation.h \
                   $(SEV_S)/sev_guest.h $(SEV_S)/snp_derive_key.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<
