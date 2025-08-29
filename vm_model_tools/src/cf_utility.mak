#    
#    File: cf_utility.mak

# CERTIFIER_ROOT will be certifier-framework-for-confidential-computing/ dir
ifndef CERTIFIER_ROOT
CERTIFIER_ROOT = ../..
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
S= $(CERTIFIER_ROOT)/src
O= $(OBJ_DIR)
US=.
I= $(CERTIFIER_ROOT)/include
INCLUDE= -I. -I$(I) -I/usr/local/opt/openssl@1.1/include/ -I$(S)/sev-snp/
CF_UTILITY_SRC= $(CERTIFIER_ROOT)/vm_model_tools/src

ENABLE_SEV=1

# Newer versions of protobuf require C++17 and dependancies on additional libraries.
# When this happens, everything must be compiles with C++17 and the linking is a
# little more complicated.  To use newer protobuf libraries, define NEWPROROBUF as
# is done below.  Comment it out for older protobuf usage.
NEWPROTOBUF=1

ifndef NEWPROTOBUF
CFLAGS_NOERROR=$(INCLUDE) -O3 -g -Wall -std=c++11 -Wno-unused-variable -D X64 -Wno-deprecated-declarations
CFLAGS1=$(INCLUDE) -O1 -g -Wall -std=c++11 -Wno-unused-variable -D X64 -Wno-deprecated-declarations
else
CFLAGS_NOERROR=$(INCLUDE) -O3 -g -Wall -std=c++17 -Wno-unused-variable -D X64 -Wno-deprecated-declarations
CFLAGS1=$(INCLUDE) -O1 -g -Wall -std=c++17 -Wno-unused-variable -D X64 -Wno-deprecated-declarations
endif
CFLAGS=$(CFLAGS_NOERROR) -Werror -fPIC

#ifdef ENABLE_SEV
CFLAGS  += -D SEV_SNP -D SEV_DUMMY_GUEST
#endif

CC=g++
LINK=g++
PROTO=protoc
AR=ar

ifdef NEWPROTOBUF
export LD_LIBRARY_PATH=/usr/local/lib
LDFLAGS= -L/usr/local/lib `pkg-config --cflags --libs protobuf` -lgtest -lgflags -lpthread -L/usr/local/opt/openssl@1.1/lib/ -lcrypto -lssl -luuid
else
export LD_LIBRARY_PATH=/usr/local/lib
LDFLAGS= -L/usr/local/lib -lprotobuf -lgtest -lgflags -lpthread -L/usr/local/opt/openssl@1.1/lib/ -lcrypto -lssl -luuid
endif

# Note:  You can omit all the files below in d_obj except $(O)/example_app.o,
#  if you link in the certifier library certifier.a.
dobj = $(O)/cf_utility.o $(O)/certifier.pb.o $(O)/certifier.o $(O)/certifier_proofs.o \
       $(O)/support.o $(O)/simulated_enclave.o $(O)/cc_helpers.o \
       $(O)/application_enclave.o $(O)/cc_useful.o $(O)/cryptstore.pb.o $(O)/cf_support.o

sobj = $(O)/cf_support_test.o $(O)/certifier.pb.o $(O)/certifier.o $(O)/certifier_proofs.o \
       $(O)/support.o $(O)/simulated_enclave.o $(O)/cc_helpers.o \
       $(O)/application_enclave.o $(O)/cc_useful.o $(O)/cryptstore.pb.o $(O)/cf_support.o

ifdef ENABLE_SEV
dobj += $(O)/sev_support.o $(O)/sev_report.o $(O)/sev_cert_table.o
sobj += $(O)/sev_support.o $(O)/sev_report.o $(O)/sev_cert_table.o
endif


all:	cf_utility.exe cf_support_test.exe
clean:
	@echo "removing generated files"
	rm -rf $(US)/certifier.pb.cc $(US)/certifier.pb.h $(I)/certifier.pb.h
	@echo "removing object files"
	rm -rf $(O)/*.o
	@echo "removing executable file"
	rm -rf $(EXE_DIR)/cf_utility.exe
	@echo "removing executable file"
	rm -rf $(EXE_DIR)/cf_support_test.exe

$(EXE_DIR)/cf_utility.exe: $(dobj)
	@echo "\nlinking executable $@"
	$(LINK) $(dobj) $(LDFLAGS) -o $(@D)/$@

$(EXE_DIR)/cf_support_test.exe: $(sobj)
	@echo "\nlinking executable $@"
	$(LINK) $(sobj) $(LDFLAGS) -o $(@D)/$@

$(I)/certifier.pb.h: $(US)/certifier.pb.cc
$(US)/certifier.pb.cc: $(CP)/certifier.proto
	$(PROTO) --proto_path=$(<D) --cpp_out=$(@D) $<
	mv $(@D)/certifier.pb.h $(I)

$(O)/cf_support_test.o: $(CF_UTILITY_SRC)/cf_support_test.cc $(I)/certifier.h $(US)/certifier.pb.cc $(CF_UTILITY_SRC)/cryptstore.pb.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(O)/cf_utility.o: $(CF_UTILITY_SRC)/cf_utility.cc $(I)/certifier.h $(US)/certifier.pb.cc $(CF_UTILITY_SRC)/cryptstore.pb.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(O)/cf_support.o: $(CF_UTILITY_SRC)/cf_support.cc $(I)/certifier.h $(US)/certifier.pb.cc $(CF_UTILITY_SRC)/cryptstore.pb.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(O)/certifier.pb.o: $(US)/certifier.pb.cc $(I)/certifier.pb.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS_NOERROR) -o $(@D)/$@ -c $<

$(O)/cryptstore.pb.o: $(CF_UTILITY_SRC)/cryptstore.pb.cc
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS_NOERROR) -o $(O)/cryptstore.pb.o -c $(CF_UTILITY_SRC)/cryptstore.pb.cc

$(CF_UTILITY_SRC)/cryptstore.pb.h: $(CF_UTILITY_SRC)/cryptstore.proto
	$(PROTO) --proto_path=$(CF_UTILITY_SRC) --cpp_out=. $(CF_UTILITY_SRC)/cryptstore.proto

$(CF_UTILITY_SRC)/cryptstore.pb.cc: $(CF_UTILITY_SRC)/cryptstore.pb.h

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

$(O)/certifier_algorithms.o: $(S)/certifier_algorithms.cc
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

ifdef ENABLE_SEV
$(O)/sev_support.o: $(S)/sev-snp/sev_support.cc
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(O)/sev_support.o -c $(S)/sev-snp/sev_support.cc

$(O)/sev_report.o: $(S)/sev-snp/sev_report.cc
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(O)/sev_report.o -c $(S)/sev-snp/sev_report.cc

$(O)/sev_cert_table.o: $(S)/sev-snp/sev_cert_table.cc
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(O)/sev_cert_table.o -c $(S)/sev-snp/sev_cert_table.cc
endif
