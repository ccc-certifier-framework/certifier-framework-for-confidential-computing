#
#    File: keystone_example_app.mak

# CERTIFIER_ROOT will be certifier-framework-for-confidential-computing/ dir
ifndef CERTIFIER_ROOT
CERTIFIER_ROOT = ../..
endif

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

# Newer versions of protobuf require C++17 and dependancies on additional libraries.
# When this happens, everything must be compiles with C++17 and the linking is a
# little more complicated.  To use newer protobuf libraries, define NEWPROROBUF as
# is done below.  Comment it out for older protobuf usage.
NEWPROTOBUF=1

CP = $(CERTIFIER_ROOT)/certifier_service/certprotos
S= $(SRC_DIR)/src
O= $(OBJ_DIR)
KS=$(S)/keystone
US=.
I= $(SRC_DIR)/include
INCLUDE= -I. -I$(I) -I/usr/local/opt/openssl@1.1/include/ -I$(S)/sev-snp/ -I$(KS)
COMMON_SRC = $(CERTIFIER_ROOT)/sample_apps/common
SE = $(S)/simulated-enclave

# Compilation of protobuf files could run into some errors, so avoid using
# # -Werror for those targets
ifndef NEWPROTOBUF
CFLAGS_NOERROR=$(INCLUDE) -O3 -g -Wall -std=c++11 -Wno-unused-variable -D X64 -Wno-deprecated-declarations -D KEYSTONE_CERTIFIER
else
CFLAGS_NOERROR=$(INCLUDE) -O3 -g -Wall -std=c++17 -Wno-unused-variable -D X64 -Wno-deprecated-declarations -D KEYSTONE_CERTIFIER
endif
CFLAGS = $(CFLAGS_NOERROR) -Werror -DKEYSTONE_SIMPLE_APP

CC=g++
LINK=g++

#PROTO=/usr/local/bin/protoc
PROTO=protoc
AR=ar

ifndef NEWPROTOBUF
#export LD_LIBRARY_PATH=/usr/local/lib
LDFLAGS= -L $(LOCAL_LIB) -lprotobuf -lgtest -lgflags -lpthread -L/usr/local/opt/openssl@1.1/lib/ -lcrypto -lssl
else
export LD_LIBRARY_PATH=/usr/local/lib
LDFLAGS= -L $(LOCAL_LIB) `pkg-config --cflags --libs protobuf` -lgtest -lgflags -lpthread -L/usr/local/opt/openssl@1.1/lib/ -lcrypto -lssl
endif

# Note:  You can omit all the files below in d_obj except $(O)/example_app.o,
#  if you link in the certifier library certifier.a.
dobj = $(O)/keystone_example_app.o $(O)/certifier.pb.o $(O)/certifier.o \
       $(O)/certifier_proofs.o $(O)/support.o $(O)/simulated_enclave.o \
       $(O)/application_enclave.o $(O)/cc_helpers.o \
       $(O)/cc_useful.o $(O)/keystone_shim.o

all:	keystone_example_app.exe
clean:
	@echo "removing generated files"
	rm -rf $(US)/certifier.pb.cc $(US)/certifier.pb.h $(I)/certifier.pb.h
	@echo "removing object files"
	rm -rf $(O)/*.o
	@echo "removing executable file"
	rm -rf $(EXE_DIR)/keystone_example_app.exe

$(EXE_DIR)/keystone_example_app.exe: $(dobj) 
	@echo "\nlinking executable $@"
	$(LINK) $(dobj) $(LDFLAGS) -o $(@D)/$@

$(I)/certifier.pb.h: $(US)/certifier.pb.cc
$(US)/certifier.pb.cc: $(CP)/certifier.proto
	$(PROTO) --proto_path=$(<D) --cpp_out=$(@D) $<
	mv $(@D)/certifier.pb.h $(I)

$(O)/certifier.pb.o: $(US)/certifier.pb.cc $(I)/certifier.pb.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS_NOERROR) -o $(@D)/$@ -c $<

$(O)/keystone_example_app.o: $(COMMON_SRC)/example_app.cc $(I)/certifier.h $(US)/certifier.pb.cc
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(O)/keystone_shim.o: $(KS)/keystone_shim.cc $(I)/certifier.h $(US)/certifier.pb.cc
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

$(O)/simulated_enclave.o: $(SE)/simulated_enclave.cc $(I)/simulated_enclave.h
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
