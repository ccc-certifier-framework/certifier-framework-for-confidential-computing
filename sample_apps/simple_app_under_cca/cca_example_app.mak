#
#    File: cca_example_app.mak


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

# AMD CCA-based sample program needs ISLET SDK
#
CERT_ROOT = ../..
ISLET_PATH = $(CERT_ROOT)/third_party/islet
ISLET_INCLUDE= -I$(ISLET_PATH)/include
ISLET_LDFLAGS= -L$(ISLET_PATH)/lib -lislet_sdk

S= $(SRC_DIR)/src
O= $(OBJ_DIR)
CCAS=$(S)/cca
US=.
I= $(SRC_DIR)/include
INCLUDE= $(ISLET_INCLUDE) -I$(I) -I/usr/local/opt/openssl@1.1/include/ -I$(S)/sev-snp/ -I$(CCAS)

# Compilation of protobuf files could run into some errors, so avoid using
# # -Werror for those targets
CFLAGS_NOERROR=$(INCLUDE) -O3 -g -Wall -std=c++11 -Wno-unused-variable -D X64 -Wno-deprecated-declarations -D CCA_CERTIFIER
CFLAGS = $(CFLAGS_NOERROR) -Werror
CFLAGS1=$(INCLUDE) -O1 -g -Wall -std=c++11 -Wno-unused-variable -D X64 -Wno-deprecated-declarations
CC=g++
LINK=g++
#PROTO=/usr/local/bin/protoc
PROTO=protoc
AR=ar
#export LD_LIBRARY_PATH=/usr/local/lib
LDFLAGS= $(ISLET_LDFLAGS) -L $(LOCAL_LIB) -lprotobuf -lgtest -lgflags -lpthread -L/usr/local/opt/openssl@1.1/lib/ -lcrypto -lssl

# Note:  You can omit all the files below in d_obj except $(O)/example_app.o,
#  if you link in the certifier library certifier.a.
dobj=	$(O)/cca_example_app.o $(O)/certifier.pb.o $(O)/certifier.o $(O)/certifier_proofs.o \
      $(O)/support.o $(O)/simulated_enclave.o $(O)/application_enclave.o $(O)/cc_helpers.o \
      $(O)/cc_useful.o $(O)/cca_shim.o

all:	cca_example_app.exe
clean:
	@echo "removing generated files"
	rm -rf $(I)/certifier.pb.h $(US)/certifier.pb.cc
	@echo "removing object files"
	rm -rf $(O)/*.o
	@echo "removing executable file"
	rm -rf $(EXE_DIR)/cca_example_app.exe

cca_example_app.exe: $(dobj)
	@echo "linking executable files"
	$(LINK) -o $(EXE_DIR)/cca_example_app.exe $(dobj) $(LDFLAGS)

$(US)/certifier.pb.cc: $(S)/certifier.proto
	$(PROTO) --proto_path=$(S) --cpp_out=$(US) $(S)/certifier.proto
	mv $(US)/certifier.pb.h $(I)

$(I)/certifier.pb.h: $(US)/certifier.pb.cc

$(O)/certifier.pb.o: $(US)/certifier.pb.cc $(I)/certifier.pb.h
	@echo "compiling certifier.pb.cc"
	$(CC) $(CFLAGS_NOERROR) -c -o $(O)/certifier.pb.o $(US)/certifier.pb.cc

$(O)/cca_example_app.o: $(US)/cca_example_app.cc $(I)/certifier.h $(US)/certifier.pb.cc
	@echo "compiling cca_example_app.cc"
	$(CC) $(CFLAGS) -c -o $(O)/cca_example_app.o $(US)/cca_example_app.cc

$(O)/cca_shim.o: $(CCAS)/cca_shim.cc $(I)/certifier.h $(US)/certifier.pb.cc
	@echo "compiling cca_shim.cc"
	$(CC) $(CFLAGS) -c -o $(O)/cca_shim.o $(CCAS)/cca_shim.cc

$(O)/certifier.o: $(S)/certifier.cc $(I)/certifier.pb.h $(I)/certifier.h
	@echo "compiling certifier.cc"
	$(CC) $(CFLAGS) -c -o $(O)/certifier.o $(S)/certifier.cc

$(O)/certifier_proofs.o: $(S)/certifier_proofs.cc $(I)/certifier.pb.h $(I)/certifier.h
	@echo "compiling certifier_proofs.cc"
	$(CC) $(CFLAGS) -c -o $(O)/certifier_proofs.o $(S)/certifier_proofs.cc

$(O)/support.o: $(S)/support.cc $(I)/support.h
	@echo "compiling support.cc"
	$(CC) $(CFLAGS) -c -o $(O)/support.o $(S)/support.cc

$(O)/simulated_enclave.o: $(S)/simulated_enclave.cc $(I)/simulated_enclave.h
	@echo "compiling simulated_enclave.cc"
	$(CC) $(CFLAGS) -c -o $(O)/simulated_enclave.o $(S)/simulated_enclave.cc

$(O)/application_enclave.o: $(S)/application_enclave.cc $(I)/application_enclave.h
	@echo "compiling application_enclave.cc"
	$(CC) $(CFLAGS) -c -o $(O)/application_enclave.o $(S)/application_enclave.cc

$(O)/cc_helpers.o: $(S)/cc_helpers.cc $(I)/certifier.h $(US)/certifier.pb.cc
	@echo "compiling cc_helpers.cc"
	$(CC) $(CFLAGS) -c -o $(O)/cc_helpers.o $(S)/cc_helpers.cc

$(O)/cc_useful.o: $(S)/cc_useful.cc $(I)/cc_useful.h
	@echo "compiling cc_useful.cc"
	$(CC) $(CFLAGS) -c -o $(O)/cc_useful.o $(S)/cc_useful.cc
