#
#    File: example_app.mak


# CERTIFIER_ROOT will be certifier-framework-for-confidential-computing/ dir
CERTIFIER_ROOT = ../..

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
INCLUDE= -I$(I) -I/usr/local/opt/openssl@1.1/include/ -I$(S)/sev-snp/

# Compilation of protobuf files could run into some errors, so avoid using
# # -Werror for those targets
CFLAGS_NOERROR=$(INCLUDE) -O3 -g -Wall -std=c++11 -Wno-unused-variable -D X64 -Wno-deprecated-declarations
CFLAGS = $(CFLAGS_NOERROR) -Werror
CFLAGS1=$(INCLUDE) -O1 -g -Wall -std=c++11 -Wno-unused-variable -D X64 -Wno-deprecated-declarations
CC=g++
LINK=g++
PROTO=protoc
AR=ar
#export LD_LIBRARY_PATH=/usr/local/lib
LDFLAGS= -L $(LOCAL_LIB) -lprotobuf -lgtest -lgflags -lpthread -L/usr/local/opt/openssl@1.1/lib/ -lcrypto -lssl

# Note:  You can omit all the files below in d_obj except $(O)/example_app.o,
#  if you link in the certifier library certifier.a.
client_dobj = $(O)/multidomain_client_app.o $(O)/certifier.pb.o $(O)/certifier.o $(O)/certifier_proofs.o \
       $(O)/support.o $(O)/simulated_enclave.o $(O)/application_enclave.o $(O)/cc_helpers.o \
       $(O)/cc_useful.o
server_dobj = $(O)/multidomain_server_app.o $(O)/certifier.pb.o $(O)/certifier.o $(O)/certifier_proofs.o \
       $(O)/support.o $(O)/simulated_enclave.o $(O)/application_enclave.o $(O)/cc_helpers.o \
       $(O)/cc_useful.o

all:	multidomain_server_app.exe multidomain_client_app.exe
clean:
	@echo "removing generated files"
	rm -rf $(US)/certifier.pb.cc $(US)/certifier.pb.h $(I)/certifier.pb.h
	@echo "removing object files"
	rm -rf $(O)/*.o
	@echo "removing executable file"
	rm -rf $(EXE_DIR)/example_app.exe

$(EXE_DIR)/multidomain_client_app.exe: $(client_dobj)
	@echo "\nlinking executable $@"
	$(LINK) $(client_dobj) $(LDFLAGS) -o $(@D)/$@

$(EXE_DIR)/multidomain_server_app.exe: $(server_dobj)
	@echo "\nlinking executable $@"
	$(LINK) $(server_dobj) $(LDFLAGS) -o $(@D)/$@

$(I)/certifier.pb.h: $(US)/certifier.pb.cc
$(US)/certifier.pb.cc: $(CP)/certifier.proto
	$(PROTO) --proto_path=$(<D) --cpp_out=$(@D) $<
	mv $(@D)/certifier.pb.h $(I)

$(O)/certifier.pb.o: $(US)/certifier.pb.cc $(I)/certifier.pb.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS_NOERROR) -o $(@D)/$@ -c $<

$(O)/multidomain_server_app.o: $(US)/multidomain_server_app.cc $(I)/certifier.h $(US)/certifier.pb.cc
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(O)/multidomain_client_app.o: $(US)/multidomain_client_app.cc $(I)/certifier.h $(US)/certifier.pb.cc
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
