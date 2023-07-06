#    
#    File: cert_utility.mak

# CERTIFIER_ROOT will be certifier-framework-for-confidential-computing/ dir
CERTIFIER_ROOT = ..

ifndef SRC_DIR
SRC_DIR=$(CERTIFIER_ROOT)/src
endif
ifndef OBJ_DIR
OBJ_DIR=.
endif
ifndef EXE_DIR
EXE_DIR=.
endif
ifndef INC_DIR
INC_DIR=../include
endif

#ifndef GOOGLE_INCLUDE
#GOOGLE_INCLUDE=/usr/local/include/g
#endif

# Allows user to over-ride libs path externally depending on machine's install
ifndef LOCAL_LIB
LOCAL_LIB=/usr/local/lib
endif

ifndef TARGET_MACHINE_TYPE
TARGET_MACHINE_TYPE= x64
endif

CP = $(CERTIFIER_ROOT)/certifier_service/certprotos

S= $(SRC_DIR)
O= $(OBJ_DIR)
I= $(INC_DIR)
US= .
INCLUDE= -I$(I) -I/usr/local/opt/openssl@1.1/include/ -I$(S)/sev-snp/

# Compilation of protobuf files could run into some errors, so avoid using
# -Werror for those targets
CFLAGS_NOERROR = $(INCLUDE) -O3 -g -Wall -std=c++11 -Wno-unused-variable -D X64 -Wno-deprecated -Wno-deprecated-declarations
CFLAGS = $(CFLAGS_NOERROR) -Werror

#For MAC, -D MACOS should be included
CFLAGS1= $(INCLUDE) -O1 -g -Wall -std=c++11 -Wno-unused-variable -D X64 -Wno-deprecated -Wno-deprecated-declarations
CC=g++
LINK=g++
# PROTO=/usr/local/bin/protoc
# Point this to the right place, if you have to. I had to do the above on my machine.
PROTO=protoc
AR=ar
#export LD_LIBRARY_PATH=/usr/local/lib
LDFLAGS= -L $(LOCAL_LIB) -lprotobuf -lgtest -lgflags -lpthread -L/usr/local/opt/openssl@1.1/lib/ -lcrypto -lssl

common_objs = $(O)/certifier.pb.o $(O)/support.o $(O)/certifier.o \
              $(O)/certifier_proofs.o $(O)/simulated_enclave.o \
              $(O)/application_enclave.o

dobj =	$(O)/cert_utility.o $(common_objs)

key_dobj = $(O)/key_utility.o $(common_objs)

mobj = $(O)/measurement_init.o $(common_objs)

all:	cert_utility.exe measurement_init.exe key_utility.exe
clean:
	@echo "removing object and generated files"
	rm -rf $(O)/*.o $(US)/certifier.pb.cc $(US)/certifier.pb.h $(I)/certifier.pb.h
	@echo "removing executable file"
	rm -rf $(EXE_DIR)/cert_utility.exe

cert_utility.exe: $(dobj) 
	@echo "\nlinking executable $@"
	$(LINK) $(dobj) $(LDFLAGS) -o $(EXE_DIR)/$@

key_utility.exe: $(key_dobj)
	@echo "\nlinking executable $@"
	$(LINK) $(key_dobj) $(LDFLAGS) -o $(EXE_DIR)/$@

measurement_init.exe: $(mobj)
	@echo "\nlinking executable $@"
	$(LINK) $(mobj) $(LDFLAGS) -o $(EXE_DIR)/$@

$(O)/measurement_init.o: $(US)/measurement_init.cc
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(O)/cert_utility.o: $(US)/cert_utility.cc $(I)/support.h $(I)/certifier.pb.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(O)/key_utility.o: $(US)/key_utility.cc $(I)/support.h $(I)/certifier.pb.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(I)/certifier.pb.h: $(US)/certifier.pb.cc
$(US)/certifier.pb.cc: $(CP)/certifier.proto
	$(PROTO) --cpp_out=$(US) --proto_path $(<D) $<
	mv $(@D)/certifier.pb.h $(I)

$(O)/certifier.pb.o: $(US)/certifier.pb.cc $(I)/certifier.pb.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS_NOERROR) -Wno-array-bounds -o $(@D)/$@ -c $<

$(O)/support.o: $(S)/support.cc $(I)/support.h $(I)/certifier.pb.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(O)/certifier.o: $(S)/certifier.cc $(I)/certifier.pb.h $(I)/certifier.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(O)/certifier_proofs.o: $(S)/certifier_proofs.cc $(I)/certifier.pb.h $(I)/certifier.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(O)/simulated_enclave.o: $(S)/simulated_enclave.cc $(I)/simulated_enclave.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(O)/application_enclave.o: $(S)/application_enclave.cc $(I)/application_enclave.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<
