#    
#    File: app_service.mak

# CERTIFIER_ROOT will be certifier-framework-for-confidential-computing/ dir
CERTIFIER_ROOT = ..

ifndef SRC_DIR
SRC_DIR=..
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

LIBSRC= $(SRC_DIR)/src
S= $(SRC_DIR)/application_service
US= $(S)
O= $(OBJ_DIR)
I= $(SRC_DIR)/include
INCLUDE= -I$(I) -I$(LIBSRC)/sev-snp -I/usr/local/opt/openssl@1.1/include/

CFLAGS=$(INCLUDE) -O3 -g -Wall -std=c++11 -Wno-unused-variable -D X64 -D DEBUG -Wno-deprecated-declarations
CC=g++
LINK=g++
# PROTO=/usr/local/bin/protoc
# Point this to the right place, if you have to.
# I had to do the above on my machine.
PROTO=protoc
AR=ar
#export LD_LIBRARY_PATH=/usr/local/lib
LDFLAGS= -L $(LOCAL_LIB) -lprotobuf -lgtest -lgflags -lpthread -L/usr/local/opt/openssl@1.1/lib/ -lcrypto -lssl -luuid

dobj = $(O)/app_service.o $(O)/certifier.pb.o $(O)/certifier.o \
       $(O)/certifier_proofs.o $(O)/support.o $(O)/simulated_enclave.o \
       $(O)/application_enclave.o $(O)/cc_helpers.o $(O)/cc_useful.o \
       $(O)/sev_support.o $(O)/sev_cert_table.o $(O)/sev_report.o

user_dobj = $(O)/test_user.o $(O)/certifier.pb.o $(O)/certifier.o \
            $(O)/certifier_proofs.o $(O)/support.o $(O)/simulated_enclave.o \
            $(O)/application_enclave.o $(O)/cc_helpers.o $(O)/cc_useful.o

send_req_dobj = $(O)/send_request.o $(O)/certifier.pb.o $(O)/certifier.o \
                $(O)/support.o $(O)/application_enclave.o \
                $(O)/simulated_enclave.o $(O)/certifier_proofs.o

all:	app_service.exe hello_world.exe send_request.exe test_user.exe

clean:
	@echo "removing generated files"
	rm -rf $(S)/certifier.pb.cc $(S)/certifier.pb.h $(I)/certifier.pb.h
	@echo "removing object files"
	rm -rf $(O)/*.o
	@echo "removing executable file"
	rm -rf $(EXE_DIR)/app_service.exe

hello_world.exe: $(S)/hello_world.cc
	@echo "compiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(EXE_DIR)/send_request.exe: $(send_req_dobj)
	@echo "linking executable $@"
	$(LINK) $(send_req_dobj) $(LDFLAGS) -o $(@D)/$@

$(O)/send_request.o: $(S)/send_request.cc
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(EXE_DIR)/app_service.exe: $(dobj)
	@echo "linking executable $@"
	$(LINK) $(dobj) $(LDFLAGS) -o $(@D)/$@

$(EXE_DIR)/test_user.exe: $(user_dobj)
	@echo "linking executable $@"
	$(LINK) $(user_dobj) $(LDFLAGS) -o $(@D)/$@

$(I)/certifier.pb.h: $(US)/certifier.pb.cc
$(US)/certifier.pb.cc: $(CP)/certifier.proto
	$(PROTO) --proto_path=$(<D) --cpp_out=$(@D) $<
	mv $(@D)/certifier.pb.h $(I)

$(O)/app_service.o: $(S)/app_service.cc $(S)/certifier.pb.cc
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(O)/certifier.pb.o: $(US)/certifier.pb.cc $(I)/certifier.pb.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(O)/certifier.o: $(LIBSRC)/certifier.cc $(I)/certifier.pb.h $(I)/certifier.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(O)/certifier_proofs.o: $(LIBSRC)/certifier_proofs.cc $(I)/certifier.pb.h $(I)/certifier.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(O)/support.o: $(LIBSRC)/support.cc $(I)/support.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(O)/cc_helpers.o: $(LIBSRC)/cc_helpers.cc $(I)/cc_helpers.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(O)/cc_useful.o: $(LIBSRC)/cc_useful.cc $(I)/cc_useful.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(O)/simulated_enclave.o: $(LIBSRC)/simulated_enclave.cc $(I)/simulated_enclave.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(O)/application_enclave.o: $(LIBSRC)/application_enclave.cc $(I)/application_enclave.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(O)/test_user.o: $(S)/test_user.cc $(S)/certifier.pb.cc
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

SEV_S=$(LIBSRC)/sev-snp

$(O)/sev_support.o: $(SEV_S)/sev_support.cc \
                    $(I)/certifier.h $(I)/support.h \
                    $(SEV_S)/attestation.h  $(SEV_S)/sev_guest.h \
                    $(SEV_S)/snp_derive_key.h \
                    $(SEV_S)/sev_cert_table.h
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
