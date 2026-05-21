#
#    Copyright 2014 John Manferdelli, All Rights Reserved.
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#	http://www.apache.org/licenses/LICENSE-2.0
#    or in the the file LICENSE-2.0.txt in the top level sourcedirectory
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License
#    File: tpm2_support.mak

#ifndef CERTIFIER_ROOT
CERTIFIER_ROOT=../..
#endif
TPM_DIR=$(CERTIFIER_ROOT)/src/tpm2
#ifndef EXE_DIR
EXE_DIR=$(TPM_DIR)
#endif
#ifndef GOOGLE_INCLUDE
GOOGLE_INCLUDE=/usr/local/include/google
#endif
#ifndef LOCAL_LIB
LOCAL_LIB=/usr/local/lib
#endif
#ifndef TARGET_MACHINE_TYPE
TARGET_MACHINE_TYPE= x64
#endif

NEWPROTOBUF=1
NEW_API=1

S= $(TPM_DIR)
O= $(TPM_DIR)
CP = $(CERTIFIER_ROOT)/certifier_service/certprotos
CI = $(CERTIFIER_ROOT)/include
SC= $(CERTIFIER_ROOT)/src
SE= $(CERTIFIER_ROOT)/src/simulated-enclave
AE= $(CERTIFIER_ROOT)/src/application-enclave

INCLUDE=-I$(TPM_DIR) -I/usr/local/opt/openssl@1.1/include/ -I$(GOOGLE_INCLUDE) \
	-I$(CI) -I$(SC)/sev-snp -I $(SC)/gramine

CC=g++
LINK=g++
PROTO=protoc

ifndef NEWPROTOBUF
CFLAGS_COMMON = $(INCLUDE) -g -Wall -std=c++11 -Wno-unused-variable -D X64 \
	-Wno-deprecated-declarations
LDFLAGS = -L $(LOCAL_LIB) -lprotobuf -lgtest -lgflags -lpthread \
	-L/usr/local/opt/openssl@1.1/lib/ -lcrypto -lssl -luuid
else
LDFLAGS = -L $(LOCAL_LIB) `pkg-config --cflags --libs protobuf` -lgtest -lgflags \
	-lpthread -L/usr/local/opt/openssl@1.1/lib/ -lcrypto -lssl -luuid
CFLAGS_COMMON = $(INCLUDE) -g -Wall -std=c++17 -Wno-unused-variable -D X64 \
	-Wno-deprecated-declarations
endif
CFLAGS=$(CFLAGS_COMMON)
ifndef NEW_API
CFLAGS += -DNEW_API
endif

certifier_objs = $(O)/certifier.pb.o $(O)/certifier.o \
	      $(O)/certifier_proofs.o  $(O)/support.o $(O)/simulated_enclave.o \
	      $(O)/application_enclave.o

dobj_tpm2= $(certifier_objs) $(O)/tpm2.pb.o $(O)/tpm2_lib.o $(O)/openssl_help.o \
	$(O)/convert.o $(O)/tpm2_support.o

all:	$(EXE_DIR)/tpm2_test.exe  $(EXE_DIR)/tpm2_set_pcrs.exe

clean:
	@echo "removing object files"
	rm $(O)/*.o
	@echo "removing executable file"
	rm $(EXE_DIR)/tpm2_test.exe
	@echo "removing executable file"
	rm $(EXE_DIR)/tpm2_set_pcrs.exe
	@echo "removing protobuf files"
	rm $(CI)/certifier.pb.h
	rm $(s)/certifier.pb.cc

$(EXE_DIR)/tpm2_test.exe: $(dobj_tpm2) $(O)/tpm2_test.o
	@echo "linking tpm2_test"
	$(LINK) -o $(EXE_DIR)/tpm2_test.exe $(dobj_tpm2)  $(O)/tpm2_test.o $(LDFLAGS)

$(EXE_DIR)/tpm2_set_pcrs.exe: $(dobj_tpm2) $(O)/tpm2_set_pcrs.o
	@echo "linking tpm2_set_pcrs"
	$(LINK) -o $(EXE_DIR)/tpm2_set_pcrs.exe $(dobj_tpm2) $(O)/tpm2_set_pcrs.o \
		$(LDFLAGS)

$(O)/certifier.pb.o: $(S)/certifier.pb.cc $(CI)/certifier.pb.h \
		$(S)/tpm2.pb.cc $(S)/tpm2.pb.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(S)/certifier.pb.cc $(CI)/certifier.pb.h: $(CP)/certifier.proto
	$(PROTO) --cpp_out=$(S) --proto_path $(<D) $<
	mv $(S)/certifier.pb.h $(CI)

$(O)/tpm2_lib.o: $(S)/tpm2_lib.cc
	@echo "compiling tpm2_lib.cc"
	$(CC) $(CFLAGS) -c -o $(O)/tpm2_lib.o $(S)/tpm2_lib.cc

$(S)/tpm2.pb.cc $(S)/tpm2.pb.h: $(S)/tpm2.proto
	@echo "creating protobuf files"
	$(PROTO) -I=$(S) --cpp_out=$(S) $(S)/tpm2.proto

$(O)/convert.o: $(S)/convert.cc
	@echo "compiling convert.cc"
	$(CC) $(CFLAGS) -c -o $(O)/convert.o $(S)/convert.cc

$(O)/openssl_help.o: $(S)/openssl_help.cc
	@echo "compiling openssl_help.cc"
	$(CC) $(CFLAGS) -c -o $(O)/openssl_help.o $(S)/openssl_help.cc

$(O)/tpm2_support.o: $(S)/tpm2_support.cc $(S)/certifier.pb.cc $(S)/tpm2.pb.cc
	@echo "compiling tpm2_support.cc"
	$(CC) $(CFLAGS) -c -o $(O)/tpm2_support.o $(S)/tpm2_support.cc

$(O)/tpm2_test.o: $(S)/tpm2_test.cc
	@echo "compiling tpm2_test.cc"
	$(CC) $(CFLAGS) -c -o $(O)/tpm2_test.o $(S)/tpm2_test.cc

$(O)/tpm2_set_pcrs.o: $(S)/tpm2_set_pcrs.cc
	@echo "compiling tpm2_set_pcrs.cc"
	$(CC) $(CFLAGS) -c -o $(O)/tpm2_set_pcrs.o $(S)/tpm2_set_pcrs.cc

$(O)/tpm2.pb.o: $(S)/tpm2.pb.cc $(S)/tpm2.pb.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(O)/certifier.o: $(SC)/certifier.cc $(CI)/certifier.pb.h $(CI)/certifier.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(O)/certifier_proofs.o: $(SC)/certifier_proofs.cc $(CI)/certifier.pb.h $(CI)/certifier.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(O)/cc_helpers.o: $(SC)/cc_helpers.cc $(CI)/certifier.pb.h $(CI)/cc_helpers.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(O)/cc_useful.o: $(SC)/cc_useful.cc $(CI)/cc_useful.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(O)/support.o: $(SC)/support.cc $(CI)/support.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(O)/simulated_enclave.o: $(SE)/simulated_enclave.cc $(CI)/simulated_enclave.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(O)/application_enclave.o: $(AE)/application_enclave.cc $(CI)/application_enclave.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<



