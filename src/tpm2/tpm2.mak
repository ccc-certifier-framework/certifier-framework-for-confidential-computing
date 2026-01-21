#
#    Copyright 2014 John Manferdelli, All Rights Reserved.
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#        http://www.apache.org/licenses/LICENSE-2.0
#    or in the the file LICENSE-2.0.txt in the top level sourcedirectory
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License
#    Project: New Cloudproxy Crypto
#    File: tpm2.mak

#ifndef SRC_DIR
SRC_DIR=$(HOME)
#endif
#ifndef OBJ_DIR
OBJ_DIR=$(HOME)/cryptoobj
#endif
#ifndef EXE_DIR
EXE_DIR=$(HOME)/cryptobin
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

S= $(SRC_DIR)/src/github.com/jlmucb/cloudproxy/src/tpm2
O= $(OBJ_DIR)/tpm20
INCLUDE= -I$(S) -I$(SRC_DIR)/keys -I/usr/local/include -I$(GOOGLE_INCLUDE)

CFLAGS=$(INCLUDE) -O3 -g -Wall -std=c++11 -Wno-strict-aliasing -Wno-deprecated # -DGFLAGS_NS=google
CFLAGS1=$(INCLUDE) -O1 -g -Wall -std=c++11

CC=g++
LINK=g++
PROTO=protoc
AR=ar
export LD_LIBRARY_PATH=/usr/local/lib
#LDFLAGS= $(LOCAL_LIB)/libgtest.a $(LOCAL_LIB)/libgflags.a -lpthread -lcrypto $(LOCAL_LIB)/libprotobuf.a
LDFLAGS= -lprotobuf -lgtest -lgflags -lpthread -lcrypto

dobj_tpm2_util=					$(O)/tpm2_lib.o \
  $(O)/tpm2.pb.o \
  $(O)/openssl_helpers.o \
  $(O)/conversions.o \
  $(O)/tpm2_util.o
dobj_GeneratePolicyKey=				$(O)/tpm2_lib.o \
  $(O)/tpm2.pb.o \
  $(O)/openssl_helpers.o \
  $(O)/conversions.o \
  $(O)/GeneratePolicyKey.o
dobj_CloudProxySignEndorsementKey=		$(O)/tpm2_lib.o \
  $(O)/tpm2.pb.o \
  $(O)/conversions.o \
  $(O)/openssl_helpers.o \
  $(O)/CloudProxySignEndorsementKey.o 
dobj_GetEndorsementKey=				$(O)/tpm2_lib.o \
  $(O)/tpm2.pb.o \
  $(O)/conversions.o \
  $(O)/openssl_helpers.o \
  $(O)/GetEndorsementKey.o
dobj_SelfSignPolicyCert=			$(O)/tpm2_lib.o \
  $(O)/openssl_helpers.o \
  $(O)/conversions.o \
  $(O)/tpm2.pb.o \
  $(O)/SelfSignPolicyCert.o
dobj_CreateAndSaveCloudProxyKeyHierarchy=	$(O)/tpm2_lib.o \
  $(O)/tpm2.pb.o \
  $(O)/openssl_helpers.o \
  $(O)/conversions.o \
  $(O)/CreateAndSaveCloudProxyKeyHierarchy.o
dobj_RestoreCloudProxyKeyHierarchy=		$(O)/tpm2_lib.o \
  $(O)/tpm2.pb.o \
  $(O)/openssl_helpers.o \
  $(O)/conversions.o \
  $(O)/RestoreCloudProxyKeyHierarchy.o
dobj_ClientGenerateProgramKeyRequest=		$(O)/tpm2_lib.o \
  $(O)/tpm2.pb.o \
  $(O)/quote_protocol.o \
  $(O)/conversions.o \
  $(O)/openssl_helpers.o \
  $(O)/ClientGenerateProgramKeyRequest.o
dobj_ServerSignProgramKeyRequest=		$(O)/tpm2_lib.o \
  $(O)/tpm2.pb.o \
  $(O)/quote_protocol.o \
  $(O)/conversions.o \
  $(O)/openssl_helpers.o \
  $(O)/ServerSignProgramKeyRequest.o
dobj_ClientGetProgramKeyCert=			$(O)/tpm2_lib.o \
  $(O)/tpm2.pb.o \
  $(O)/conversions.o \
  $(O)/openssl_helpers.o \
  $(O)/ClientGetProgramKeyCert.o
dobj_SigningInstructions=			$(O)/tpm2_lib.o \
  $(O)/tpm2.pb.o \
  $(O)/conversions.o \
  $(O)/openssl_helpers.o \
  $(O)/SigningInstructions.o
dobj_PadTest =	$(O)/tpm2_lib.o \
  $(O)/tpm2.pb.o \
  $(O)/conversions.o \
  $(O)/quote_protocol.o \
  $(O)/openssl_helpers.o \
  $(O)/padtest.o

all:	$(EXE_DIR)/tpm2_util.exe \
	$(EXE_DIR)/GeneratePolicyKey.exe \
	$(EXE_DIR)/SigningInstructions.exe \
	$(EXE_DIR)/GetEndorsementKey.exe \
	$(EXE_DIR)/SelfSignPolicyCert.exe \
	$(EXE_DIR)/CloudProxySignEndorsementKey.exe \
	$(EXE_DIR)/CreateAndSaveCloudProxyKeyHierarchy.exe \
	$(EXE_DIR)/CloudProxySignEndorsementKey.exe \
	$(EXE_DIR)/RestoreCloudProxyKeyHierarchy.exe \
	$(EXE_DIR)/ClientGenerateProgramKeyRequest.exe \
	$(EXE_DIR)/ServerSignProgramKeyRequest.exe \
	$(EXE_DIR)/ClientGetProgramKeyCert.exe \
	$(EXE_DIR)/padtest.exe

clean:
	@echo "removing object files"
	rm $(O)/*.o
	@echo "removing executable file"
	rm $(EXE_DIR)/tpm2_util.exe
	rm $(EXE_DIR)/GeneratePolicyKey.exe
	rm $(EXE_DIR)/SigningInstructions.exe
	rm $(EXE_DIR)/GetEndorsementKey.exe
	rm $(EXE_DIR)/SelfSignPolicyCert.exe
	rm $(EXE_DIR)/CloudProxySignEndorsementKey.exe
	rm $(EXE_DIR)/CreateAndSaveCloudProxyKeyHierarchy.exe
	rm $(EXE_DIR)/CloudProxySignEndorsementKey.exe
	rm $(EXE_DIR)/RestoreCloudProxyKeyHierarchy.exe
	rm $(EXE_DIR)/ClientGenerateProgramKeyRequest.exe
	rm $(EXE_DIR)/ServerSignProgramKeyRequest.exe
	rm $(EXE_DIR)/ClientGetProgramKeyCert.exe

$(EXE_DIR)/tpm2_util.exe: $(dobj_tpm2_util)
	@echo "linking tpm2_util"
	$(LINK) -o $(EXE_DIR)/tpm2_util.exe $(dobj_tpm2_util) $(LDFLAGS)

$(EXE_DIR)/GeneratePolicyKey.exe: $(dobj_GeneratePolicyKey)
	@echo "linking GeneratePolicyKey"
	$(LINK) -o $(EXE_DIR)/GeneratePolicyKey.exe $(dobj_GeneratePolicyKey) $(LDFLAGS)

$(EXE_DIR)/CloudProxySignEndorsementKey.exe: $(dobj_CloudProxySignEndorsementKey)
	@echo "linking CloudProxySignEndorsementKey"
	$(LINK) -o $(EXE_DIR)/CloudProxySignEndorsementKey.exe $(dobj_CloudProxySignEndorsementKey) $(LDFLAGS)

$(EXE_DIR)/GetEndorsementKey.exe: $(dobj_GetEndorsementKey)
	@echo "linking GetEndorsementKey"
	$(LINK) -o $(EXE_DIR)/GetEndorsementKey.exe $(dobj_GetEndorsementKey) $(LDFLAGS)

$(EXE_DIR)/SelfSignPolicyCert.exe: $(dobj_SelfSignPolicyCert)
	@echo "linking SelfSignPolicyCert"
	$(LINK) -o $(EXE_DIR)/SelfSignPolicyCert.exe $(dobj_SelfSignPolicyCert) $(LDFLAGS)

$(EXE_DIR)/CreateAndSaveCloudProxyKeyHierarchy.exe: $(dobj_CreateAndSaveCloudProxyKeyHierarchy)
	@echo "linking CreateAndSaveCloudProxyKeyHierarchy"
	$(LINK) -o $(EXE_DIR)/CreateAndSaveCloudProxyKeyHierarchy.exe $(dobj_CreateAndSaveCloudProxyKeyHierarchy) $(LDFLAGS)

$(EXE_DIR)/RestoreCloudProxyKeyHierarchy.exe: $(dobj_RestoreCloudProxyKeyHierarchy)
	@echo "linking RestoreCloudProxyKeyHierarchy"
	$(LINK) -o $(EXE_DIR)/RestoreCloudProxyKeyHierarchy.exe $(dobj_RestoreCloudProxyKeyHierarchy) $(LDFLAGS)

$(EXE_DIR)/ClientGenerateProgramKeyRequest.exe: $(dobj_ClientGenerateProgramKeyRequest)
	@echo "linking ClientGenerateProgramKeyRequest"
	$(LINK) -o $(EXE_DIR)/ClientGenerateProgramKeyRequest.exe $(dobj_ClientGenerateProgramKeyRequest) $(LDFLAGS)

$(EXE_DIR)/ServerSignProgramKeyRequest.exe: $(dobj_ServerSignProgramKeyRequest)
	@echo "linking ServerSignProgramKeyRequest"
	$(LINK) -o $(EXE_DIR)/ServerSignProgramKeyRequest.exe $(dobj_ServerSignProgramKeyRequest) $(LDFLAGS)

$(EXE_DIR)/ClientGetProgramKeyCert.exe: $(dobj_ClientGetProgramKeyCert)
	@echo "linking ClientGetProgramKeyCert"
	$(LINK) -o $(EXE_DIR)/ClientGetProgramKeyCert.exe $(dobj_ClientGetProgramKeyCert) $(LDFLAGS)

$(EXE_DIR)/SigningInstructions.exe: $(dobj_SigningInstructions)
	@echo "linking SigningInstructions"
	$(LINK) -o $(EXE_DIR)/SigningInstructions.exe $(dobj_SigningInstructions) $(LDFLAGS)

$(O)/tpm2.pb.o: $(S)/tpm2.pb.cc
	@echo "compiling protobuf object"
	$(CC) $(CFLAGS) -c -o $(O)/tpm2.pb.o $(S)/tpm2.pb.cc

$(S)/tpm2.pb.cc tpm2.pb.h: $(S)/tpm2.proto
	@echo "creating protobuf files"
	$(PROTO) -I=$(S) --cpp_out=$(S) $(S)/tpm2.proto

$(O)/tpm2_lib.o: $(S)/tpm2_lib.cc
	@echo "compiling tpm2_lib.cc"
	$(CC) $(CFLAGS) -c -o $(O)/tpm2_lib.o $(S)/tpm2_lib.cc

$(O)/conversions.o: $(S)/conversions.cc
	@echo "compiling conversions.cc"
	$(CC) $(CFLAGS) -c -o $(O)/conversions.o $(S)/conversions.cc

$(O)/openssl_helpers.o: $(S)/openssl_helpers.cc
	@echo "compiling openssl_helpers.cc"
	$(CC) $(CFLAGS) -c -o $(O)/openssl_helpers.o $(S)/openssl_helpers.cc

$(O)/quote_protocol.o: $(S)/quote_protocol.cc
	@echo "compiling quote_protocol.cc"
	$(CC) $(CFLAGS) -c -o $(O)/quote_protocol.o $(S)/quote_protocol.cc

$(O)/tpm2_util.o: $(S)/tpm2_util.cc
	@echo "compiling tpm2_util.cc"
	$(CC) $(CFLAGS) -c -o $(O)/tpm2_util.o $(S)/tpm2_util.cc

$(O)/GeneratePolicyKey.o: $(S)/GeneratePolicyKey.cc
	@echo "compiling GeneratePolicyKey.cc"
	$(CC) $(CFLAGS) -c -o $(O)/GeneratePolicyKey.o $(S)/GeneratePolicyKey.cc

$(O)/CloudProxySignEndorsementKey.o: $(S)/CloudProxySignEndorsementKey.cc
	@echo "compiling CloudProxySignEndorsementKey.cc"
	$(CC) $(CFLAGS) -c -o $(O)/CloudProxySignEndorsementKey.o $(S)/CloudProxySignEndorsementKey.cc

$(O)/CreateAndSaveCloudProxyKeyHierarchy.o: $(S)/CreateAndSaveCloudProxyKeyHierarchy.cc
	@echo "compiling CreateAndSaveCloudProxyKeyHierarchy.cc"
	$(CC) $(CFLAGS) -c -o $(O)/CreateAndSaveCloudProxyKeyHierarchy.o $(S)/CreateAndSaveCloudProxyKeyHierarchy.cc

$(O)/RestoreCloudProxyKeyHierarchy.o: $(S)/RestoreCloudProxyKeyHierarchy.cc
	@echo "compiling RestoreCloudProxyKeyHierarchy.cc"
	$(CC) $(CFLAGS) -c -o $(O)/RestoreCloudProxyKeyHierarchy.o $(S)/RestoreCloudProxyKeyHierarchy.cc

$(O)/ClientGetProgramKeyCert.o: $(S)/ClientGetProgramKeyCert.cc
	@echo "compiling ClientGetProgramKeyCert.cc"
	$(CC) $(CFLAGS) -c -o $(O)/ClientGetProgramKeyCert.o $(S)/ClientGetProgramKeyCert.cc

$(O)/ServerSignProgramKeyRequest.o: $(S)/ServerSignProgramKeyRequest.cc
	@echo "compiling ServerSignProgramKeyRequest.cc"
	$(CC) $(CFLAGS) -c -o $(O)/ServerSignProgramKeyRequest.o $(S)/ServerSignProgramKeyRequest.cc

$(O)/ClientGenerateProgramKeyRequest.o: $(S)/ClientGenerateProgramKeyRequest.cc
	@echo "compiling ClientGenerateProgramKeyRequest.cc"
	$(CC) $(CFLAGS) -c -o $(O)/ClientGenerateProgramKeyRequest.o $(S)/ClientGenerateProgramKeyRequest.cc

$(O)/GetEndorsementKey.o: $(S)/GetEndorsementKey.cc
	@echo "compiling GetEndorsementKey.cc"
	$(CC) $(CFLAGS) -c -o $(O)/GetEndorsementKey.o $(S)/GetEndorsementKey.cc

$(O)/SelfSignPolicyCert.o: $(S)/SelfSignPolicyCert.cc
	@echo "compiling SelfSignPolicyCert.cc"
	$(CC) $(CFLAGS) -c -o $(O)/SelfSignPolicyCert.o $(S)/SelfSignPolicyCert.cc

$(O)/SigningInstructions.o: $(S)/SigningInstructions.cc
	@echo "compiling SigningInstructions.cc"
	$(CC) $(CFLAGS) -c -o $(O)/SigningInstructions.o $(S)/SigningInstructions.cc

$(O)/padtest.o: $(S)/padtest.cc
	@echo "compiling padtest.cc"
	$(CC) $(CFLAGS) -c -o $(O)/padtest.o $(S)/padtest.cc

$(EXE_DIR)/padtest.exe: $(dobj_PadTest)
	@echo "linking padtest"
	$(LINK) -o $(EXE_DIR)/padtest.exe $(dobj_PadTest) $(LDFLAGS)


