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

S= $(TPM_DIR)
O= $(TPM_DIR)
INCLUDE=-I$(TPM_DIR) -I/usr/local/opt/openssl@1.1/include/ -I$(GOOGLE_INCLUDE)

CC=g++
LINK=g++
PROTO=protoc

NEWPROTOBUF=1
ifndef NEWPROTOBUF
CFLAGS_COMMON = $(INCLUDE) -g -Wall -std=c++11 -Wno-unused-variable -D X64 -Wno-deprecated-declarations
LDFLAGS = -L $(LOCAL_LIB) -lprotobuf -lgtest -lgflags -lpthread -L/usr/local/opt/openssl@1.1/lib/ -lcrypto -lssl -luuid
else
LDFLAGS = -L $(LOCAL_LIB) `pkg-config --cflags --libs protobuf` -lgtest -lgflags -lpthread -L/usr/local/opt/openssl@1.1/lib/ -lcrypto -lssl -luuid
CFLAGS_COMMON = $(INCLUDE) -g -Wall -std=c++17 -Wno-unused-variable -D X64 -Wno-deprecated-declarations
endif
CFLAGS=$(CFLAGS_COMMON)

dobj_tpm2_util=	$(O)/tpm2_lib.o \
  $(O)/Openssl_help.o \
  $(O)/Convert.o \
  $(O)/tpm2_util.o

all:	$(EXE_DIR)/tpm2_util.exe \

clean:
	@echo "removing object files"
	rm $(O)/*.o
	@echo "removing executable file"
	rm $(EXE_DIR)/tpm2_util.exe

$(EXE_DIR)/tpm2_util.exe: $(dobj_tpm2_util)
	@echo "linking tpm2_util"
	$(LINK) -o $(EXE_DIR)/tpm2_util.exe $(dobj_tpm2_util) $(LDFLAGS)

$(O)/tpm2_lib.o: $(S)/tpm2_lib.cc
	@echo "compiling tpm2_lib.cc"
	$(CC) $(CFLAGS) -c -o $(O)/tpm2_lib.o $(S)/tpm2_lib.cc

$(O)/Convert.o: $(S)/Convert.cc
	@echo "compiling Convert.cc"
	$(CC) $(CFLAGS) -c -o $(O)/Convert.o $(S)/Convert.cc

$(O)/Openssl_help.o: $(S)/Openssl_help.cc
	@echo "compiling Openssl_help.cc"
	$(CC) $(CFLAGS) -c -o $(O)/Openssl_help.o $(S)/Openssl_help.cc

$(O)/tpm2_util.o: $(S)/tpm2_util.cc
	@echo "compiling tpm2_util.cc"
	$(CC) $(CFLAGS) -c -o $(O)/tpm2_util.o $(S)/tpm2_util.cc

