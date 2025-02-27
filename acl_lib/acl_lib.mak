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
#    File: acl_lib.mak


ifndef SRC_DIR
SRC_DIR=$(HOME)/src/github.com/jlmucb/class_notes
endif
ifndef OBJ_DIR
OBJ_DIR=$(HOME)/cryptoobj
endif
ifndef EXE_DIR
EXE_DIR=$(HOME)/cryptobin
endif
ifndef LIB_DIR
LIB_DIR=$(SRC_DIR)
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
NEWPROTOBUF=1

S= $(SRC_DIR)/datica_tmp/acl_lib
O= $(OBJ_DIR)/acl_lib
INCLUDE= -I$(SRC_DIR)/include -I$(S) -I/usr/local/include -I/usr/local/opt/openssl@1.1/include/

ifndef NEWPROTOBUF
CFLAGS=$(INCLUDE) -O3 -g -Wall -std=c++11 -Wno-unused-variable -D X64 -Wno-deprecated-declarations
CFLAGS1=$(INCLUDE) -O1 -g -Wall -std=c++11 -Wno-unused-variable -D X64 -Wno-deprecated-declarations
else
CFLAGS=$(INCLUDE) -O3 -g -Wall -std=c++17 -Wno-unused-variable -D X64 -Wno-deprecated-declarations
CFLAGS1=$(INCLUDE) -O1 -g -Wall -std=c++17 -Wno-unused-variable -D X64 -Wno-deprecated-declarations
endif
CC=g++
LINK=g++
PROTO=protoc
AR=ar

# build the library later
tobj=   $(O)/acl_rpc.o $(O)/acl_support.o $(O)/acl.o $(O)/acl.pb.o $(O)/test_acl.o

ifdef NEWPROTOBUF
export LD_LIBRARY_PATH=/usr/local/lib
LDFLAGS= -L/usr/local/lib `pkg-config --cflags --libs protobuf` -lgtest -lgflags -lpthread -L/usr/local/opt/openssl@1.1/lib/ -lcrypto -lssl
else
export LD_LIBRARY_PATH=/usr/local/lib
LDFLAGS= -L/usr/local/lib -lprotobuf -lgtest -lgflags -lpthread -L/usr/local/opt/openssl@1.1/lib/ -lcrypto -lssl
endif

all:	test_acl.exe
clean:
	@echo "removing object files"
	rm $(O)/*.o
	@echo "removing executable file"
	rm $(EXE_DIR)/test_acl.exe

test_acl.exe: $(tobj)
	@echo "linking executable files"
	$(LINK) -o $(EXE_DIR)/test_acl.exe $(tobj) $(LDFLAGS)

$(S)/acl.pb.cc: $(S)/acl.proto
	$(PROTO) -I=$(S) --cpp_out=$(S) $(S)/acl.proto

$(O)/test_acl.o: $(S)/acl.h $(S)/test_acl.cc $(S)/acl.pb.cc
	@echo "compiling test_acl.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/test_acl.o $(S)/test_acl.cc

$(O)/acl.pb.o: $(S)/acl.pb.cc $(S)/acl.pb.h
	@echo "compiling acl.pb.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/acl.pb.o $(S)/acl.pb.cc

$(O)/acl_support.o: $(S)/acl_support.h $(S)/acl_support.cc $(S)/acl.pb.cc
	@echo "compiling acl_support.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/acl_support.o $(S)/acl_support.cc

$(O)/acl.o: $(S)/acl.h $(S)/acl.cc $(S)/acl.pb.cc $(S)/acl_support.h
	@echo "compiling acl.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/acl.o $(S)/acl.cc

$(O)/acl_rpc.o: $(S)/acl.h $(S)/acl_rpc.h $(S)/acl.pb.cc $(S)/acl_support.h $(S)/acl_rpc.cc
	@echo "compiling acl_rpc.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/acl_rpc.o $(S)/acl_rpc.cc
