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
#    File: standalone_app.mak


# CERTIFIER_ROOT will be certifier-framework-for-confidential-computing/ dir
CERTIFIER_ROOT = ..

ifndef SRC_DIR
SRC_DIR=$(CERTIFIER_ROOT)/acl_lib
endif
ifndef OBJ_DIR
OBJ_DIR=.
endif
ifndef EXE_DIR
EXE_DIR=.
endif
ifndef LIB_DIR
LIB_DIR=$(SRC_DIR)
endif

CI=../include
CS=../src
CP=../certifier_service/certprotos

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

O= $(OBJ_DIR)
INCLUDE= -I$(CI) -I$(SRC_DIR) -I/usr/local/include -I/usr/local/opt/openssl@1.1/include/

ifndef NEWPROTOBUF
CFLAGS=$(INCLUDE) -O3 -g -Wall -std=c++11 -fPIC -Wno-unused-variable -D X64 -Wno-deprecated-declarations
CFLAGS1=$(INCLUDE) -O1 -g -Wall -std=c++11 -fPIC -Wno-unused-variable -D X64 -Wno-deprecated-declarations
else
CFLAGS=$(INCLUDE) -O3 -g -Wall -std=c++17 -fPIC -Wno-unused-variable -D X64 -Wno-deprecated-declarations
CFLAGS1=$(INCLUDE) -O1 -g -Wall -std=c++17 -fPIC -Wno-unused-variable -D X64 -Wno-deprecated-declarations
endif
CC=g++
LINK=g++
PROTO=protoc
AR=ar

# build the library later
tobj=   $(O)/standalone_app.o

ifdef NEWPROTOBUF
export LD_LIBRARY_PATH=/usr/local/lib
LDFLAGS= -L/usr/local/lib -L.. -L. -l:acl_lib.a -l:certifier.a `pkg-config --cflags --libs protobuf` -lgtest -lgflags -lpthread -L/usr/local/opt/openssl@1.1/lib/ -lcrypto -lssl
else
export LD_LIBRARY_PATH=/usr/local/lib ..
LDFLAGS= -L/usr/local/lib -L.. -L. -l:acl_lib.a -l:certifier.a -lprotobuf -lgtest -lgflags -lpthread -L/usr/local/opt/openssl@1.1/lib/ -lcrypto -lssl
endif

all:	standalone_app.exe
clean:
	@echo "removing object files"
	rm $(O)/*.o
	@echo "removing executable file"
	rm $(EXE_DIR)/standalone_app.exe

standalone_app.exe: $(tobj)
	@echo "linking executable files"
	$(LINK) -o $(EXE_DIR)/standalone_app.exe $(tobj) $(LDFLAGS)

$(O)/standalone_app.o: $(SRC_DIR)/acl.h $(SRC_DIR)/standalone_app.cc
	@echo "compiling standalone_app.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/standalone_app.o $(SRC_DIR)/standalone_app.cc
