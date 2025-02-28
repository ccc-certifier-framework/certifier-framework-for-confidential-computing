#
#    File: policy_generator.mak

# CERTIFIER_ROOT will be certifier-framework-for-confidential-computing/ dir
ifndef CERTIFIER_ROOT
CERTIFIER_ROOT=..
endif

ifndef SRC_DIR
SRC_DIR=.
endif

ifndef OBJ_DIR
OBJ_DIR=.
endif
ifndef EXE_DIR
EXE_DIR=.
endif

S= $(SRC_DIR)
CERT_SRC=$(CERTIFIER_ROOT)/src
O= $(OBJ_DIR)

JSON_VALIDATOR=/usr/local
LOCAL_LIB=$(JSON_VALIDATOR)/lib
INCLUDE= -I$(JSON_VALIDATOR)/include


# Newer versions of protobuf require C++17 and dependancies on additional libraries.
# When this happens, everything must be compiles with C++17 and the linking is a
# little more complicated.  To use newer protobuf libraries, define NEWPROROBUF as
# is done below.  Comment it out for older protobuf usage.
NEWPROTOBUF=1

ifndef NEWPROTOBUF
CFLAGS= $(INCLUDE) -O3 -g -Wall -Werror -Wno-unused-variable -std=c++11 -D X64 -Wno-deprecated -Wno-deprecated-declarations
else
CFLAGS= $(INCLUDE) -O3 -g -Wall -Werror -Wno-unused-variable -std=c++17 -D X64 -Wno-deprecated -Wno-deprecated-declarations
endif

CC=g++
LD=g++

ifndef NEWPROTOBUF
LDFLAGS= -L$(LOCAL_LIB) -lnlohmann_json_schema_validator -lgflags
else
LDFLAGS= -L$(LOCAL_LIB) `pkg-config --cflags --libs protobuf` -lnlohmann_json_schema_validator -lgflags
endif

all:	$(EXE_DIR)/policy_generator.exe

clean:
	rm -rf $(O)/policy_generator.o $(EXE_DIR)/policy_generator.exe

$(EXE_DIR)/policy_generator.exe: $(EXE_DIR)/policy_generator.o
	$(LD) -o $(EXE_DIR)/policy_generator.exe policy_generator.o $(LDFLAGS)

$(O)/policy_generator.o: $(S)/policy_generator.cc
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<
