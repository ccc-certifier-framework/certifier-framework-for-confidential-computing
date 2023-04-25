#
#    File: policy_generator.mak

ifndef CERTIFIER_PROTOTYPE_DIR
CERTIFIER_PROTOTYPE_DIR=..
endif
ifndef SRC_DIR
SRC_DIR=$(CERTIFIER_PROTOTYPE_DIR)/utilities
endif
ifndef INC_DIR
INC_DIR=$(CERTIFIER_PROTOTYPE_DIR)/include
endif
ifndef OBJ_DIR
OBJ_DIR=.
endif
ifndef EXE_DIR
EXE_DIR=.
endif

S= $(SRC_DIR)
CERT_SRC=$(CERTIFIER_PROTOTYPE_DIR)/src
O= $(OBJ_DIR)

JSON_VALIDATOR=/usr/local
LOCAL_LIB=$(JSON_VALIDATOR)/lib
INCLUDE= -I$(JSON_VALIDATOR)/include

CC=g++
CFLAGS= $(INCLUDE) -O3 -g -Wall -Wno-unused-variable -D X64 -Wno-deprecated -Wno-deprecated-declarations
LD=g++
LDFLAGS= -L$(LOCAL_LIB) -lnlohmann_json_schema_validator -lgflags

all:	$(EXE_DIR)/policy_generator.exe

clean:
	rm -rf $(O)/policy_generator.o
	rm -rf $(EXE_DIR)/policy_generator.exe

$(EXE_DIR)/policy_generator.exe: $(EXE_DIR)/policy_generator.o
	$(LD) -o $(EXE_DIR)/policy_generator.exe policy_generator.o $(LDFLAGS)

$(O)/policy_generator.o: $(S)/policy_generator.cc
	$(CC) $(CFLAGS) -c -o $(O)/policy_generator.o $(S)/policy_generator.cc
