# git clone keystone
# export KEYSTONE_ROOT_DIR = /keystone # or wherever desired, same as clone
# make -f keystone_example_app.mak keystone_certifier_app
# for testing Keystone compile + link (this currently works)
# make -f keystone_example_app.mak keystone_api

ifndef KEYSTONE_ROOT_DIR
    KEYSTONE_ROOT_DIR = /keystone
endif

# all the Keystone headers, srcs, and libs
KEYSTONE_SDK_INCLUDE = $(KEYSTONE_ROOT_DIR)/sdk/build64/include
KEYSTONE_SDK_LIB_DIR = $(KEYSTONE_ROOT_DIR)/sdk/build64/lib
KEYSTONE_SDK_LIBS = -lkeystone-host -lkeystone-eapp -lkeystone-edge -lkeystone-verifier
KEYSTONE_RT_INCLUDE = $(KEYSTONE_ROOT_DIR)/runtime/include
KEYSTONE_RT_SRC = $(KEYSTONE_ROOT_DIR)/runtime
KEYSTONE_FLAGS = -DUSE_PAGE_CRYPTO

# RISC-V cross compiler
CC = riscv64-unknown-linux-gnu-g++
LINK = riscv64-unknown-linux-gnu-g++
# flags from Keystone
CFLAGS = -Wall -I$(KEYSTONE_SDK_INCLUDE) -I$(KEYSTONE_RT_INCLUDE)
LDFLAGS = -static -L$(KEYSTONE_SDK_LIB_DIR) $(KEYSTONE_SDK_LIBS)

ifndef SRC_DIR
SRC_DIR=../..
endif
ifndef INC_DIR
INC_DIR=../../../include
endif
ifndef OBJ_DIR
OBJ_DIR=./build
endif
ifndef EXE_DIR
EXE_DIR=.
endif

# TODO: add flags for linking in rest of certifier
S = $(SRC_DIR)/keystone
O = $(OBJ_DIR)
I = $(INC_DIR)
CFLAGS += -I$(I) -I$(S) -DKEYSTONE_PRESENT
LDFLAGS +=

dobj = $(O)/keystone_api.o $(O)/keystone_aes.o $(O)/api_only_app.o

all: $(EXE_DIR)/api_only_app.exe

clean:
	rm -f $(dobj) $(EXE_DIR)/api_only_app.exe $(O)

$(EXE_DIR)/api_only_app.exe: $(dobj) $(KEYSTONE_SDK_LIB)
	@echo "linking executable file api_only_app.exe"
	$(LINK) -o $(EXE_DIR)/api_only_app.exe $(dobj) $(LDFLAGS)

$(O)/api_only_app.o: ./api_only_app.cc
	@echo "compiling api_only_app.cc"
	mkdir -p $(O)
	$(CC) $(CFLAGS) -c -o $(O)/api_only_app.o ./api_only_app.cc

$(O)/keystone_api.o: $(S)/keystone_api.cc
	@echo "compiling keystone_api.cc"
	mkdir -p $(O)
	$(CC) $(CFLAGS) -c -o $(O)/keystone_api.o $(S)/keystone_api.cc

$(O)/keystone_aes.o: $(KEYSTONE_RT_SRC)/crypto/aes.c
	@echo "compiling keystone_aes.o"
	mkdir -p $(O)
	$(CC) $(CFLAGS) $(KEYSTONE_FLAGS) -c -o $(O)/keystone_aes.o $(KEYSTONE_RT_SRC)/crypto/aes.c
