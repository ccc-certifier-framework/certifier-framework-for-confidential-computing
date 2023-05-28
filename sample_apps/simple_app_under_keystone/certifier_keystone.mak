# git clone keystone
# export KEYSTONE_ROOT_DIR = /keystone
# make -f certifier_keystone.mak

ifndef KEYSTONE_ROOT_DIR
    KEYSTONE_ROOT_DIR = /keystone
endif

# all the header and src files
KEYSTONE_SDK_INCLUDE = $(KEYSTONE_ROOT_DIR)/sdk/build64/include
KEYSTONE_SDK_LIB_DIR = $(KEYSTONE_ROOT_DIR)/sdk/build64/lib
KEYSTONE_SDK_LIBS = -lkeystone-eapp -lkeystone-edge -lkeystone-host -lkeystone-verifier
KEYSTONE_RT_INCLUDE = $(KEYSTONE_ROOT_DIR)/runtime/include
KEYSTONE_RT_SRC = $(KEYSTONE_ROOT_DIR)/runtime

# KEYSTONE_SDK_SRC = $(KEYSTONE_ROOT_DIR)/sdk/src
# KEYSTONE_SRCS = app/string.c app/tiny-malloc.c edge/edge_dispatch.c verifier/json11.cpp app/syscall.c edge/edge_call.c edge/edge_syscall.c verifier/Report.cpp verifier/keys.cpp verifier/ed25519/fe.c verifier/ed25519/ge.c verifier/ed25519/keypair.c verifier/ed25519/sc.c verifier/ed25519/sign.c verifier/ed25519/verify.c
# # don't need: crypto/merkle.c crypto/sha256.c
# KEYSTONE_SRCS = $(patsubst %,$(KEYSTONE_SDK_SRC)/%,$(KEYSTONE_SRCS))
# KEYSTONE_SRCS += $(KEYSTONE_RT_SRC)/crypto/aes.c
# KEYSTONE_ASM_SRCS = $(KEYSTONE_SDK_SRC)/app/encret.S
KEYSTONE_AES = $(KEYSTONE_RT_SRC)/crypto/aes.c

# RISC-V cross compiler
CC = riscv64-unknown-linux-gnu-g++
LINK = riscv64-unknown-linux-gnu-g++
# CFLAGS = -Wall -fPIC -fno-builtin
CFLAGS = -Wall -fno-builtin
LDFLAGS = -static -L$(KEYSTONE_SDK_LIB_DIR) $(KEYSTONE_SDK_LIBS) # no dynamic libraries!

ifndef SRC_DIR
SRC_DIR = ../..
endif
ifndef OBJ_DIR
OBJ_DIR = ./build
endif
ifndef EXE_DIR
EXE_DIR = .
endif

S = $(SRC_DIR)/src
O = $(OBJ_DIR)
SEV_S = $(S)/keystone
I = $(SRC_DIR)/include
INCLUDE = -I$(I) -I$(KEYSTONE_SDK_INCLUDE) -I$(KEYSTONE_RT_INCLUDE)
CFLAGS += $(INCLUDE)

EXPERIMENT_FLAGS = -g

$(O)/keystone_aes.o: $(KEYSTONE_AES)
	@echo "compiling $(KEYSTONE_AES)"
	$(CC) $(CFLAGS) -c -o $(O)/keystone_aes.o $(KEYSTONE_AES) $(EXPERIMENT_FLAGS)

$(O)/keystone_api.o: $(SEV_S)/keystone_api.cc
	@echo "compiling keystone_api.cc"
	$(CC) $(CFLAGS) -c -o $(O)/keystone_api.o $(SEV_S)/keystone_api.cc $(EXPERIMENT_FLAGS)

# keystone_certifier_app not done
dobj = certifier.a $(O)/keystone_api.o

keystone_certifier_app: $(dobj)
	@echo "linking executable files"
	$(LINK) -o $(EXE_DIR)/keystone_certifier_app $(dobj) $(LDFLAGS)

# below are for testing only

keystone_api: $(O)/keystone_api.o $(O)/keystone_aes.o $(KEYSTONE_SDK_LIB)
	@echo "linking into keystone_api"
	$(LINK) -o $(EXE_DIR)/keystone_api $(O)/keystone_api.o $(O)/keystone_aes.o $(LDFLAGS) $(EXPERIMENT_FLAGS)

all_in_one:
	@echo "all_in_one"
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(EXE_DIR)/keystone_api $(SEV_S)/keystone_api.cc $(KEYSTONE_AES) $(EXPERIMENT_FLAGS)


clean:
	rm $(O)/keystone_aes.o; rm $(O)/keystone_api.o; rm $(EXE_DIR)/keystone_api; exit 0

# from example

# $(O)/keystone_api.o: $(SEV_S)/keystone_api.cc \
# $(I)/certifier.h $(I)/support.h $(SEV_S)/attestation.h  $(SEV_S)/sev_guest.h  \
# $(SEV_S)/snp_derive_key.h
# 	@echo "compiling keystone_api.cc"
# 	$(CC) $(CFLAGS) -c -o $(O)/keystone_api.o $(SEV_S)/keystone_api.cc
#
# keystone_certifier_app: $(dobj)
# 	@echo "linking executable files"
# 	$(LINK) -o $(EXE_DIR)/keystone_certifier_app $(dobj) $(LDFLAGS)
