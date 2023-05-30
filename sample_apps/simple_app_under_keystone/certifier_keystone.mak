# git clone keystone
# export KEYSTONE_ROOT_DIR = /keystone
# make -f certifier_keystone.mak

ifndef KEYSTONE_ROOT_DIR
    KEYSTONE_ROOT_DIR = /keystone
endif

# all the header and src files
KEYSTONE_SDK_INCLUDE = $(KEYSTONE_ROOT_DIR)/sdk/build64/include
KEYSTONE_SDK_LIB_DIR = $(KEYSTONE_ROOT_DIR)/sdk/build64/lib
KEYSTONE_SDK_LIBS = -lkeystone-host -lkeystone-eapp -lkeystone-edge -lkeystone-verifier
# KEYSTONE_SDK_LIBS = $(KEYSTONE_SDK_LIB_DIR)/libkeystone-eapp.a $(KEYSTONE_SDK_LIB_DIR)/libkeystone-edge.a $(KEYSTONE_SDK_LIB_DIR)/libkeystone-host.a $(KEYSTONE_SDK_LIB_DIR)/libkeystone-verifier.a
KEYSTONE_RT_INCLUDE = $(KEYSTONE_ROOT_DIR)/runtime/include
KEYSTONE_RT_SRC = $(KEYSTONE_ROOT_DIR)/runtime
KEYSTONE_FLAGS = -DUSE_PAGE_CRYPTO

# KEYSTONE_SDK_SRC = $(KEYSTONE_ROOT_DIR)/sdk/src
# KEYSTONE_SRCS = app/string.c app/tiny-malloc.c edge/edge_dispatch.c verifier/json11.cpp app/syscall.c edge/edge_call.c edge/edge_syscall.c verifier/Report.cpp verifier/keys.cpp verifier/ed25519/fe.c verifier/ed25519/ge.c verifier/ed25519/keypair.c verifier/ed25519/sc.c verifier/ed25519/sign.c verifier/ed25519/verify.c
# # don't need: crypto/merkle.c crypto/sha256.c
# KEYSTONE_SRCS = $(patsubst %,$(KEYSTONE_SDK_SRC)/%,$(KEYSTONE_SRCS))
# KEYSTONE_SRCS += $(KEYSTONE_RT_SRC)/crypto/aes.c
# KEYSTONE_ASM_SRCS = $(KEYSTONE_SDK_SRC)/app/encret.S

# RISC-V cross compiler
CC = riscv64-unknown-linux-gnu-g++
LINK = riscv64-unknown-linux-gnu-g++
# CFLAGS = -Wall -fPIC -fno-builtin
CFLAGS = -Wall -fno-builtin
LDFLAGS = -static -L$(KEYSTONE_SDK_LIB_DIR) $(KEYSTONE_SDK_LIBS)
# /keystone/riscv64/bin/../lib/gcc/riscv64-unknown-linux-gnu/10.2.0/libgcc.a
# /keystone/riscv64/bin/riscv64-unknown-linux-gnu-g++     CMakeFiles/hello-runner.dir/host/host.cpp.o  -o hello-runner /keystone/sdk/build64/lib/libkeystone-host.a /keystone/sdk/build64/lib/libkeystone-edge.a

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

$(O)/keystone_aes.o: $(KEYSTONE_RT_SRC)/crypto/aes.c
	@echo "compiling keystone_aes.o"
	$(CC) $(CFLAGS) $(KEYSTONE_FLAGS) -c -o $(O)/keystone_aes.o $(KEYSTONE_RT_SRC)/crypto/aes.c

# $(O)/keystone_string.o: $(KEYSTONE_SDK_SRC)/app/string.c
# 	@echo "compiling keystone_string.o"
# 	$(CC) $(CFLAGS) $(KEYSTONE_FLAGS) -c -o $(O)/keystone_string.o $(KEYSTONE_SDK_SRC)/app/string.c
#
# $(O)/keystone_syscall.o: $(KEYSTONE_SDK_SRC)/app/syscall.c
# 	@echo "compiling keystone_syscall.o"
# 	$(CC) $(CFLAGS) $(KEYSTONE_FLAGS) -c -o $(O)/keystone_syscall.o $(KEYSTONE_SDK_SRC)/app/syscall.c


$(O)/keystone_api.o: $(SEV_S)/keystone_api.cc
	@echo "compiling keystone_api.cc"
	$(CC) $(CFLAGS) -c -o $(O)/keystone_api.o $(SEV_S)/keystone_api.cc

# dobj = certifier.a $(O)/keystone_api.o $(O)/keystone_aes.o
# dobj = $(O)/keystone_api.o $(O)/keystone_aes.o $(O)/keystone_string.o $(O)/keystone_syscall.o
dobj = $(O)/keystone_api.o $(O)/keystone_aes.o

# keystone_certifier_app is missing certifier and app files
keystone_certifier_app: $(dobj)
	@echo "linking executable files"
	$(LINK) -o $(EXE_DIR)/keystone_certifier_app $(dobj) $(LDFLAGS)

# below are for testing only

keystone_api: $(dobj) $(KEYSTONE_SDK_LIB)
	@echo "linking into keystone_api"
	$(LINK) -o $(EXE_DIR)/keystone_api $(dobj) $(LDFLAGS)

all_in_one:
	@echo "all_in_one"
	$(CC) $(CFLAGS) $(KEYSTONE_FLAGS) -o $(EXE_DIR)/keystone_api $(SEV_S)/keystone_api.cc $(KEYSTONE_RT_SRC)/crypto/aes.c $(LDFLAGS)


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
