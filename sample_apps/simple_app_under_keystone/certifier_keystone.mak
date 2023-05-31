# git clone keystone
# export KEYSTONE_ROOT_DIR = /keystone # or wherever desired, same as clone
# make -f certifier_keystone.mak keystone_certifier_app
# for testing Keystone compile + link (this currently works)
# make -f certifier_keystone.mak keystone_api

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
CFLAGS = -Wall -fno-builtin -I$(KEYSTONE_SDK_INCLUDE) -I$(KEYSTONE_RT_INCLUDE)
LDFLAGS = -static -L$(KEYSTONE_SDK_LIB_DIR) $(KEYSTONE_SDK_LIBS)

# Example app building
ifndef SRC_DIR
    SRC_DIR = ../..
endif
ifndef OBJ_DIR
    OBJ_DIR = ./build
endif
ifndef EXE_DIR
    EXE_DIR = .
endif

# TODO: add flags for linking in rest of certifier
S = $(SRC_DIR)/src
O = $(OBJ_DIR)
SEV_S = $(S)/keystone
I = $(SRC_DIR)/include
CFLAGS += -I$(I)

$(O)/keystone_aes.o: $(KEYSTONE_RT_SRC)/crypto/aes.c
	@echo "compiling keystone_aes.o"
	mkdir -p $(O)
	$(CC) $(CFLAGS) $(KEYSTONE_FLAGS) -c -o $(O)/keystone_aes.o $(KEYSTONE_RT_SRC)/crypto/aes.c

$(O)/keystone_api.o: $(SEV_S)/keystone_api.cc
	@echo "compiling keystone_api.cc"
	mkdir -p $(O)
	$(CC) $(CFLAGS) -c -o $(O)/keystone_api.o $(SEV_S)/keystone_api.cc

# TODO: maybe fix?
$(O)/example_app.o: ./example_app.cc
	@echo "compiling example_app.cc"
	mkdir -p $(O)
	$(CC) $(CFLAGS) -c -o $(O)/example_app.o ./example_app.cc

internal-dobj = $(O)/keystone_api.o $(O)/keystone_aes.o $(O)/example_app.o
dobj = certifier.a $(internal-dobj) # TODO: maybe move certifier library mix-in to $(LDFLAGS)

# TODO: maybe fix?
keystone_certifier_app: $(dobj) $(KEYSTONE_SDK_LIB)
	@echo "linking executable files"
	$(LINK) -o $(EXE_DIR)/keystone_certifier_app $(dobj) $(LDFLAGS)

clean:
	rm -f $(internal-dobj) $(EXE_DIR)/keystone_certifier_app $(O)/dummy_main.o $(EXE_DIR)/keystone_api

# testing Keystone compilation & linking only
keystone_api: $(O)/keystone_api.o $(O)/keystone_aes.o $(KEYSTONE_SDK_LIB)
	@echo "testing linking into keystone_api"
	echo "int main(int argc, char** argv) { return 0; }" >> $(O)/dummy_main.c
	$(CC) $(CFLAGS) -c -o $(O)/dummy_main.o $(O)/dummy_main.c
	rm $(O)/dummy_main.c
	$(LINK) -o $(EXE_DIR)/keystone_api $(O)/dummy_main.o $(O)/keystone_api.o $(O)/keystone_aes.o $(LDFLAGS)
	rm $(O)/dummy_main.o $(EXE_DIR)/keystone_api
	@echo "KEYSTONE LINK TEST SUCCESS"
