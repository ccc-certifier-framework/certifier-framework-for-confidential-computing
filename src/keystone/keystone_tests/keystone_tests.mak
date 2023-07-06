# any is fine
CC = g++
LINK = g++
CFLAGS = -Wall -fno-builtin
LDFLAGS = -static

ifdef KEYSTONE_ROOT_DIR
    CFLAGS += -I$(KEYSTONE_ROOT_DIR)/sdk/build64/include -DKEYSTONE_PRESENT
else
    ifdef KEYSTONE_SDK_DIR
        CFLAGS += -I$(KEYSTONE_SDK_DIR)/include -DKEYSTONE_PRESENT
    endif
endif

# Example app building
ifndef SRC_DIR
    SRC_DIR = ../../..
endif
ifndef OBJ_DIR
    OBJ_DIR = ./build
endif
ifndef EXE_DIR
    EXE_DIR = OBJ_DIR
endif

# TODO: add flags for linking in rest of certifier
S = $(SRC_DIR)/src
O = $(OBJ_DIR)
SEV_S = $(S)/keystone
I = $(SRC_DIR)/include
CFLAGS += -I$(I) -I$(SEV_S) # TODO: rework -I$(SEV_S)
LDFLAGS +=

$(O)/keystone_aes.o: $(KEYSTONE_RT_SRC)/crypto/aes.c
	@echo "compiling keystone_aes.o"
	mkdir -p $(O)
	$(CC) $(CFLAGS) $(KEYSTONE_FLAGS) -c -o $(O)/keystone_aes.o $(KEYSTONE_RT_SRC)/crypto/aes.c

$(O)/keystone_api.o: $(SEV_S)/keystone_api.cc
	@echo "compiling keystone_api.cc"
	mkdir -p $(O)
	$(CC) $(CFLAGS) -c -o $(O)/keystone_api.o $(SEV_S)/keystone_api.cc

# TODO: maybe fix?
$(O)/keystone_test.o: ./keystone_test.cc
	@echo "compiling keystone_test.cc"
	mkdir -p $(O)
	$(CC) $(CFLAGS) -c -o $(O)/keystone_test.o ./keystone_test.cc

internal-dobj = $(O)/keystone_api.o $(O)/keystone_aes.o $(O)/keystone_test.o
dobj = certifier.a $(internal-dobj) # TODO: maybe move certifier library mix-in to $(LDFLAGS)

# TODO: maybe fix?
tests: $(dobj) $(KEYSTONE_SDK_LIB)
	@echo "linking executable $@"
	$(LINK) -o $(EXE_DIR)/tests $(dobj) $(LDFLAGS)

# uses keystone_api and not certifier
tests_bare: $(internal-dobj) $(KEYSTONE_SDK_LIB)
	@echo "linking executable $@"
	$(LINK) -o $(EXE_DIR)/tests_bare $(internal-dobj) $(LDFLAGS)

# does not use keystone
$(O)/keystone_shim.o: ./keystone_shim.cc
	@echo "compiling keystone_shim.cc"
	mkdir -p $(O)
	$(CC) $(CFLAGS) -c -o $(O)/keystone_shim.o ./keystone_shim.cc

shim-dobj = $(O)/keystone_shim.o $(O)/keystone_test.o

tests_bare_shim: $(shim-dobj)
	@echo "linking executable $@"
	$(LINK) -o ./tests_bare_shim $(shim-dobj) $(LDFLAGS)

clean:
	rm -f $(internal-dobj) $(shim-dobj) $(EXE_DIR)/tests $(EXE_DIR)/tests_bare $(EXE_DIR)/tests_bare_shim
