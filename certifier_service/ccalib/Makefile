#
# certifier_service/ccalib/Makefile
#

LOCAL_LIB=/usr/local/lib
PROTO=protoc

# CERTIFIER_ROOT will be certifier-framework-for-confidential-computing/ dir
CERTIFIER_ROOT = ../..

CERTIFIER_INCLUDE = -I . -I $(CERTIFIER_ROOT)/include -I $(CERTIFIER_ROOT)/src/cca
CERTIFIER_CFLAGS = $(CERTIFIER_INCLUDE)
CERTIFIER_LDFLAGS =
CERTIFIER_LDFLAGS += -lcrypto -lssl

ISLET_PATH = $(CERTIFIER_ROOT)/third_party/islet
ISLET_INCLUDE = -I $(ISLET_PATH)/include
ISLET_LDFLAGS = -L $(ISLET_PATH)/lib -ldl -lislet_sdk

CFLAGS += $(CERTIFIER_CFLAGS) $(ISLET_INCLUDE)
CFLAGS += -g -Wall -Wno-unused-variable -Werror
LDFLAGS=
LDFLAGS += -L $(LOCAL_LIB) -ldl -lprotobuf -lgtest -lgflags -pthread $(CERTIFIER_LDFLAGS) $(ISLET_LDFLAGS)

CCAVERIFYLIB = libccaverify.so

CS = $(CERTIFIER_ROOT)/src
CCAS = $(CERTIFIER_ROOT)/src/cca
S = $(CERTIFIER_ROOT)/certifier_service/ccalib

OBJ_DIR = .
O = $(OBJ_DIR)
I = $(CERTIFIER_ROOT)/include

dobj = $(O)/certifier.pb.o $(O)/cca_verify.o $(O)/cca_shim.o $(O)/support.o

.PHONY: all build dummy clean

all: build

build: $(CCAVERIFYLIB)
	@echo " \nCompilers used: $(CC), $(CXX). Linking $<"
	$(CXX) -shared -o $(CCAVERIFYLIB) $(dobj) $(LDFLAGS)

$(CCAVERIFYLIB): $(dobj)

$(O)/certifier.pb.o: $(CS)/certifier.pb.cc $(I)/certifier.pb.h
	@echo " \nCompiling $<"
	$(CC) -fPIC $(CFLAGS) -Wno-array-bounds -c $< -o $@

$(CS)/certifier.pb.cc $(I)/certifier.pb.h: $(CS)/certifier.proto
	@echo "\nGenerate protobuf files"
	$(PROTO) --proto_path=$(CS) --cpp_out=$(CS) $<
	mv $(CS)/certifier.pb.h $(I)

$(O)/cca_verify.o: $(S)/cca_verify.cc
	@ echo " \nCompiling $<"
	$(CXX) -fPIC $(CFLAGS) -c $< -o $@

$(O)/cca_shim.o: $(CCAS)/cca_shim.cc
	@ echo " \nCompiling $<"
	$(CXX) -fPIC $(CFLAGS) -c $< -o $@

$(O)/support.o: $(CS)/support.cc
	@ echo " \nCompiling $<"
	$(CXX) -fPIC $(CFLAGS) -Wno-deprecated-declarations -c $< -o $@

dummy:
	@ echo " \nCompilers used: $(CC), $(CXX)"
	$(CXX) -fPIC -c cca_verify_dummy.cc
	$(CXX) -shared -o $(CCAVERIFYLIB) cca_verify_dummy.o

clean:
	@echo "Removing generated files"
	rm -rf $(I)/certifier.pb.h $(CS)/certifier.pb.cc
	rm -rf *.o $(CCAVERIFYLIB)
