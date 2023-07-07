#
# certifier_service/isletlib/Makefile
#

LOCAL_LIB=/usr/local/lib
PROTO=protoc

# CERTIFIER_ROOT will be certifier-framework-for-confidential-computing/ dir
CERTIFIER_ROOT = ../..

CERTIFIER_INCLUDE = -I . -I $(CERTIFIER_ROOT)/include -I $(CERTIFIER_ROOT)/src/islet
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

ISLET_VERIFY_LIB = libisletverify.so

CP = $(CERTIFIER_ROOT)/certifier_service/certprotos

CS = $(CERTIFIER_ROOT)/src
ISLET_S = $(CERTIFIER_ROOT)/src/islet
S = $(CERTIFIER_ROOT)/certifier_service/isletlib

OBJ_DIR = .
O = $(OBJ_DIR)
I = $(CERTIFIER_ROOT)/include

dobj = $(O)/certifier.pb.o $(O)/islet_verify.o $(O)/islet_shim.o $(O)/support.o

.PHONY: all build dummy clean

all: build

build: $(ISLET_VERIFY_LIB)
	@echo " \nCompilers used: $(CC), $(CXX). Linking $<"
	$(CXX) -shared -o $(ISLET_VERIFY_LIB) $(dobj) $(LDFLAGS)

$(ISLET_VERIFY_LIB): $(dobj)

$(I)/certifier.pb.h: $(S)/certifier.pb.cc
$(S)/certifier.pb.cc: $(CP)/certifier.proto
	@echo "\nGenerate protobuf files"
	$(PROTO) --proto_path=$(CP) --cpp_out=$(S) $<
	mv $(S)/certifier.pb.h $(I)

$(O)/certifier.pb.o: $(S)/certifier.pb.cc $(I)/certifier.pb.h
	@echo " \nCompiling $<"
	$(CC) -fPIC $(CFLAGS) -Wno-array-bounds -c $< -o $@

$(O)/islet_verify.o: $(S)/islet_verify.cc
	@ echo " \nCompiling $<"
	$(CXX) -fPIC $(CFLAGS) -c $< -o $@

$(O)/islet_shim.o: $(ISLET_S)/islet_shim.cc
	@ echo " \nCompiling $<"
	$(CXX) -fPIC $(CFLAGS) -c $< -o $@

$(O)/support.o: $(CS)/support.cc
	@ echo " \nCompiling $<"
	$(CXX) -fPIC $(CFLAGS) -Wno-deprecated-declarations -c $< -o $@

dummy:
	@ echo " \nCompilers used: $(CC), $(CXX)"
	$(CXX) -fPIC -c islet_verify_dummy.cc
	$(CXX) -shared -o $(ISLET_VERIFY_LIB) islet_verify_dummy.o

clean:
	@echo "Removing generated files"
	rm -rf $(I)/certifier.pb.h $(S)/certifier.pb.h $(S)/certifier.pb.cc
	rm -rf *.o $(ISLET_VERIFY_LIB)
