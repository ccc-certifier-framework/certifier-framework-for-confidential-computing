#
# certifier_service/ccalib/Makefile
#

LOCAL_LIB=/usr/local/lib

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

dobj = $(O)/cca_verify.o $(O)/cca_shim.o $(O)/support.o

.PHONY: all build dummy clean

all: build

build: $(CCAVERIFYLIB)
	@ echo "Compilers used: $(CC), $(CXX)"
	$(CXX) -shared -o $(CCAVERIFYLIB) $(dobj) $(LDFLAGS)

$(CCAVERIFYLIB): $(dobj)
$(O)/cca_verify.o: $(S)/cca_verify.cc
	@ echo "Compiling $<"
	$(CXX) -fPIC $(CFLAGS) -c $< -o $@

$(O)/cca_shim.o: $(CCAS)/cca_shim.cc
	@ echo "Compiling $<"
	$(CXX) -fPIC $(CFLAGS) -c $< -o $@

$(O)/support.o: $(CS)/support.cc
	@ echo "Compiling $<"
	$(CXX) -fPIC $(CFLAGS) -Wno-deprecated-declarations -c $< -o $@

dummy:
	@ echo "Compilers used: $(CC), $(CXX)"
	$(CXX) -fPIC -c cca_verify_dummy.cc
	$(CXX) -shared -o $(CCAVERIFYLIB) cca_verify_dummy.o

clean:
	rm -f *.o $(CCAVERIFYLIB)
