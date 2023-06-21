#
# certifier_service/ccalib/Makefile
#

LOCAL_LIB=/usr/local/lib

CERTIFIER_ROOT = ../..
CERTIFIER_INCLUDE = -I . -I $(CERTIFIER_ROOT)/include -I $(CERTIFIER_ROOT)/src/cca
CERTIFIER_CFLAGS = $(CERTIFIER_INCLUDE)
CERTIFIER_LDFLAGS =
CERTIFIER_LDFLAGS += -L /usr/local/opt/openssl@1.1/lib/ -lcrypto -lssl

ISLET_PATH = $(CERTIFIER_ROOT)/third_party/islet
ISLET_INCLUDE = -I $(ISLET_PATH)/include
ISLET_LDFLAGS = -L $(ISLET_PATH)/lib -lislet_sdk

CFLAGS += $(CERTIFIER_CFLAGS) $(ISLET_INCLUDE)
CFLAGS += -g -Wall -Wno-unused-variable -Werror
LDFLAGS=
LDFLAGS += -ldl -L $(LOCAL_LIB) -lprotobuf -lgtest -lgflags -pthread $(CERTIFIER_LDFLAGS) $(ISLET_LDFLAGS)

CCAVERIFYLIB = libccaverify.so

.PHONY: all build dummy clean

all: build

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	$(CXX) -fPIC -c $(CFLAGS) cca_verify.cc
	$(CXX) -fPIC -c $(CFLAGS) $(CERTIFIER_ROOT)/src/cca/cca_shim.cc
	$(CXX) -fPIC -c $(CFLAGS) -Wno-deprecated-declarations $(CERTIFIER_ROOT)/src/support.cc
	$(CXX) -shared -o $(CCAVERIFYLIB) cca_verify.o cca_shim.o support.o $(LDFLAGS)

dummy:
	@ echo "Compilers used: $(CC), $(CXX)"
	$(CXX) -fPIC -c cca_verify_dummy.cc
	$(CXX) -shared -o $(CCAVERIFYLIB) cca_verify_dummy.o

clean:
	rm -f *.o $(CCAVERIFYLIB)
