#
# certifier_service/ccalib/Makefile
#

CERTIFIER_ROOT = ../..
CERTIFIER_INCLUDE = -I . -I $(CERTIFIER_ROOT)/include -I $(CERTIFIER_ROOT)/src/cca
CERTIFIER_CFLAGS = $(CERTIFIER_INCLUDE)
CERTIFIER_LDFLAGS = -lssl -lcrypto
CERTIFIER_LDFLAGS += -L./ -L/usr/local/lib
CERTIFIER_LDFLAGS += `pkg-config --cflags --libs protobuf`

ISLET_PATH = $(CERTIFIER_ROOT)/third_party/islet
ISLET_INCLUDE = -I $(ISLET_PATH)/include

CFLAGS += $(CERTIFIER_CFLAGS) $(ISLET_INCLUDE)
CFLAGS += -g -Wall -Wno-unused-variable -Werror
LDFLAGS=
LDFLAGS += -Wl,--enable-new-dtags -L /usrl/local/lib -ldl $(CERTIFIER_LDFLAGS)

CCAVERIFYLIB = libccaverify.so

.PHONY: all build dummy clean

all: build

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	$(CXX) -fPIC -c $(CFLAGS) cca_verify.cc
	$(CXX) -fPIC -c $(CFLAGS) $(CERTIFIER_ROOT)/src/cca/cca_shim.cc
	$(CXX) -shared -o $(CCAVERIFYLIB) cca_verify.o cca_shim.o $(LDFLAGS)

dummy:
	@ echo "Compilers used: $(CC), $(CXX)"
	$(CXX) -fPIC -c cca_verify_dummy.cc
	$(CXX) -shared -o $(CCAVERIFYLIB) cca_verify_dummy.o

clean:
	rm -f *.o $(CCAVERIFYLIB)
