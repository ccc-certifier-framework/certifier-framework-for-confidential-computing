#
# certifier_service/ccalib/Makefile
#

CERTIFIER_SRC_PATH = ../../
CERTIFIER_INCLUDE = -I . -I $(CERTIFIER_SRC_PATH)/include -I $(CERTIFIER_SRC_PATH)/src/cca
CERTIFIER_CFLAGS = $(CERTIFIER_INCLUDE)
CERTIFIER_LDFLAGS = -lssl -lcrypto
CERTIFIER_LDFLAGS += -L./ -L/usr/local/lib
CERTIFIER_LDFLAGS += `pkg-config --cflags --libs protobuf`

CFLAGS += $(CERTIFIER_CFLAGS)
LDFLAGS=
LDFLAGS += -Wl,--enable-new-dtags -L /usrl/local/lib -ldl $(CERTIFIER_LDFLAGS)

.PHONY: all build dummy clean

all: build

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	$(CXX)  -g -fPIC -c $(CFLAGS) gramine_verify.cc
	$(CXX)  -g -fPIC -c $(CFLAGS) $(CERTIFIER_SRC_PATH)/src/gramine/gramine_api_impl.cc
	$(CXX) -shared -o libgramineverify.so gramine_verify.o gramine_api_impl.o $(LDFLAGS)

dummy:
	@ echo "Compilers used: $(CC), $(CXX)"
	$(CXX)  -g -fPIC -c cca_verify_dummy.cc
	$(CXX) -shared -o libccaverify.so cca_verify_dummy.o

clean:
	rm -f libccaverify.so *.o
