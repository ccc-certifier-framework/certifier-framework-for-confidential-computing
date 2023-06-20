GRAMINE_SRC_PATH = ../../../gramine/gramine
SGX_INCLUDE = -I$(GRAMINE_SRC_PATH)/pal/src/host/linux-sgx
SGX_LDFLAGS = -Wl,--enable-new-dtags $(shell pkg-config --libs sgx_util)
CERTIFIER_SRC_PATH = ../../
CERTIFIER_INCLUDE = -I. -I$(CERTIFIER_SRC_PATH)/include -I$(CERTIFIER_SRC_PATH)/src/gramine $(SGX_INCLUDE) -I./mbedtls/include
CERTIFIER_CFLAGS = $(CERTIFIER_INCLUDE) -DGRAMINE_CERTIFIER
CERTIFIER_LDFLAGS = -lssl -lcrypto
CERTIFIER_LDFLAGS += -L./ -L/usr/local/lib
CERTIFIER_LDFLAGS += `pkg-config --cflags --libs protobuf`
CERTIFIER_LDFLAGS += $(shell pkg-config --libs mbedtls_gramine)

CFLAGS += $(CERTIFIER_CFLAGS)
LDFLAGS=
LDFLAGS += -Wl,--enable-new-dtags $(shell pkg-config --libs mbedtls_gramine) -L/usrl/local/lib -ldl $(CERTIFIER_LDFLAGS) $(SGX_LDFLAGS)

.PHONY: all build dummy clean

all: build

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	$(CXX)  -g -fPIC -c $(CFLAGS) gramine_verify.cc
	$(CXX)  -g -fPIC -c $(CFLAGS) $(CERTIFIER_SRC_PATH)/src/gramine/gramine_api_impl.cc
	$(CXX) -shared -o libgramineverify.so gramine_verify.o gramine_api_impl.o $(LDFLAGS)

dummy:
	@ echo "Compilers used: $(CC), $(CXX)"
	$(CXX)  -g -fPIC -c gramine_verify_dummy.cc
	$(CXX) -shared -o libgramineverify.so gramine_verify_dummy.o

clean:
	rm -f libgramineverify.so *.o

distclean:
	rm -r mbedtls/ *.tar.gz
