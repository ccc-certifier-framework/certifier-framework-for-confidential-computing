include config.mk

CFLAGS=$(shell pkg-config tpmhostverify-$(COMPILER) --cflags) -std=c++17
LDFLAGS=$(shell pkg-config tpmhostverify-$(COMPILER) --libs)
CFLAGS += -Wno-strict-aliasing

.PHONY: all build dummy clean

all: build

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	$(CXX)  -g -fPIC -c $(CFLAGS) -I../../include -I../../src/tpm2 tpmverify.c
	$(CXX) -shared -o libtpmverify.so tpmverify.o $(LDFLAGS)

dummy:
	@ echo "Compilers used: $(CC), $(CXX)"
	$(CXX)  -g -fPIC -c tpmverify_dummy.c
	$(CXX) -shared -o libtpmverify.so tpmverify_dummy.o

clean:
	rm -f libtpmverify.so *.o
