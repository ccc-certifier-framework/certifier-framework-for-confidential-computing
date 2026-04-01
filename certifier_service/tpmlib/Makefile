include config.mk

CFLAGS=$(shell pkg-config tpmhostverify-$(COMPILER) --cflags)
LDFLAGS=$(shell pkg-config tpmhostverify-$(COMPILER) --libs)

.PHONY: all build dummy clean

all: build

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	$(CC)  -g -fPIC -c $(CFLAGS) tpmverify.c
	$(CC) -shared -o libtpmverify.so tpmverify.o $(LDFLAGS)

dummy:
	@ echo "Compilers used: $(CC), $(CXX)"
	$(CC)  -g -fPIC -c tpmverify_dummy.c
	$(CC) -shared -o libtpmverify.so tpmverify_dummy.o

clean:
	rm -f libtpmverify.so *.o
