include config.mk

CFLAGS=$(shell pkg-config oehostverify-$(COMPILER) --cflags)
LDFLAGS=$(shell pkg-config oehostverify-$(COMPILER) --libs)

.PHONY: all build clean

all: build

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	$(CC)  -g -fPIC -c $(CFLAGS) oeverify.c
	$(CC) -shared -o liboeverify.so oeverify.o $(LDFLAGS)

clean:
	rm -f liboeverify.so oeverify.o
