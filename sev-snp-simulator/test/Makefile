SOURCE_DIR := .
SOURCES    := $(shell find $(SOURCE_DIR) -name "*.c")
OBJECTS    := $(SOURCES:.c=.o)

CC              := gcc
CFLAGS          := -g -Wall -Werror -O0 -I ./include -I/usr/local/include -I/usr/include
OPENSSL_LDFLAGS := -L/usr/local/lib64/ -lssl -lcrypto
UUID_LDFLAGS    := -luuid
OPENSSL         := openssl

TARGETS := sev-test

all: $(TARGETS)

sev-test: sev-test.o sev-ecdsa.o report.o
	$(CC) $(CFLAGS) -DPROG_NAME=$@ -o $@ $^ $(OPENSSL_LDFLAGS)

sev-keys:
	$(OPENSSL) ecparam -name secp384r1 -genkey -noout -out ec-secp384r1-priv-key.pem
	$(OPENSSL) ec -in ec-secp384r1-priv-key.pem -pubout > ec-secp384r1-pub-key.pem

clean:
	$(RM) $(TARGETS) $(OBJECTS) cscope.*

cleanall: clean
	$(RM) *.pem
