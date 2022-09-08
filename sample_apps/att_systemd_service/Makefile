LOCAL_LIB=/usr/local/lib

ifndef TARGET_MACHINE_TYPE
TARGET_MACHINE_TYPE= x64
endif

# Change the CERTIFIER_* variables to point to your Certifier installation destination
CERTIFIER_LIB=../../
CERTIFIER_INCLUDE=../../include
INCLUDE=-I/usr/local/opt/openssl@1.1/include/ -I$(CERTIFIER_INCLUDE)

CFLAGS=$(INCLUDE) -O3 -g -Wall -std=c++11 -Wno-unused-variable -D X64 -D SEV_SNP

CC=g++
LINK=g++
PROTO=protoc
LDFLAGS= -L $(LOCAL_LIB) -lprotobuf -lgtest -lgflags -lpthread -L/usr/local/opt/openssl@1.1/lib/ -lcrypto -lssl

dobj=	attsvc.o

all:	attsvc
clean:
	@echo "removing object files"
	rm ./*.o
	@echo "removing executable file"
	rm attsvc

attsvc: $(dobj)
	@echo "linking executable files"
	$(LINK) -o attsvc $(dobj) $(CERTIFIER_LIB)/certifier.a $(LDFLAGS)

policy_key.cc:
	cert_utility.exe --operation=generate-policy-key-and-test-keys \
	--policy_key_output_file=policy_key_file.bin --policy_cert_output_file=policy_cert_file.bin \
	--platform_key_output_file=platform_key_file.bin --attest_key_output_file=attest_key_file.bin
	embed_policy_key.exe --input=policy_cert_file.bin --output=policy_key.cc

attsvc.o: attsvc.cc $(CERTIFIER_INCLUDE)/certifier.pb.h $(CERTIFIER_INCLUDE)/certifier.h policy_key.cc
	@echo "compiling attsvc.cc"
	$(CC) $(CFLAGS) -c -o attsvc.o attsvc.cc
