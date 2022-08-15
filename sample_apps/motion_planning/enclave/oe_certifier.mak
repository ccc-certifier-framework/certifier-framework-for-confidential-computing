#
#    File: oe_certifier.mak


ifndef SRC_DIR
SRC_DIR=..
endif
ifndef OBJ_DIR
OBJ_DIR=.
endif
ifndef EXE_DIR
EXE_DIR=.
endif
#ifndef GOOGLE_INCLUDE
#GOOGLE_INCLUDE=/usr/local/include/g
#endif
ifndef LOCAL_LIB
LOCAL_LIB=/usr/local/lib
endif
ifndef TARGET_MACHINE_TYPE
TARGET_MACHINE_TYPE= x64
endif


S= $(SRC_DIR)
O= $(OBJ_DIR)
INCLUDE=-I/usr/local/opt/openssl@1.1/include/ -I../

CFLAGS=$(INCLUDE) -O3 -g -Wall -std=c++11 -Wno-unused-variable -D X64
CFLAGS1=$(INCLUDE) -O1 -g -Wall -std=c++11 -Wno-unused-variable -D X64
CC=g++
LINK=g++
PROTO=protoc
AR=ar
#export LD_LIBRARY_PATH=/usr/local/lib
LDFLAGS= -lprotobuf -lpthread -L/usr/local/opt/openssl@1.1/lib/ -lcrypto -lssl

dobj=	$(O)/oe_certifier.o $(O)/certifier.pb.o $(O)/certifier.o $(O)/support.o


all:	oe_certifier.exe
clean:
	@echo "removing object files"
	rm $(O)/*.o
	@echo "removing executable file"
	rm $(EXE_DIR)/oe_certifier.exe

oe_certifier.exe: $(dobj) 
	@echo "linking executable files"
	$(LINK) -o $(EXE_DIR)/oe_certifier.exe $(dobj) $(LDFLAGS)

certifier.pb.cc certifier.pb.h: $(S)/certifier.proto
	$(PROTO) -I$(S) --cpp_out=. $(S)/certifier.proto

$(O)/oe_certifier.o: oe_certifier.cc certifier.pb.h $(S)/certifier.h
	@echo "compiling certifier_tests.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/oe_certifier.o oe_certifier.cc

$(O)/certifier.pb.o: certifier.pb.cc certifier.pb.h
	@echo "compiling certifier.pb.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/certifier.pb.o certifier.pb.cc

$(O)/certifier.o: $(S)/certifier.cc certifier.pb.h $(S)/certifier.h
	@echo "compiling certifier.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/certifier.o $(S)/certifier.cc

$(O)/support.o: $(S)/support.cc $(S)/support.h
	@echo "compiling support.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/support.o $(S)/support.cc
