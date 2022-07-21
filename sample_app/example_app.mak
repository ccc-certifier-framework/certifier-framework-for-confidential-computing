#    
#    File: example_app.mak


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


S= $(SRC_DIR)/src
O= $(OBJ_DIR)
US= .
I= $(SRC_DIR)/include
INCLUDE= -I$(I) -I/usr/local/opt/openssl@1.1/include/

CFLAGS=$(INCLUDE) -O3 -g -Wall -std=c++11 -Wno-unused-variable -D X64
CFLAGS1=$(INCLUDE) -O1 -g -Wall -std=c++11 -Wno-unused-variable -D X64
CC=g++
LINK=g++
PROTO=/usr/local/bin/protoc
AR=ar
#export LD_LIBRARY_PATH=/usr/local/lib
LDFLAGS= -L $(LOCAL_LIB) -lprotobuf -lgtest -lgflags -lpthread -L/usr/local/opt/openssl@1.1/lib/ -lcrypto -lssl

dobj=	$(O)/example_app.o $(O)/certifier.pb.o $(O)/certifier.o $(O)/support.o \
$(O)/simulated_enclave.o $(O)/application_enclave.o


all:	example_app.exe
clean:
	@echo "removing object files"
	rm $(O)/*.o
	@echo "removing executable file"
	rm $(EXE_DIR)/example_app.exe

example_app.exe: $(dobj) 
	@echo "linking executable files"
	$(LINK) -o $(EXE_DIR)/example_app.exe $(dobj) $(LDFLAGS)

$(S)/certifier.pb.cc $(S)/certifier.pb.h: $(S)/certifier.proto
	$(PROTO) -I$(I) --cpp_out=$(S) $(S)/certifier.proto
	mv certifier.pb.h $(I)

$(O)/example_app.o: $(US)/example_app.cc $(I)/certifier.pb.h $(I)/certifier.h
	@echo "compiling example_app.cc"
	$(CC) $(CFLAGS) -c -o $(O)/example_app.o $(US)/example_app.cc

$(O)/certifier.pb.o: $(S)/certifier.pb.cc $(I)/certifier.pb.h
	@echo "compiling certifier.pb.cc"
	$(CC) $(CFLAGS) -c -o $(O)/certifier.pb.o $(S)/certifier.pb.cc

$(O)/certifier.o: $(S)/certifier.cc $(I)/certifier.pb.h $(I)/certifier.h
	@echo "compiling certifier.cc"
	$(CC) $(CFLAGS) -c -o $(O)/certifier.o $(S)/certifier.cc

$(O)/support.o: $(S)/support.cc $(I)/support.h
	@echo "compiling support.cc"
	$(CC) $(CFLAGS) -c -o $(O)/support.o $(S)/support.cc

$(O)/simulated_enclave.o: $(S)/simulated_enclave.cc $(I)/simulated_enclave.h
	@echo "compiling simulated_enclave.cc"
	$(CC) $(CFLAGS) -c -o $(O)/simulated_enclave.o $(S)/simulated_enclave.cc

$(O)/application_enclave.o: $(S)/application_enclave.cc $(I)/application_enclave.h
	@echo "compiling application_enclave.cc"
	$(CC) $(CFLAGS) -c -o $(O)/application_enclave.o $(S)/application_enclave.cc
