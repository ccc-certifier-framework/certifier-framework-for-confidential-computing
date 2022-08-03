#    
#    File: cert_utility.mak


ifndef SRC_DIR
SRC_DIR=..
endif
ifndef OBJ_DIR
OBJ_DIR=.
endif
ifndef EXE_DIR
EXE_DIR=.
endif
ifndef INC_DIR
INC_DIR=../include
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
I= $(INC_DIR)
US= .
INCLUDE= -I$(I) -I/usr/local/opt/openssl@1.1/include/

CFLAGS= $(INCLUDE) -O3 -g -Wall -std=c++11 -Wno-unused-variable -D X64
CFLAGS1= $(INCLUDE) -O1 -g -Wall -std=c++11 -Wno-unused-variable -D X64
CC=g++
LINK=g++
# PROTO=/usr/local/bin/protoc
# Point this to the right place, if you have to.
# I had to do the above on my machine.
PROTO=protoc
AR=ar
#export LD_LIBRARY_PATH=/usr/local/lib
LDFLAGS= -L $(LOCAL_LIB) -lprotobuf -lgtest -lgflags -lpthread -L/usr/local/opt/openssl@1.1/lib/ -lcrypto -lssl

dobj=	$(O)/cert_utility.o $(O)/certifier.pb.o $(O)/support.o $(O)/certifier.o \
$(O)/simulated_enclave.o $(O)/application_enclave.o


all:	cert_utility.exe measurement_init.exe
clean:
	@echo "removing object files"
	rm $(O)/*.o
	@echo "removing executable file"
	rm $(EXE_DIR)/cert_utility.exe

cert_utility.exe: $(dobj) 
	@echo "linking executable files"
	$(LINK) -o $(EXE_DIR)/cert_utility.exe $(dobj) $(LDFLAGS)

measurement_init.exe: $(O)/measurement_init.o
	@echo "linking executable files"
	$(LINK) -o $(EXE_DIR)/measurement_init.exe $(O)/measurement_init.o $(LDFLAGS)

$(O)/measurement_init.o: $(US)/measurement_init.cc
	@echo "compiling measurement_init.cc"
	$(CC) $(CFLAGS) -c -o $(O)/measurement_init.o $(US)/measurement_init.cc

$(O)/cert_utility.o: $(US)/cert_utility.cc $(I)/support.h $(I)/certifier.pb.h
	@echo "compiling cert_utility.cc"
	$(CC) $(CFLAGS) -c -o $(O)/cert_utility.o $(US)/cert_utility.cc

$(US)/certifier.pb.cc $(I)/certifier.pb.h: $(S)/certifier.proto
	$(PROTO) -I$(S) --cpp_out=$(US) $(S)/certifier.proto
	mv certifier.pb.h $(I)

$(O)/certifier.pb.o: $(US)/certifier.pb.cc $(I)/certifier.pb.h
	@echo "compiling certifier.pb.cc"
	$(CC) $(CFLAGS) -c  -o $(O)/certifier.pb.o $(US)/certifier.pb.cc

$(O)/support.o: $(S)/support.cc $(I)/support.h $(I)/certifier.pb.h
	@echo "compiling support.cc"
	$(CC) $(CFLAGS) -c -o $(O)/support.o $(S)/support.cc

$(O)/certifier.o: $(S)/certifier.cc $(I)/certifier.pb.h $(I)/certifier.h
	@echo "compiling certifier.cc"
	$(CC) $(CFLAGS) -c -o $(O)/certifier.o $(S)/certifier.cc

$(O)/simulated_enclave.o: $(S)/simulated_enclave.cc $(I)/simulated_enclave.h
	@echo "compiling simulated_enclave.cc"
	$(CC) $(CFLAGS) -c -o $(O)/simulated_enclave.o $(S)/simulated_enclave.cc

$(O)/application_enclave.o: $(S)/application_enclave.cc $(I)/application_enclave.h
	@echo "compiling application_enclave.cc"
	$(CC) $(CFLAGS) -c -o $(O)/application_enclave.o $(S)/application_enclave.cc
