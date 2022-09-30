#    
#    File: policy_utillities.mak

ifndef CERTIFIER_PROTOTYPE_DIR
CERTIFIER_PROTOTYPE_DIR=..
endif
ifndef SRC_DIR
SRC_DIR=$(CERTIFIER_PROTOTYPE_DIR)/utilities
endif
ifndef INC_DIR
INC_DIR=$(CERTIFIER_PROTOTYPE_DIR)/include
endif
ifndef OBJ_DIR
OBJ_DIR=.
endif
ifndef EXE_DIR
EXE_DIR=.
endif

#ifndef GOOGLE_INCLUDE
#GOOGLE_INCLUDE=/usr/local/include/google
#endif

LOCAL_LIB=/usr/local/lib

ifndef TARGET_MACHINE_TYPE
TARGET_MACHINE_TYPE= x64
endif

S= $(SRC_DIR)
CERT_SRC=$(CERTIFIER_PROTOTYPE_DIR)/src
O= $(OBJ_DIR)
INCLUDE= -I$(INC_DIR) -I/usr/local/opt/openssl@1.1/include/

CFLAGS= $(INCLUDE) -O3 -g -Wall -std=c++11 -Wno-unused-variable -D X64 
CFLAGS1= $(INCLUDE) -O1 -g -Wall -std=c++11 -Wno-unused-variable -D X64

CC=g++
LINK=g++
#PROTO=/usr/local/bin/protoc
# Point this to the right place, if you have to.
# I had to do the above on my machine.
PROTO=protoc
AR=ar
#export LD_LIBRARY_PATH=/usr/local/lib
LDFLAGS= -L $(LOCAL_LIB) -lprotobuf -lgtest -lgflags -lpthread -L/usr/local/opt/openssl@1.1/lib/ -lcrypto -lssl


measurement_utility_obj=$(O)/measurement_utility.o $(O)/support.o $(O)/certifier.o $(O)/certifier.pb.o \
$(O)/simulated_enclave.o $(O)/application_enclave.o
make_indirect_vse_clause_obj= $(O)/make_indirect_vse_clause.o $(O)/support.o $(O)/certifier.o \
$(O)/certifier.pb.o $(O)/simulated_enclave.o $(O)/application_enclave.o
make_simple_vse_clause_obj= $(O)/make_simple_vse_clause.o $(O)/support.o $(O)/certifier.o \
$(O)/certifier.pb.o $(O)/simulated_enclave.o $(O)/application_enclave.o
make_unary_vse_clause_obj= $(O)/make_unary_vse_clause.o $(O)/support.o $(O)/certifier.o \
$(O)/certifier.pb.o $(O)/simulated_enclave.o $(O)/application_enclave.o
make_signed_claim_from_vse_clause_obj= $(O)/make_signed_claim_from_vse_clause.o $(O)/support.o \
$(O)/certifier.o $(O)/certifier.pb.o $(O)/simulated_enclave.o $(O)/application_enclave.o
print_vse_clause_obj= $(O)/print_vse_clause.o $(O)/support.o $(O)/certifier.o $(O)/certifier.pb.o \
$(O)/simulated_enclave.o $(O)/application_enclave.o
print_signed_claim_obj= $(O)/print_signed_claim.o $(O)/support.o $(O)/certifier.o $(O)/certifier.pb.o \
$(O)/simulated_enclave.o $(O)/application_enclave.o
package_claims_obj= $(O)/package_claims.o $(O)/support.o $(O)/certifier.o $(O)/certifier.pb.o \
$(O)/simulated_enclave.o $(O)/application_enclave.o
print_packaged_claims_obj= $(O)/print_packaged_claims.o $(O)/support.o $(O)/certifier.o \
$(O)/certifier.pb.o $(O)/simulated_enclave.o $(O)/application_enclave.o
embed_policy_key_obj=$(O)/embed_policy_key.o
appoint_platform_obj= $(O)/appoint_platform.o $(O)/support.o \
$(O)/certifier.o $(O)/certifier.pb.o $(O)/simulated_enclave.o $(O)/application_enclave.o


all:	$(EXE_DIR)/measurement_utility.exe $(EXE_DIR)/make_indirect_vse_clause.exe \
	$(EXE_DIR)/make_simple_vse_clause.exe $(EXE_DIR)/make_unary_vse_clause.exe \
	$(EXE_DIR)/make_signed_claim_from_vse_clause.exe $(EXE_DIR)/print_vse_clause.exe \
	$(EXE_DIR)/print_signed_claim.exe $(EXE_DIR)/package_claims.exe \
	$(EXE_DIR)/print_packaged_claims.exe $(EXE_DIR)/embed_policy_key.exe \
	$(EXE_DIR)/appoint_platform.exe

clean:
	@echo "removing object files"
	rm $(O)/*.o
	@echo "removing executable file"
	rm $(EXE_DIR)/*.exe

$(EXE_DIR)/measurement_utility.exe: $(measurement_utility_obj) 
	@echo "linking executable files"
	$(LINK) -o $(EXE_DIR)/measurement_utility.exe $(measurement_utility_obj) $(LDFLAGS)
#-L $(CERTIFIER_PROTOTYPE_DIR)/certifier.a

$(O)/measurement_utility.o: $(S)/measurement_utility.cc $(INC_DIR)/certifier.pb.h $(INC_DIR)/certifier.h
	@echo "compiling measurement_utility.cc"
	$(CC) $(CFLAGS) -c -o $(O)/measurement_utility.o $(S)/measurement_utility.cc

$(O)/cert_utility.o: $(US)/cert_utility.cc $(INC_DIR)/support.h $(INC_DIR)/certifier.pb.h
	@echo "compiling cert_utility.cc"
	$(CC) $(CFLAGS) -c -o $(O)/cert_utility.o $(US)/cert_utility.cc

$(O)/key_utility.o: $(US)/key_utility.cc $(INC_DIR)/support.h $(INC_DIR)/certifier.pb.h
	@echo "compiling key_utility.cc"
	$(CC) $(CFLAGS) -c -o $(O)/key_utility.o $(US)/key_utility.cc

$(O)/certifier.pb.o: $(CERT_SRC)/certifier.pb.cc $(INC_DIR)/certifier.pb.h
	@echo "compiling certifier.pb.cc"
	$(CC) $(CFLAGS) -c  -o $(O)/certifier.pb.o $(CERT_SRC)/certifier.pb.cc

$(O)/support.o: $(CERT_SRC)/support.cc $(INC_DIR)/support.h $(INC_DIR)/certifier.pb.h
	@echo "compiling support.cc"
	$(CC) $(CFLAGS) -c -o $(O)/support.o $(CERT_SRC)/support.cc

$(O)/certifier.o: $(CERT_SRC)/certifier.cc $(INC_DIR)/certifier.pb.h $(INC_DIR)/certifier.h
	@echo "compiling certifier.cc"
	$(CC) $(CFLAGS) -c -o $(O)/certifier.o $(CERT_SRC)/certifier.cc

$(O)/simulated_enclave.o: $(CERT_SRC)/simulated_enclave.cc $(INC_DIR)/simulated_enclave.h
	@echo "compiling simulated_enclave.cc"
	$(CC) $(CFLAGS) -c -o $(O)/simulated_enclave.o $(CERT_SRC)/simulated_enclave.cc

$(O)/application_enclave.o: $(CERT_SRC)/application_enclave.cc $(INC_DIR)/application_enclave.h
	@echo "compiling application_enclave.cc"
	$(CC) $(CFLAGS) -c -o $(O)/application_enclave.o $(CERT_SRC)/application_enclave.cc

$(O)/measurement_init.o: $(US)/measurement_init.cc
	@echo "compiling measurement_init.cc"
	$(CC) $(CFLAGS) -c -o $(O)/measurement_init.o $(US)/measurement_init.cc

$(O)/make_indirect_vse_clause.o: $(S)/make_indirect_vse_clause.cc $(INC_DIR)/certifier.pb.h $(INC_DIR)/certifier.h
	@echo "compiling make_indirect_vse_clause.cc"
	$(CC) $(CFLAGS) -c -o $(O)/make_indirect_vse_clause.o $(S)/make_indirect_vse_clause.cc

$(EXE_DIR)/make_indirect_vse_clause.exe: $(make_indirect_vse_clause_obj) 
	@echo "linking executable files"
	$(LINK) -o $(EXE_DIR)/make_indirect_vse_clause.exe $(make_indirect_vse_clause_obj) $(LDFLAGS)

$(O)/make_simple_vse_clause.o: $(S)/make_simple_vse_clause.cc $(INC_DIR)/certifier.pb.h $(INC_DIR)/certifier.h
	@echo "compiling make_simple_vse_clause.cc"
	$(CC) $(CFLAGS) -c -o $(O)/make_simple_vse_clause.o $(S)/make_simple_vse_clause.cc

$(EXE_DIR)/make_simple_vse_clause.exe: $(make_simple_vse_clause_obj) 
	@echo "linking executable files"
	$(LINK) -o $(EXE_DIR)/make_simple_vse_clause.exe $(make_simple_vse_clause_obj) $(LDFLAGS)

$(O)/make_unary_vse_clause.o: $(S)/make_unary_vse_clause.cc $(INC_DIR)/certifier.pb.h $(INC_DIR)/certifier.h
	@echo "compiling make_unary_vse_clause.cc"
	$(CC) $(CFLAGS) -c -o $(O)/make_unary_vse_clause.o $(S)/make_unary_vse_clause.cc

$(EXE_DIR)/make_unary_vse_clause.exe: $(make_unary_vse_clause_obj) 
	@echo "linking executable files"
	$(LINK) -o $(EXE_DIR)/make_unary_vse_clause.exe $(make_unary_vse_clause_obj) $(LDFLAGS)

$(O)/make_signed_claim_from_vse_clause.o: $(S)/make_signed_claim_from_vse_clause.cc $(INC_DIR)/certifier.pb.h $(INC_DIR)/certifier.h
	@echo "compiling make_signed_claim_from_vse_clause.cc"
	$(CC) $(CFLAGS) -c -o $(O)/make_signed_claim_from_vse_clause.o $(S)/make_signed_claim_from_vse_clause.cc

$(EXE_DIR)/make_signed_claim_from_vse_clause.exe: $(make_signed_claim_from_vse_clause_obj) 
	@echo "linking executable files"
	$(LINK) -o $(EXE_DIR)/make_signed_claim_from_vse_clause.exe $(make_signed_claim_from_vse_clause_obj) $(LDFLAGS)

# package_claims.exe print_packaged_claims.exe

$(EXE_DIR)/print_vse_clause.exe: $(print_vse_clause_obj) 
	@echo "linking executable files"
	$(LINK) -o $(EXE_DIR)/print_vse_clause.exe $(print_vse_clause_obj) $(LDFLAGS)

$(O)/print_vse_clause.o: $(S)/print_vse_clause.cc $(INC_DIR)/certifier.pb.h $(INC_DIR)/certifier.h
	@echo "compiling print_vse_clause.cc"
	$(CC) $(CFLAGS) -c -o $(O)/print_vse_clause.o $(S)/print_vse_clause.cc

$(EXE_DIR)/print_signed_claim.exe: $(print_signed_claim_obj) 
	@echo "linking executable files"
	$(LINK) -o $(EXE_DIR)/print_signed_claim.exe $(print_signed_claim_obj) $(LDFLAGS)

$(O)/print_signed_claim.o: $(S)/print_signed_claim.cc $(INC_DIR)/certifier.pb.h $(INC_DIR)/certifier.h
	@echo "compiling print_signed_claim.cc"
	$(CC) $(CFLAGS) -c -o $(O)/print_signed_claim.o $(S)/print_signed_claim.cc

$(EXE_DIR)/package_claims.exe: $(package_claims_obj) 
	@echo "linking executable files"
	$(LINK) -o $(EXE_DIR)/package_claims.exe $(package_claims_obj) $(LDFLAGS)

$(O)/package_claims.o: $(S)/package_claims.cc $(INC_DIR)/certifier.pb.h $(INC_DIR)/certifier.h
	@echo "compiling package_claims.cc"
	$(CC) $(CFLAGS) -c -o $(O)/package_claims.o $(S)/package_claims.cc

$(EXE_DIR)/print_packaged_claims.exe: $(print_packaged_claims_obj) 
	@echo "linking executable files"
	$(LINK) -o $(EXE_DIR)/print_packaged_claims.exe $(print_packaged_claims_obj) $(LDFLAGS)

print_packaged_claims.o: $(S)/print_packaged_claims.cc $(INC_DIR)/certifier.pb.h $(INC_DIR)/certifier.h
	@echo "compiling print_packaged_claims.cc"
	$(CC) $(CFLAGS) -c -o $(O)/print_packaged_claims.o $(S)/print_packaged_claims.cc

$(EXE_DIR)/embed_policy_key.exe: $(embed_policy_key_obj)
	@echo "linking executable files"
	$(LINK) -o $(EXE_DIR)/embed_policy_key.exe $(embed_policy_key_obj) $(LDFLAGS)

$(O)/embed_policy_key.o: $(S)/embed_policy_key.cc $(INC_DIR)/certifier.pb.h $(INC_DIR)/certifier.h
	@echo "compiling embed_policy_key.cc"
	$(CC) $(CFLAGS) -c -o $(O)/embed_policy_key.o $(S)/embed_policy_key.cc

$(EXE_DIR)/appoint_platform.exe: $(appoint_platform_obj)
	@echo "linking executable files"
	$(LINK) -o $(EXE_DIR)/appoint_platform.exe $(appoint_platform_obj) $(LDFLAGS)

$(O)/appoint_platform.o: $(S)/appoint_platform.cc $(INC_DIR)/certifier.pb.h $(INC_DIR)/certifier.h
	@echo "compiling appoint_platform.cc"
	$(CC) $(CFLAGS) -c -o $(O)/appoint_platform.o $(S)/appoint_platform.cc
