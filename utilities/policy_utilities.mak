#    
#    File: policy_utillities.mak

ifndef CERTIFIER_ROOT
CERTIFIER_ROOT=..
endif
ifndef SRC_DIR
SRC_DIR=.
endif
ifndef INC_DIR
INC_DIR=$(CERTIFIER_ROOT)/include
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

# Allows user to over-ride libs path externally depending on machine's install
ifndef LOCAL_LIB
LOCAL_LIB=/usr/local/lib
endif

ifndef TARGET_MACHINE_TYPE
TARGET_MACHINE_TYPE= x64
endif

CERT_SRC=$(CERTIFIER_ROOT)/src
CP = $(CERTIFIER_ROOT)/certifier_service/certprotos

S= $(SRC_DIR)
O= $(OBJ_DIR)
I= $(INC_DIR)

INCLUDE= -I$(INC_DIR) -I/usr/local/opt/openssl@1.1/include/ -I$(CERT_SRC)/sev-snp/

CFLAGS_NOERROR = $(INCLUDE) -O3 -g -Wall -std=c++11 -Wno-unused-variable -D X64 -Wno-deprecated -Wno-deprecated-declarations
CFLAGS = $(CFLAGS_NOERROR) -Werror
# For Mac: -D MACOS should be defined

CC=g++
LINK=g++
#PROTO=/usr/local/bin/protoc
# Point this to the right place, if you have to.
# I had to do the above on my machine.
PROTO=protoc
AR=ar
#export LD_LIBRARY_PATH=/usr/local/lib
LDFLAGS= -L $(LOCAL_LIB) -lprotobuf -lgtest -lgflags -lpthread -L/usr/local/opt/openssl@1.1/lib/ -lcrypto -lssl

common_objs = $(O)/support.o $(O)/certifier.o $(O)/certifier_proofs.o \
              $(O)/certifier.pb.o $(O)/simulated_enclave.o \
              $(O)/application_enclave.o

measurement_utility_obj = $(O)/measurement_utility.o $(common_objs)

make_indirect_vse_clause_obj = $(O)/make_indirect_vse_clause.o $(common_objs)

make_simple_vse_clause_obj = $(O)/make_simple_vse_clause.o $(common_objs)

make_unary_vse_clause_obj = $(O)/make_unary_vse_clause.o $(common_objs)

make_signed_claim_from_vse_clause_obj = $(O)/make_signed_claim_from_vse_clause.o \
                                        $(common_objs)

print_vse_clause_obj = $(O)/print_vse_clause.o $(common_objs)

print_signed_claim_obj = $(O)/print_signed_claim.o $(common_objs)

package_claims_obj = $(O)/package_claims.o $(common_objs)

print_packaged_claims_obj = $(O)/print_packaged_claims.o $(common_objs)

embed_policy_key_obj=$(O)/embed_policy_key.o

make_platform_obj = $(O)/make_platform.o $(common_objs)

make_property_obj = $(O)/make_property.o $(common_objs)

combine_properties_obj = $(O)/combine_properties.o $(common_objs)

make_environment_obj = $(O)/make_environment.o $(common_objs)

simulated_sev.obj = $(O)/simulated_sev_attest.o $(common_objs)

sample_sev_key_generation.obj = $(O)/sample_sev_key_generation.o $(common_objs)

simulated_sev_key_generation.obj = $(O)/simulated_sev_key_generation.o $(common_objs)

all:	$(EXE_DIR)/measurement_utility.exe \
	    $(EXE_DIR)/make_indirect_vse_clause.exe \
	    $(EXE_DIR)/make_simple_vse_clause.exe \
	    $(EXE_DIR)/make_unary_vse_clause.exe \
	    $(EXE_DIR)/make_signed_claim_from_vse_clause.exe \
	    $(EXE_DIR)/make_platform.exe \
	    $(EXE_DIR)/make_property.exe \
	    $(EXE_DIR)/make_environment.exe \
	    $(EXE_DIR)/package_claims.exe \
	    $(EXE_DIR)/print_packaged_claims.exe \
	    $(EXE_DIR)/embed_policy_key.exe \
	    $(EXE_DIR)/combine_properties.exe \
	    $(EXE_DIR)/sample_sev_key_generation.exe \
	    $(EXE_DIR)/simulated_sev_attest.exe \
	    $(EXE_DIR)/simulated_sev_key_generation.exe \
	    $(EXE_DIR)/print_vse_clause.exe \
	    $(EXE_DIR)/print_signed_claim.exe \
	    $(EXE_DIR)/print_packaged_claims.exe

clean:
	@echo "removing generated files"
	rm -rf $(CERT_SRC)/certifier.pb.cc $(CERT_SRC)/certifier.pb.h $(I)/certifier.pb.h
	@echo "removing object files"
	rm -rf $(O)/*.o
	@echo "removing executables"
	rm -rf $(EXE_DIR)/*.exe

$(EXE_DIR)/measurement_utility.exe: $(measurement_utility_obj) 
	@echo "\nlinking executable $@"
	$(LINK) $(measurement_utility_obj) $(LDFLAGS) -o $(@D)/$@

$(O)/measurement_utility.o: $(S)/measurement_utility.cc $(INC_DIR)/certifier.pb.h $(INC_DIR)/certifier.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

# Generate certifier.pb.cc in src/ dir, using proto file from certprotos/
$(I)/certifier.pb.h: $(CERT_SRC)/certifier.pb.cc
$(CERT_SRC)/certifier.pb.cc: $(CP)/certifier.proto
	$(PROTO) --proto_path=$(CP) --cpp_out=$(CERT_SRC) $<
	mv $(CERT_SRC)/certifier.pb.h $(I)

$(O)/certifier.pb.o: $(CERT_SRC)/certifier.pb.cc $(INC_DIR)/certifier.pb.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS_NOERROR) -Warray-bounds -o $(@D)/$@ -c $<

$(O)/support.o: $(CERT_SRC)/support.cc $(INC_DIR)/support.h $(INC_DIR)/certifier.pb.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(O)/certifier.o: $(CERT_SRC)/certifier.cc $(INC_DIR)/certifier.pb.h $(INC_DIR)/certifier.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(O)/certifier_proofs.o: $(CERT_SRC)/certifier_proofs.cc $(INC_DIR)/certifier.pb.h $(INC_DIR)/certifier.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(O)/simulated_enclave.o: $(CERT_SRC)/simulated_enclave.cc $(INC_DIR)/simulated_enclave.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(O)/application_enclave.o: $(CERT_SRC)/application_enclave.cc $(INC_DIR)/application_enclave.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(O)/measurement_init.o: $(S)/measurement_init.cc
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(O)/make_indirect_vse_clause.o: $(S)/make_indirect_vse_clause.cc $(INC_DIR)/certifier.pb.h $(INC_DIR)/certifier.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(EXE_DIR)/make_indirect_vse_clause.exe: $(make_indirect_vse_clause_obj) 
	@echo "\nlinking executable $@"
	$(LINK) -o $(EXE_DIR)/make_indirect_vse_clause.exe $(make_indirect_vse_clause_obj) $(LDFLAGS)

$(O)/make_simple_vse_clause.o: $(S)/make_simple_vse_clause.cc $(INC_DIR)/certifier.pb.h $(INC_DIR)/certifier.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(EXE_DIR)/make_simple_vse_clause.exe: $(make_simple_vse_clause_obj) 
	@echo "\nlinking executable $@"
	$(LINK) -o $(EXE_DIR)/make_simple_vse_clause.exe $(make_simple_vse_clause_obj) $(LDFLAGS)

$(O)/make_unary_vse_clause.o: $(S)/make_unary_vse_clause.cc $(INC_DIR)/certifier.pb.h $(INC_DIR)/certifier.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(EXE_DIR)/make_unary_vse_clause.exe: $(make_unary_vse_clause_obj) 
	@echo "\nlinking executable $@"
	$(LINK) -o $(EXE_DIR)/make_unary_vse_clause.exe $(make_unary_vse_clause_obj) $(LDFLAGS)

$(O)/make_signed_claim_from_vse_clause.o: $(S)/make_signed_claim_from_vse_clause.cc $(INC_DIR)/certifier.pb.h $(INC_DIR)/certifier.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(EXE_DIR)/make_signed_claim_from_vse_clause.exe: $(make_signed_claim_from_vse_clause_obj) 
	@echo "\nlinking executable $@"
	$(LINK) -o $(EXE_DIR)/make_signed_claim_from_vse_clause.exe $(make_signed_claim_from_vse_clause_obj) $(LDFLAGS)

$(EXE_DIR)/print_vse_clause.exe: $(print_vse_clause_obj) 
	@echo "\nlinking executable $@"
	$(LINK) -o $(EXE_DIR)/print_vse_clause.exe $(print_vse_clause_obj) $(LDFLAGS)

$(O)/print_vse_clause.o: $(S)/print_vse_clause.cc $(INC_DIR)/certifier.pb.h $(INC_DIR)/certifier.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(EXE_DIR)/print_signed_claim.exe: $(print_signed_claim_obj) 
	@echo "\nlinking executable $@"
	$(LINK) -o $(EXE_DIR)/print_signed_claim.exe $(print_signed_claim_obj) $(LDFLAGS)

$(O)/print_signed_claim.o: $(S)/print_signed_claim.cc $(INC_DIR)/certifier.pb.h $(INC_DIR)/certifier.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(EXE_DIR)/package_claims.exe: $(package_claims_obj) 
	@echo "\nlinking executable $@"
	$(LINK) -o $(EXE_DIR)/package_claims.exe $(package_claims_obj) $(LDFLAGS)

$(O)/package_claims.o: $(S)/package_claims.cc $(INC_DIR)/certifier.pb.h $(INC_DIR)/certifier.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(EXE_DIR)/print_packaged_claims.exe: $(print_packaged_claims_obj) 
	@echo "\nlinking executable $@"
	$(LINK) -o $(EXE_DIR)/print_packaged_claims.exe $(print_packaged_claims_obj) $(LDFLAGS)

print_packaged_claims.o: $(S)/print_packaged_claims.cc $(INC_DIR)/certifier.pb.h $(INC_DIR)/certifier.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(EXE_DIR)/embed_policy_key.exe: $(embed_policy_key_obj)
	@echo "\nlinking executable $@"
	$(LINK) -o $(EXE_DIR)/embed_policy_key.exe $(embed_policy_key_obj) $(LDFLAGS)

$(O)/embed_policy_key.o: $(S)/embed_policy_key.cc $(INC_DIR)/certifier.pb.h $(INC_DIR)/certifier.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(EXE_DIR)/make_platform.exe: $(make_platform_obj)
	@echo "\nlinking executable $@"
	$(LINK) -o $(EXE_DIR)/make_platform.exe $(make_platform_obj) $(LDFLAGS)

$(O)/make_platform.o: $(S)/make_platform.cc $(INC_DIR)/certifier.pb.h $(INC_DIR)/certifier.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(O)/make_property.o: $(S)/make_property.cc $(INC_DIR)/certifier.pb.h $(INC_DIR)/certifier.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(EXE_DIR)/make_property.exe: $(make_property_obj)
	@echo "\nlinking executable $@"
	$(LINK) -o $(EXE_DIR)/make_property.exe $(make_property_obj) $(LDFLAGS)

$(O)/combine_properties.o: $(S)/combine_properties.cc $(INC_DIR)/certifier.pb.h $(INC_DIR)/certifier.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(EXE_DIR)/combine_properties.exe: $(combine_properties_obj)
	@echo "\nlinking executable $@"
	$(LINK) -o $(EXE_DIR)/combine_properties.exe $(combine_properties_obj) $(LDFLAGS)

$(O)/make_environment.o: $(S)/make_environment.cc $(INC_DIR)/certifier.pb.h $(INC_DIR)/certifier.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(EXE_DIR)/make_environment.exe: $(make_environment_obj)
	@echo "\nlinking executable $@"
	$(LINK) -o $(EXE_DIR)/make_environment.exe $(make_environment_obj) $(LDFLAGS)

$(O)/simulated_sev_attest.o: $(S)/simulated_sev_attest.cc
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(EXE_DIR)/simulated_sev_attest.exe: $(simulated_sev.obj)
	@echo "\nlinking executable $@"
	$(LINK) -o $(EXE_DIR)/simulated_sev_attest.exe $(simulated_sev.obj) $(LDFLAGS)

$(O)/sample_sev_key_generation.o: $(S)/sample_sev_key_generation.cc
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(EXE_DIR)/sample_sev_key_generation.exe: $(sample_sev_key_generation.obj)
	@echo "\nlinking executable $@"
	$(LINK) -o $(EXE_DIR)/sample_sev_key_generation.exe $(sample_sev_key_generation.obj) $(LDFLAGS)

$(O)/simulated_sev_key_generation.o: $(S)/simulated_sev_key_generation.cc
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(EXE_DIR)/simulated_sev_key_generation.exe: $(simulated_sev_key_generation.obj)
	@echo "\nlinking executable $@"
	$(LINK) -o $(EXE_DIR)/simulated_sev_key_generation.exe $(simulated_sev_key_generation.obj) $(LDFLAGS)
