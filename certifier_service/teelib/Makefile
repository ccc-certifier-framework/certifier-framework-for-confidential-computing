#
# certifier_service/teelib/Makefile
#

ifndef LOCAL_LIB
LOCAL_LIB=/usr/local/lib
endif
PROTO=protoc

# CERTIFIER_ROOT will be certifier-framework-for-confidential-computing/ dir
CERTIFIER_ROOT = ../..

CERTIFIER_INCLUDE = -I . -I $(CERTIFIER_ROOT)/include -I $(CERTIFIER_ROOT)/src/sev-snp
CERTIFIER_CFLAGS = $(CERTIFIER_INCLUDE)
CERTIFIER_LDFLAGS =
CERTIFIER_LDFLAGS += -lcrypto -lssl -luuid

CFLAGS += $(CERTIFIER_CFLAGS)
CFLAGS += -O3 -g -Wall -std=c++11 -Wno-unused-variable -Werror -Wno-missing-braces -DSEV_SNP
LDFLAGS=
LDFLAGS += -L $(LOCAL_LIB) -ldl -lprotobuf -lgtest -lgflags -pthread $(CERTIFIER_LDFLAGS)

TEE_PRIMITIVE_LIB = libtee.so

CP = $(CERTIFIER_ROOT)/certifier_service/certprotos

CS = $(CERTIFIER_ROOT)/src
S = $(CERTIFIER_ROOT)/certifier_service/teelib

OBJ_DIR = .
O = $(OBJ_DIR)
I = $(CERTIFIER_ROOT)/include

dobj = $(O)/certifier.pb.o $(O)/tee_primitives.o $(O)/certifier.o $(O)/support.o \
	$(O)/sev_support.o $(O)/sev_cert_table.o $(O)/sev_report.o \
	$(O)/simulated_enclave.o $(O)/application_enclave.o $(O)/certifier_proofs.o

.PHONY: all build dummy clean

all: build

build: $(TEE_PRIMITIVE_LIB)
	@echo " \nCompilers used: $(CC), $(CXX). Linking $<"
	$(CXX) -shared -o $(TEE_PRIMITIVE_LIB) $(dobj) $(LDFLAGS)

$(TEE_PRIMITIVE_LIB): $(dobj)

$(I)/certifier.pb.h: $(S)/certifier.pb.cc
$(S)/certifier.pb.cc: $(CP)/certifier.proto
	@echo "\nGenerate protobuf files"
	$(PROTO) --proto_path=$(CP) --cpp_out=$(S) $<
	mv $(S)/certifier.pb.h $(I)

$(O)/certifier.pb.o: $(S)/certifier.pb.cc $(I)/certifier.pb.h
	@echo " \nCompiling $<"
	$(CC) -fPIC $(CFLAGS) -Wno-array-bounds -c $< -o $@

$(O)/tee_primitives.o: $(S)/tee_primitives.cc
	@ echo " \nCompiling $<"
	$(CXX) -fPIC $(CFLAGS) -c $< -o $@

$(O)/certifier.o: $(CS)/certifier.cc
	@ echo " \nCompiling $<"
	$(CXX) -fPIC $(CFLAGS) -Wno-deprecated-declarations -c $< -o $@

$(O)/support.o: $(CS)/support.cc
	@ echo " \nCompiling $<"
	$(CXX) -fPIC $(CFLAGS) -Wno-deprecated-declarations -c $< -o $@

$(O)/sev_support.o: $(CS)/sev-snp/sev_support.cc
	@ echo " \nCompiling $<"
	$(CXX) -fPIC $(CFLAGS) -Wno-deprecated-declarations -c $< -o $@

$(O)/sev_cert_table.o: $(CS)/sev-snp/sev_cert_table.cc
	@ echo " \nCompiling $<"
	$(CXX) -fPIC $(CFLAGS) -Wno-deprecated-declarations -c $< -o $@

$(O)/sev_report.o: $(CS)/sev-snp/sev_report.cc
	@ echo " \nCompiling $<"
	$(CXX) -fPIC $(CFLAGS) -Wno-deprecated-declarations -c $< -o $@

$(O)/simulated_enclave.o: $(CS)/simulated_enclave.cc
	@ echo " \nCompiling $<"
	$(CXX) -fPIC $(CFLAGS) -Wno-deprecated-declarations -c $< -o $@

$(O)/application_enclave.o: $(CS)/application_enclave.cc
	@ echo " \nCompiling $<"
	$(CXX) -fPIC $(CFLAGS) -Wno-deprecated-declarations -c $< -o $@

$(O)/certifier_proofs.o: $(CS)/certifier_proofs.cc
	@ echo " \nCompiling $<"
	$(CXX) -fPIC $(CFLAGS) -Wno-deprecated-declarations -c $< -o $@

clean:
	@echo "Removing generated files"
	rm -rf $(I)/certifier.pb.h $(S)/certifier.pb.h $(S)/certifier.pb.cc
	rm -rf *.o $(TEE_PRIMITIVE_LIB)
