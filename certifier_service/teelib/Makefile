#
# certifier_service/teelib/Makefile
#

ifndef LOCAL_LIB
LOCAL_LIB=/usr/local/lib
endif
PROTO=protoc

# CERTIFIER_ROOT will be certifier-framework-for-confidential-computing/ dir
ifndef CERTIFIER_ROOT
CERTIFIER_ROOT = ../..
endif

NEWPROTOBUF=1

CERTIFIER_INCLUDE = -I . -I $(CERTIFIER_ROOT)/include -I $(CERTIFIER_ROOT)/src/sev-snp -I/usr/include -I$(CERTIFIER_ROOT)/src/tpm2
CERTIFIER_CFLAGS = $(CERTIFIER_INCLUDE)
CERTIFIER_LDFLAGS =
CERTIFIER_LDFLAGS += -lssl -lcrypto -luuid

CFLAGS += $(CERTIFIER_CFLAGS)

ifndef NEWPROTOBUF
CFLAGS += -fPIC -O3 -g -Wall -std=c++11 -Wno-unused-variable -Werror -Wno-missing-braces -DSEV_SNP -Wno-deprecated -Wno-error=deprecated-declarations -Wno-error=strict-aliasing
else
CFLAGS += -fPIC -O3 -g -Wall -std=c++17 -Wno-unused-variable -Werror -Wno-missing-braces -DSEV_SNP -Wno-deprecated -Wno-error=deprecated-declarations -Wno-error=strict-aliasing
endif
LDFLAGS=

CFLAGS += -DTPM_CERTIFIER
CFLAGS += -Wno-strict-aliasing

ifndef NEWPROTOBUF
LDFLAGS += -L $(LOCAL_LIB) -ldl -lprotobuf -pthread $(CERTIFIER_LDFLAGS)
else
LDFLAGS += -L $(LOCAL_LIB) -ldl `pkg-config --cflags --libs protobuf` -pthread $(CERTIFIER_LDFLAGS) 
endif

TEE_PRIMITIVE_LIB = libtee.so

S = $(CERTIFIER_ROOT)/certifier_service/teelib
CP = $(CERTIFIER_ROOT)/certifier_service/certprotos
CS = $(CERTIFIER_ROOT)/src

OBJ_DIR = .
O = $(OBJ_DIR)
I = $(CERTIFIER_ROOT)/include
SE=$(CS)/simulated-enclave
AE=$(CS)/application-enclave
TE=$(CS)/tpm2

dobj = $(O)/certifier.pb.o $(O)/tee_primitives.o $(O)/certifier.o $(O)/support.o \
	$(O)/sev_support.o $(O)/sev_cert_table.o $(O)/sev_report.o \
	$(O)/simulated_enclave.o $(O)/application_enclave.o $(O)/certifier_proofs.o \
	$(O)/tpm2_lib.o $(O)/tpm2.pb.o $(O)/convert.o $(O)/openssl_help.o \
        $(O)/tpm2_support.o

.PHONY: all build dummy clean

all: build

ifndef NEWPROTOBUF
build: $(TEE_PRIMITIVE_LIB)
	@echo " \nCompilers used: $(CC), $(CXX). Linking $<"
	$(CXX) -shared -o $(TEE_PRIMITIVE_LIB) $(dobj) $(LDFLAGS)
else
build: $(TEE_PRIMITIVE_LIB)
	@echo " \nCompilers used: $(CC), $(CXX). Linking $<"
#	ar rcs $(TEE_PRIMITIVE_LIB) $(dobj)
	$(CXX) -shared -o $(TEE_PRIMITIVE_LIB) $(dobj) $(LDFLAGS) -lstdc++ -lm -lc
endif

$(TEE_PRIMITIVE_LIB): $(dobj)

$(I)/certifier.pb.h: $(S)/certifier.pb.cc
$(S)/certifier.pb.cc: $(CP)/certifier.proto
	@echo "\nGenerate protobuf files"
	$(PROTO) --proto_path=$(CP) --cpp_out=$(S) $<
	mv $(S)/certifier.pb.h $(I)

$(O)/certifier.pb.o: $(S)/certifier.pb.cc $(I)/certifier.pb.h
	@echo " \nCompiling $<"
	$(CC) $(CFLAGS) -Wno-array-bounds -c $< -o $@

$(O)/tee_primitives.o: $(S)/tee_primitives.cc
	@ echo " \nCompiling $<"
	$(CXX) $(CFLAGS) -c $< -o $@

$(O)/certifier.o: $(CS)/certifier.cc
	@ echo " \nCompiling $<"
	$(CXX) $(CFLAGS) -Wno-deprecated-declarations -c $< -o $@

$(O)/support.o: $(CS)/support.cc
	@ echo " \nCompiling $<"
	$(CXX) $(CFLAGS) -Wno-deprecated-declarations -c $< -o $@

$(O)/sev_support.o: $(CS)/sev-snp/sev_support.cc
	@ echo " \nCompiling $<"
	$(CXX) $(CFLAGS) -Wno-deprecated-declarations -c $< -o $@

$(O)/sev_cert_table.o: $(CS)/sev-snp/sev_cert_table.cc
	@ echo " \nCompiling $<"
	$(CXX) $(CFLAGS) -Wno-deprecated-declarations -c $< -o $@

$(O)/sev_report.o: $(CS)/sev-snp/sev_report.cc
	@ echo " \nCompiling $<"
	$(CXX) $(CFLAGS) -Wno-deprecated-declarations -c $< -o $@

$(O)/simulated_enclave.o: $(SE)/simulated_enclave.cc
	@ echo " \nCompiling $<"
	$(CXX) $(CFLAGS) -Wno-deprecated-declarations -c $< -o $@

$(O)/application_enclave.o: $(AE)/application_enclave.cc
	@ echo " \nCompiling $<"
	$(CXX) $(CFLAGS) -Wno-deprecated-declarations -c $< -o $@

$(O)/certifier_proofs.o: $(CS)/certifier_proofs.cc
	@ echo " \nCompiling $<"
	$(CXX) $(CFLAGS) -Wno-deprecated-declarations -c $< -o $@

$(TE)/tpm2.pb.cc $(TE)/tpm2.pb.h: $(TE)/tpm2.proto
	@echo "creating protobuf files"
	$(PROTO) -I=$(TE) --cpp_out=$(TE) $(TE)/tpm2.proto

$(O)/tpm2.pb.o: $(TE)/tpm2.pb.cc
	@echo "compiling tpm2.pb.cc"
	$(CXX) $(CFLAGS) -c -o $(O)/tpm2.pb.o $(TE)/tpm2.pb.cc

$(O)/convert.o: $(TE)/convert.cc
	@echo "compiling convert.cc"
	$(CXX) $(CFLAGS) -Wno-deprecated-declarations  -c -o $(O)/convert.o $(TE)/convert.cc

$(O)/tpm2_lib.o: $(TE)/tpm2_lib.cc
	@echo "compiling tpm2_lib.cc"
	$(CXX) $(CFLAGS) -Wno-deprecated-declarations  -c -o $(O)/tpm2_lib.o $(TE)/tpm2_lib.cc

$(O)/openssl_help.o: $(TE)/openssl_help.cc
	@echo "compiling openssl_help.cc"
	$(CXX) $(CFLAGS) -Wno-deprecated-declarations  -c -o $(O)/openssl_help.o $(TE)/openssl_help.cc

$(O)/tpm2_support.o: $(TE)/tpm2_support.cc
	@echo "compiling tpm2_support.cc"
	$(CXX) $(CFLAGS) -Wno-deprecated-declarations  -c -o $(O)/tpm2_support.o $(TE)/tpm2_support.cc

clean:
	@echo "Removing generated files"
	rm -rf $(I)/certifier.pb.h $(S)/certifier.pb.h $(S)/certifier.pb.cc
	rm -rf *.o $(TEE_PRIMITIVE_LIB)
