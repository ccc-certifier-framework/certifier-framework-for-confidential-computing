#    
#    File: certifier.mak

ENABLE_SEV=1

# CERTIFIER_ROOT will be certifier-framework-for-confidential-computing/ dir
CERTIFIER_ROOT = ..

ifndef SRC_DIR
SRC_DIR=.
endif
ifndef INC_DIR
INC_DIR=../include
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

CP = $(CERTIFIER_ROOT)/certifier_service/certprotos

S= $(SRC_DIR)
O= $(OBJ_DIR)
I= $(INC_DIR)
CL=..

INCLUDE=-I $(I) -I/usr/local/opt/openssl@1.1/include/ -I $(S)/sev-snp

CFLAGS_COMMON = $(INCLUDE) -g -Wall -std=c++11 -Wno-unused-variable -D X64 -Wno-deprecated-declarations

CFLAGS  = $(CFLAGS_COMMON) -O3
CFLAGS_PIC =

ifdef ENABLE_SEV
CFLAGS  += -D SEV_SNP
endif

CFLAGS += $(CFLAGS_PIC)

CC=g++
LINK=g++

# Point this to the right place, if you have to, based on your machine's install:
# PROTO=/usr/local/bin/protoc
PROTO=protoc
AR=ar
LL = ls -aFlrt

# Definitions needed for generating Python bindings using SWIG tool
SWIG=swig

# -Wallkw: Enable keyword warnings for all the supported languages
SWIG_FLAGS = -Wallkw

# Base of Certifier Framework's interface file for use by SWIG
SWIG_CERT_INTERFACE = certifier_framework

PY_INCLUDE = -I /usr/include/python3.10/

#export LD_LIBRARY_PATH=/usr/local/lib
LDFLAGS= -L $(LOCAL_LIB) -lprotobuf -lgtest -lgflags -lpthread -L/usr/local/opt/openssl@1.1/lib/ -lcrypto -lssl

# ----------------------------------------------------------------------
# Define list of objects for common case which will be extended for
# ENABLE_SEV build mode.
# ----------------------------------------------------------------------
dobj = $(O)/certifier.pb.o $(O)/certifier.o $(O)/certifier_proofs.o        \
       $(O)/support.o $(O)/application_enclave.o $(O)/simulated_enclave.o  \
       $(O)/cc_helpers.o $(O)/cc_useful.o $(O)/keystone_shim.o

ifdef ENABLE_SEV
dobj += $(O)/sev_support.o $(O)/sev_report.o
endif

# Objs needed to build Certifer Framework shared lib for use by Python module
cfsl_dobj := $(dobj) $(O)/$(SWIG_CERT_INTERFACE)_wrap.o

CERTIFIER_LIB = certifier.a

LIBCERTIFIER         = lib$(SWIG_CERT_INTERFACE)
CERTIFIER_SHARED_LIB = $(LIBCERTIFIER).so

all:	$(CL)/$(CERTIFIER_LIB)

# NOTE: Default target 'all' does -not- include this target
# Separate target provided to build the shared library which requires
# rebuilding all objects with CFLAGS_PIC = -fpic flag.
sharedlib:	$(CL)/$(CERTIFIER_SHARED_LIB)

clean:
	@echo "removing generated files"
	rm -rf $(S)/certifier.pb.h $(I)/certifier.pb.h $(S)/certifier.pb.cc $(S)/$(SWIG_CERT_INTERFACE)_wrap.cc
	@echo "removing generated Python files"
	rm -rf $(CERTIFIER_ROOT)/$(SWIG_CERT_INTERFACE).py $(CERTIFIER_ROOT)/certifier_pb2.py
	@echo "removing object files"
	rm -rf $(O)/*.o
	@echo "removing executable files"
	rm -rf $(CL)/$(CERTIFIER_LIB) $(CL)/$(CERTIFIER_SHARED_LIB)

$(CL)/$(CERTIFIER_LIB): $(dobj)
	@echo "\nLinking certifier library $@"
	$(AR) rcs $(CL)/$(CERTIFIER_LIB) $(dobj)

sharedlib: CFLAGS_PIC = -fpic
$(CL)/$(CERTIFIER_SHARED_LIB): $(cfsl_dobj)
	@echo "\nLinking certifier shared library $@"
	$(LINK) -shared $(cfsl_dobj) -o $@ $(LDFLAGS)

$(I)/certifier.pb.h: $(S)/certifier.pb.cc
$(S)/certifier.pb.cc: $(CP)/certifier.proto
	@echo "\nGenerate cpp sources from proto file $<"
	$(PROTO) --cpp_out=$(@D) --proto_path $(<D) $<
	mv $(S)/certifier.pb.h $(I)
	@echo "\nGenerate python interface bindings from proto file $<"
	$(PROTO) --python_out=$(CERTIFIER_ROOT) --proto_path $(<D) $<
	$(LL) $(CERTIFIER_ROOT)/*.py*

$(O)/certifier_tests.o: $(S)/certifier_tests.cc $(I)/certifier.pb.h $(I)/certifier.h $(S)/test_support.cc
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(O)/certifier.pb.o: $(S)/certifier.pb.cc $(I)/certifier.pb.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -Wno-array-bounds -o $(@D)/$@ -c $<

$(O)/certifier.o: $(S)/certifier.cc $(I)/certifier.pb.h $(I)/certifier.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

# Ref: https://stackoverflow.com/questions/12369131/swig-and-python3-surplus-underscore
# Use -interface arg to overcome double __ issue in generated SWIG_init #define
#     -outdir specifies output-dir for generated *.py file.
$(S)/$(SWIG_CERT_INTERFACE)_wrap.cc: $(I)/$(SWIG_CERT_INTERFACE).i $(S)/certifier.cc
	@echo "\nGenerating $@"
	$(SWIG) $(SWIG_FLAGS) -v -python -c++ -Wall -interface $(LIBCERTIFIER) -outdir $(CERTIFIER_ROOT) -o $(@D)/$@ $<
	$(LL) $(CERTIFIER_ROOT)/*.py*

$(O)/$(SWIG_CERT_INTERFACE)_wrap.o: $(S)/$(SWIG_CERT_INTERFACE)_wrap.cc $(I)/certifier.pb.h $(I)/certifier.h
	@echo "compiling $<"
	$(CC) $(CFLAGS) $(PY_INCLUDE) -fpermissive -o $(@D)/$@ -c $<

$(O)/certifier_proofs.o: $(S)/certifier_proofs.cc $(I)/certifier.pb.h $(I)/certifier.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(O)/support.o: $(S)/support.cc $(I)/support.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(O)/simulated_enclave.o: $(S)/simulated_enclave.cc $(I)/simulated_enclave.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(O)/application_enclave.o: $(S)/application_enclave.cc $(I)/application_enclave.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(O)/cc_helpers.o: $(S)/cc_helpers.cc $(I)/cc_helpers.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(O)/cc_useful.o: $(S)/cc_useful.cc $(I)/cc_useful.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(O)/keystone_shim.o: $(S)/keystone/keystone_shim.cc $(S)/keystone/keystone_api.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

ifdef ENABLE_SEV
SEV_S=$(S)/sev-snp

$(O)/sev_support.o: $(SEV_S)/sev_support.cc \
                    $(I)/certifier.h $(I)/support.h $(SEV_S)/attestation.h  \
                    $(SEV_S)/sev_guest.h  $(SEV_S)/snp_derive_key.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(O)/sev_report.o: $(SEV_S)/sev_report.cc \
                   $(I)/certifier.h $(I)/support.h $(SEV_S)/attestation.h  \
                   $(SEV_S)/sev_guest.h  $(SEV_S)/snp_derive_key.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<
endif
