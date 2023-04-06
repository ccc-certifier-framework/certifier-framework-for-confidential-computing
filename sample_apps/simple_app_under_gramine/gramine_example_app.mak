ARCH_LIBDIR ?= /lib/$(shell $(CC) -dumpmachine)

ifeq ($(DEBUG),1)
GRAMINE_LOG_LEVEL = debug
CFLAGS += -O0 -ggdb3
else
GRAMINE_LOG_LEVEL = error
CFLAGS += -O2
endif

CFLAGS += -fPIE
LDFLAGS += -pie

RA_TYPE ?= none
RA_CLIENT_SPID ?=
RA_CLIENT_LINKABLE ?= 0

.PHONY: all
all: app

.PHONY: app
app: gramine_example_app.manifest.sgx gramine_example_app.sig gramine_example_app.token

######################### GRAMINE/SGX VARIABLES ###############################
GRAMINE_SRC_PATH = ../../../gramine/gramine
SGX_INCLUDE = -I$(GRAMINE_SRC_PATH)/pal/src/host/linux-sgx
SGX_LDFLAGS = -Wl,--enable-new-dtags $(shell pkg-config --libs sgx_util)

######################### CERTIFIER ###########################
CERTIFIER_SRC_PATH = ../../src

.SECONDARY: certifier
CERTIFIER_SRC = $(CERTIFIER_SRC_PATH)/gramine/gramine_api.cc        \
		$(CERTIFIER_SRC_PATH)/gramine/gramine_api_impl.cc   \
		$(CERTIFIER_SRC_PATH)/certifier.cc                  \
		$(CERTIFIER_SRC_PATH)/certifier_proofs.cc           \
		$(CERTIFIER_SRC_PATH)/support.cc                    \
		$(CERTIFIER_SRC_PATH)/simulated_enclave.cc          \
		$(CERTIFIER_SRC_PATH)/application_enclave.cc        \
		$(CERTIFIER_SRC_PATH)/cc_helpers.cc                 \
		$(CERTIFIER_SRC_PATH)/test_support.cc               \
		$(CERTIFIER_SRC_PATH)/certifier.pb.cc               \

CERTIFIER_INCLUDE = -I. -I$(CERTIFIER_SRC_PATH)/../include -I$(CERTIFIER_SRC_PATH)/gramine $(SGX_INCLUDE) -I./mbedtls/include
CERTIFIER_CFLAGS = $(CERTIFIER_INCLUDE) -DGRAMINE_CERTIFIER
CERTIFIER_LDFLAGS = -lssl -lcrypto
CERTIFIER_LDFLAGS += -L./ -L/usr/local/lib
CERTIFIER_LDFLAGS += `pkg-config --cflags --libs protobuf`
CERTIFIER_LDFLAGS += $(shell pkg-config --libs mbedtls_gramine)
GPP=g++

certifier:
	$(GPP) -shared -fPIC -o libcertifier.so $(CERTIFIER_CFLAGS) $(CERTIFIER_SRC) $(CERTIFIER_LDFLAGS)

######################### TEST APP EXECUTABLES ################################

CFLAGS += $(CERTIFIER_CFLAGS)
LDFLAGS += -Wl,--enable-new-dtags $(shell pkg-config --libs mbedtls_gramine) -L/usrl/local/lib -L./ -lcertifier -ldl -lgtest -lgflags $(CERTIFIER_LDFLAGS) $(SGX_LDFLAGS)

gramine_example_app: gramine_example_app.cc certifier
	$(GPP) $< $(CFLAGS) $(LDFLAGS) -o $@

########################### TEST APP MANIFEST #################################

gramine_example_app.manifest: gramine_example_app.manifest.template
	gramine-manifest \
		-Dlog_level=$(GRAMINE_LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		-Dra_type=$(RA_TYPE) \
		-Dra_client_spid=$(RA_CLIENT_SPID) \
		-Dra_client_linkable=$(RA_CLIENT_LINKABLE) \
		$< > $@

gramine_example_app.manifest.sgx gramine_example_app.sig: sgx_sign_gramine_example_app
	@:

.INTERMEDIATE: sgx_sign_gramine_example_app
sgx_sign_gramine_example_app: gramine_example_app.manifest gramine_example_app
	gramine-sgx-sign \
		--manifest $< \
		--output $<.sgx

gramine_example_app.token: gramine_example_app.sig
	gramine-sgx-get-token --output $@ --sig $<

################################## CLEANUP ####################################

.PHONY: clean
clean:
	$(RM) -r \
		*.token *.sig *.manifest.sgx *.manifest gramine_example_app *.so *.o *.a *.so.* OUTPUT

.PHONY: distclean
distclean: clean
	$(RM) -r mbedtls/ *.tar.gz
