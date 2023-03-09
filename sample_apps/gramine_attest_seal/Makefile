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
app: ssl/attest_seal_app.crt mbedtls/.mbedtls_configured attest_seal_app.manifest.sgx attest_seal_app.sig attest_seal_app.token

############################# SSL DATA DEPENDENCY #############################

# SSL data: key and x.509 self-signed certificate
ssl/attest_seal_app.crt: ssl/ca_config.conf
	openssl genrsa -out ssl/ca.key 2048
	openssl req -x509 -new -nodes -key ssl/ca.key -sha256 -days 1024 -out ssl/ca.crt -config ssl/ca_config.conf
	openssl genrsa -out ssl/attest_seal_app.key 2048
	openssl req -new -key ssl/attest_seal_app.key -out ssl/attest_seal_app.csr -config ssl/ca_config.conf
	openssl x509 -req -days 360 -in ssl/attest_seal_app.csr -CA ssl/ca.crt -CAkey ssl/ca.key -CAcreateserial -out ssl/attest_seal_app.crt

######################### GRAMINE/SGX VARIABLES ###############################
GRAMINE_SRC_PATH = ../../../gramine/gramine
SGX_INCLUDE = -I$(GRAMINE_SRC_PATH)/pal/src/host/linux-sgx -I$(GRAMINE_SRC_PATH)/tools/sgx/ra-tls
SGX_LDFLAGS = -Wl,--enable-new-dtags $(shell pkg-config --libs sgx_util)

############################# MBEDTLS DEPENDENCY ##############################

# This download is done to get headers in include/, because we currently fail to provide the headers
# (`pkg-config --cflags mbedtls_gramine` in the below CFLAGS line returns a non-existing directory).
# TODO: install mbedtls_gramine headers during Gramine install, and use them in below CFLAGS line.

MBEDTLS_VERSION ?= 3.2.1
MBEDTLS_SRC ?= mbedtls-$(MBEDTLS_VERSION).tar.gz
MBEDTLS_URI ?= \
	https://github.com/ARMmbed/mbedtls/archive \
	https://packages.gramineproject.io/distfiles
MBEDTLS_HASH ?= 5850089672560eeaca03dc36678ee8573bb48ef6e38c94f5ce349af60c16da33

ifeq ($(DEBUG),1)
MBED_BUILD_TYPE=Debug
else
MBED_BUILD_TYPE=Release
endif

$(MBEDTLS_SRC):
	$(GRAMINE_SRC_PATH)/CI-Examples/common_tools/download --output $@ $(foreach mirror,$(MBEDTLS_URI),--url $(mirror)/$(MBEDTLS_SRC)) --sha256 $(MBEDTLS_HASH)

.SECONDARY: mbedtls/.mbedtls_downloaded
mbedtls/.mbedtls_downloaded: $(MBEDTLS_SRC)
	tar --touch -xzf $(MBEDTLS_SRC)
	mv mbedtls-mbedtls-$(MBEDTLS_VERSION) mbedtls
	touch $@

.SECONDARY: mbedtls/.mbedtls_configured
mbedtls/.mbedtls_configured: mbedtls/.mbedtls_downloaded
	cd mbedtls && ./scripts/config.pl set MBEDTLS_CMAC_C MBEDTLS_ERROR_C
	touch $@

######################### CERTIFIER ###########################
CERTIFIER_SRC_PATH = ../../src

.SECONDARY: certifier
CERTIFIER_SRC = $(CERTIFIER_SRC_PATH)/certifier.cc                  \
                $(CERTIFIER_SRC_PATH)/certifier_proofs.cc           \
                $(CERTIFIER_SRC_PATH)/support.cc                    \
		$(CERTIFIER_SRC_PATH)/simulated_enclave.cc          \
		$(CERTIFIER_SRC_PATH)/application_enclave.cc        \
		$(CERTIFIER_SRC_PATH)/cc_helpers.cc                 \
		$(CERTIFIER_SRC_PATH)/test_support.cc               \
		$(CERTIFIER_SRC_PATH)/gramine/gramine_api.cc        \
		$(CERTIFIER_SRC_PATH)/gramine/gramine_api_impl.cc   \
		$(CERTIFIER_SRC_PATH)/certifier.pb.cc               \
		#$(CERTIFIER_SRC_PATH)/../sample_apps/gramine_attest_seal/gramine_trusted.cc \

CERTIFIER_INCLUDE = -I$(CERTIFIER_SRC_PATH)/../include -I$(CERTIFIER_SRC_PATH)/gramine -I$(CERTIFIER_SRC_PATH)/../sample_apps/gramine_attest_seal $(SGX_INCLUDE) -I$(CERTIFIER_SRC_PATH)/../sample_apps/gramine_attest_seal/./mbedtls/include
CERTIFIER_CFLAGS = $(CERTIFIER_INCLUDE) -DGRAMINE_CERTIFIER
CERTIFIER_LDFLAGS = -lssl -lcrypto
CERTIFIER_LDFLAGS += -L./ -L/usr/local/lib
CERTIFIER_LDFLAGS += `pkg-config --cflags --libs protobuf`
GPP=g++

certifier:
	$(GPP) -shared -fPIC -o libcertifier.so $(CERTIFIER_CFLAGS) $(CERTIFIER_SRC) mbedtls/.mbedtls_configured $(CERTIFIER_LDFLAGS)

######################### CLIENT/SERVER EXECUTABLES ###########################

# TODO: use `$(shell pkg-config --cflags mbedtls_gramine)` instead of local mbedtls includes
CFLAGS += -I./mbedtls/include $(SGX_INCLUDE) $(CERTIFIER_CFLAGS)
LDFLAGS += -ldl -Wl,--enable-new-dtags $(shell pkg-config --libs mbedtls_gramine) -L/usrl/local/lib -L./ -lcertifier $(CERTIFIER_LDFLAGS) $(SGX_LDFLAGS)

attest_seal_app: attest_seal_app.c certifier mbedtls/.mbedtls_configured
	$(GPP) $< $(CFLAGS) $(LDFLAGS) -o $@

############################### SERVER MANIFEST ###############################

attest_seal_app.manifest: attest_seal_app.manifest.template
	gramine-manifest \
		-Dlog_level=$(GRAMINE_LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		-Dra_type=$(RA_TYPE) \
		-Dra_client_spid=$(RA_CLIENT_SPID) \
		-Dra_client_linkable=$(RA_CLIENT_LINKABLE) \
		$< > $@

# Make on Ubuntu <= 20.04 doesn't support "Rules with Grouped Targets" (`&:`),
# see the helloworld example for details on this workaround.
attest_seal_app.manifest.sgx attest_seal_app.sig: sgx_sign_attest_seal_app
	@:

.INTERMEDIATE: sgx_sign_attest_seal_app
sgx_sign_attest_seal_app: attest_seal_app.manifest attest_seal_app
	gramine-sgx-sign \
		--manifest $< \
		--output $<.sgx

attest_seal_app.token: attest_seal_app.sig
	gramine-sgx-get-token --output $@ --sig $<

################################## CLEANUP ####################################

.PHONY: clean
clean:
	$(RM) -r \
		*.token *.sig *.manifest.sgx *.manifest attest_seal_app *.so *.so.* OUTPUT

.PHONY: distclean
distclean: clean
	$(RM) -r mbedtls/ *.tar.gz ssl/ca.* ssl/attest_seal_app.*
