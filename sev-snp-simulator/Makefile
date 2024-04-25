MODULE_NAME := sevnull
DEV_PATH := /dev/sev-guest
EXTRA_CFLAGS  += -g -std=gnu99  -Wfatal-errors
OPENSSL := openssl


ifneq ($(KERNELRELEASE),) 	# kernelspace
	sevnull-y := \
		sevguest.o
	obj-m += sevnull.o

else						# userspace


CURRENT_PATH ?= $(shell pwd)
LINUX_KERNEL ?= $(shell uname -r)
LINUX_KERNEL_PATH ?= /lib/modules/$(LINUX_KERNEL)/build

CURRENT_PATH := $(shell pwd)

modules:
	make -C $(LINUX_KERNEL_PATH) M=$(CURRENT_PATH) modules

modules_install:
	make -C $(LINUX_KERNEL_PATH) M=$(CURRENT_PATH) modules_install

keys:
	rm -rf keys
	mkdir keys
	$(OPENSSL) ecparam -name secp384r1 -genkey -noout -out keys/ec-secp384r1-priv-key.pem
	$(OPENSSL) ec -in keys/ec-secp384r1-priv-key.pem -pubout > keys/ec-secp384r1-pub-key.pem
	sudo rm -rf /etc/certifier-snp-sim
	sudo mkdir /etc/certifier-snp-sim
	sudo cp -p keys/* /etc/certifier-snp-sim/

insmod:
	sudo insmod $(MODULE_NAME).ko

reinsmod:
	sudo rmmod $(MODULE_NAME)
	sudo insmod $(MODULE_NAME).ko

rmmod:
	sudo rmmod $(MODULE_NAME)

clean:
	make -C $(LINUX_KERNEL_PATH) M=$(CURRENT_PATH) clean
	rm -f modules.order Module.symvers Module.markers *.o *.cmd sevnull.ko
	rm -rf keys

.PHONY:
	modules modules_install clean

endif

