# Makefile for the Enhanced Advanced Entropy Generator (EAEG) kernel module

# If KERNELDIR is not specified, use the default path
KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

# Module name
obj-m := eaeg.o

all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
