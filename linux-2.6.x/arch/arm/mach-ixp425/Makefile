#
# Makefile for the linux kernel.
#

obj-y	+= mm.o gpio.o ixp425-irq.o ixp425-time.o ixp425-pci.o \
	   pcibuf.o pci-io.o

obj-$(CONFIG_ARCH_IXDP425)	+= ixdp425.o ixdp425-pci.o
obj-$(CONFIG_ARCH_ADI_COYOTE)	+= coyote.o coyote-pci.o
obj-$(CONFIG_ARCH_PRPMC1100)	+= prpmc1100.o prpmc1100-pci.o
obj-$(CONFIG_ARCH_SE4000)	+= se4000.o
obj-$(CONFIG_KGDB) 		+= kgdb.o

