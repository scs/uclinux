ifeq ($(PATCHLEVEL),6)

# Makefile frag for Linux v2.6

obj-$(CONFIG_XENOMAI) += xeno_hal.o

xeno_hal-y := hal.o
xeno_hal-$(CONFIG_XENO_HW_FPU) += fpu.o

ifeq ($(CONFIG_PPC64),y)
xeno_hal-$(CONFIG_PPC64) += switch_64.o
else
xeno_hal-$(CONFIG_PPC) += switch_32.o
endif

EXTRA_CFLAGS += -D__IN_XENOMAI__ -Iinclude/xenomai

else

# Makefile frag for Linux v2.4

USE_STANDARD_AS_RULE := true

O_TARGET := built-in.o

obj-y := hal.o
obj-$(CONFIG_XENO_HW_FPU) += fpu.o

ifeq ($(CONFIG_PPC64),y)
obj-y += switch_64.o
else
obj-y += switch_32.o
endif

export-objs := hal.o

EXTRA_CFLAGS += -D__IN_XENOMAI__ -I$(TOPDIR)/include/xenomai -I$(TOPDIR)/include/xenomai/compat

EXTRA_AFLAGS += -I$(TOPDIR)/arch/ppc/kernel

include $(TOPDIR)/Rules.make

endif
