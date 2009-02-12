ifeq ($(PATCHLEVEL),6)

# Makefile frag for Linux v2.6

obj-$(CONFIG_XENOMAI) += xeno_hal.o

xeno_hal-y := hal.o

xeno_hal-$(CONFIG_XENO_HW_NMI_DEBUG_LATENCY) += nmi.o

EXTRA_CFLAGS += -D__IN_XENOMAI__ -Iinclude/xenomai

else

# Makefile frag for Linux v2.4

O_TARGET := built-in.o

obj-y := hal.o compat.o

obj-$(CONFIG_XENO_HW_NMI_DEBUG_LATENCY) += nmi.o

export-objs := $(obj-y)

EXTRA_CFLAGS += -D__IN_XENOMAI__ -I$(TOPDIR)/include/xenomai -I$(TOPDIR)/include/xenomai/compat

include $(TOPDIR)/Rules.make

endif
