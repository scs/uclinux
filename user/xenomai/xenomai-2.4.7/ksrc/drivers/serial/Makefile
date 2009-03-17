ifeq ($(PATCHLEVEL),6)

# Makefile frag for Linux v2.6

EXTRA_CFLAGS += -D__IN_XENOMAI__ -Iinclude/xenomai

obj-$(CONFIG_XENO_DRIVERS_16550A) += xeno_16550A.o

xeno_16550A-y := 16550A.o

else

# Makefile frag for Linux v2.4

O_TARGET := built-in.o

obj-$(CONFIG_XENO_DRIVERS_16550A) := xeno_16550A.o

xeno_16550A-objs := 16550A.o

export-objs := $(xeno_16550A-objs)

EXTRA_CFLAGS += -D__IN_XENOMAI__ -I$(TOPDIR)/include/xenomai -I$(TOPDIR)/include/xenomai/compat

include $(TOPDIR)/Rules.make

xeno_16550A.o: $(xeno_16550A-objs)
	$(LD) -r -o $@ $(xeno_16550A-objs)

endif
