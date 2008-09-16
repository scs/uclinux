ifeq ($(PATCHLEVEL),6)

# Makefile frag for Linux v2.6

EXTRA_CFLAGS += -D__IN_XENOMAI__ -Iinclude/xenomai

obj-$(CONFIG_XENO_DRIVERS_TIMERBENCH) += xeno_timerbench.o
obj-$(CONFIG_XENO_DRIVERS_IRQBENCH)   += xeno_irqbench.o
obj-$(CONFIG_XENO_DRIVERS_SWITCHTEST) += xeno_switchtest.o

xeno_timerbench-y := timerbench.o

xeno_irqbench-y := irqbench.o

xeno_switchtest-y := switchtest.o

EXTRA_CFLAGS += -D__IN_XENOMAI__ -Iinclude/xenomai

else

# Makefile frag for Linux v2.4

O_TARGET := built-in.o

obj-$(CONFIG_XENO_DRIVERS_TIMERBENCH) += xeno_timerbench.o
obj-$(CONFIG_XENO_DRIVERS_IRQBENCH)   += xeno_irqbench.o
obj-$(CONFIG_XENO_DRIVERS_SWITCHTEST) += xeno_switchtest.o

xeno_timerbench-objs := timerbench.o

xeno_irqbench-objs := irqbench.o

xeno_switchtest-objs := switchtest.o

export-objs := $(xeno_timerbench-objs) $(xeno_irqbench-objs) $(xeno_switchtest-objs)

EXTRA_CFLAGS += -D__IN_XENOMAI__ -I$(TOPDIR)/include/xenomai -I$(TOPDIR)/include/xenomai/compat

include $(TOPDIR)/Rules.make

xeno_timerbench.o: $(xeno_timerbench-objs)
	$(LD) -r -o $@ $(xeno_timerbench-objs)

xeno_irqbench.o: $(xeno_irqbench-objs)
	$(LD) -r -o $@ $(xeno_irqbench-objs)

xeno_switchtest.o: $(xeno_switchtest-objs)
	$(LD) -r -o $@ $(xeno_switchtest-objs)

endif
