ifeq ($(PATCHLEVEL),6)

# Makefile frag for Linux v2.6

obj-$(CONFIG_XENO_OPT_NUCLEUS) += xeno_nucleus.o

xeno_nucleus-y := heap.o intr.o module.o pod.o synch.o thread.o timebase.o timer.o

xeno_nucleus-$(CONFIG_XENO_OPT_PERVASIVE) += shadow.o

xeno_nucleus-$(CONFIG_XENO_OPT_PIPE) += pipe.o

xeno_nucleus-$(CONFIG_XENO_OPT_MAP) += map.o

xeno_nucleus-$(CONFIG_XENO_OPT_REGISTRY) += registry.o

EXTRA_CFLAGS += -D__IN_XENOMAI__ -Iinclude/xenomai

else

# Makefile frag for Linux v2.4

O_TARGET := built-in.o

obj-$(CONFIG_XENO_OPT_NUCLEUS) := xeno_nucleus.o

list-multi := xeno_nucleus.o

xeno_nucleus-objs := heap.o intr.o module.o pod.o synch.o thread.o timebase.o timer.o

opt_objs-y :=
opt_objs-$(CONFIG_XENO_OPT_PERVASIVE) += shadow.o
opt_objs-$(CONFIG_XENO_OPT_PIPE) += pipe.o
opt_objs-$(CONFIG_XENO_OPT_MAP) += map.o
opt_objs-$(CONFIG_XENO_OPT_REGISTRY) += registry.o

xeno_nucleus-objs += $(opt_objs-y)

export-objs := $(xeno_nucleus-objs)

EXTRA_CFLAGS += -D__IN_XENOMAI__ -I$(TOPDIR)/include/xenomai -I$(TOPDIR)/include/xenomai/compat

include $(TOPDIR)/Rules.make

xeno_nucleus.o: $(xeno_nucleus-objs)
	$(LD) -r -o $@ $(xeno_nucleus-objs)

endif
