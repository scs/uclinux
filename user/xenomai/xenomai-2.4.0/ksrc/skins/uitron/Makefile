ifeq ($(PATCHLEVEL),6)

# Makefile frag for Linux v2.6

obj-$(CONFIG_XENO_SKIN_UITRON) += xeno_uitron.o

xeno_uitron-y := flag.o mbx.o module.o sem.o task.o

xeno_uitron-$(CONFIG_XENO_OPT_PERVASIVE) += syscall.o

EXTRA_CFLAGS += -D__IN_XENOMAI__ -Iinclude/xenomai -I$(src)/..

else

# Makefile frag for Linux v2.4

O_TARGET := built-in.o

obj-$(CONFIG_XENO_SKIN_UITRON) := xeno_uitron.o

xeno_uitron-objs := flag.o mbx.o module.o sem.o task.o

opt_objs-y :=
opt_objs-$(CONFIG_XENO_OPT_PERVASIVE) += syscall.o

xeno_uitron-objs += $(opt_objs-y)

export-objs := $(xeno_uitron-objs)

EXTRA_CFLAGS += -D__IN_XENOMAI__ -I$(TOPDIR)/include/xenomai -I$(TOPDIR)/include/xenomai/compat -I..

include $(TOPDIR)/Rules.make

xeno_uitron.o: $(xeno_uitron-objs)
	$(LD) -r -o $@ $(xeno_uitron-objs)

endif
