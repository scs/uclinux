ifeq ($(PATCHLEVEL),6)

# Makefile frag for Linux v2.6

obj-$(CONFIG_XENO_SKIN_VRTX) += xeno_vrtx.o

xeno_vrtx-y := event.o heap.o mb.o module.o mx.o pt.o queue.o sem.o task.o time.o

xeno_vrtx-$(CONFIG_XENO_OPT_PERVASIVE) += syscall.o

EXTRA_CFLAGS += -D__IN_XENOMAI__ -I$(src)/.. -Iinclude/xenomai

else

# Makefile frag for Linux v2.4

O_TARGET := built-in.o

obj-$(CONFIG_XENO_SKIN_VRTX) := xeno_vrtx.o

list-multi := xeno_vrtx.o

opt_objs-y :=
opt_objs-$(CONFIG_XENO_OPT_PERVASIVE) += syscall.o

xeno_vrtx-objs := event.o heap.o mb.o module.o mx.o pt.o queue.o sem.o task.o time.o $(opt_objs-y)

export-objs := $(xeno_vrtx-objs)

EXTRA_CFLAGS += -D__IN_XENOMAI__ -I$(TOPDIR)/include/xenomai -I$(TOPDIR)/include/xenomai/compat -I..

include $(TOPDIR)/Rules.make

xeno_vrtx.o: $(xeno_vrtx-objs)
	$(LD) -r -o $@ $(xeno_vrtx-objs)

endif
