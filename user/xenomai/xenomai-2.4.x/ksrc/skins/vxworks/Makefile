ifeq ($(PATCHLEVEL),6)

# Makefile frag for Linux v2.6

obj-$(CONFIG_XENO_SKIN_VXWORKS) += xeno_vxworks.o

xeno_vxworks-y := errnoLib.o intLib.o kernelLib.o module.o msgQLib.o semLib.o \
		sysLib.o taskHookLib.o taskInfo.o taskLib.o tickLib.o wdLib.o

xeno_vxworks-$(CONFIG_XENO_OPT_PERVASIVE) += syscall.o

EXTRA_CFLAGS += -D__IN_XENOMAI__ -Iinclude/xenomai -I$(src)/..

else

# Makefile frag for Linux v2.4

O_TARGET := built-in.o

obj-$(CONFIG_XENO_SKIN_VXWORKS) := xeno_vxworks.o

list-multi := xeno_vxworks.o

opt_objs-y :=
opt_objs-$(CONFIG_XENO_OPT_PERVASIVE) += syscall.o

xeno_vxworks-objs := errnoLib.o intLib.o kernelLib.o module.o msgQLib.o semLib.o \
		sysLib.o taskHookLib.o taskInfo.o taskLib.o tickLib.o wdLib.o $(opt_objs-y)

export-objs := $(xeno_vxworks-objs)

EXTRA_CFLAGS += -D__IN_XENOMAI__ -I$(TOPDIR)/include/xenomai -I$(TOPDIR)/include/xenomai/compat -I..

include $(TOPDIR)/Rules.make

xeno_vxworks.o: $(xeno_vxworks-objs)
	$(LD) -r -o $@ $(xeno_vxworks-objs)

endif
