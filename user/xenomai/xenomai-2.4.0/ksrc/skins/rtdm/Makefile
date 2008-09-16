ifeq ($(PATCHLEVEL),6)

# Makefile frag for Linux v2.6

obj-$(CONFIG_XENO_SKIN_RTDM) += xeno_rtdm.o

xeno_rtdm-y := core.o device.o drvlib.o module.o

xeno_rtdm-$(CONFIG_XENO_OPT_PERVASIVE) += syscall.o

xeno_rtdm-$(CONFIG_PROC_FS) += proc.o

EXTRA_CFLAGS += -D__IN_XENOMAI__ -Iinclude/xenomai -I$(src)/..

else

# Makefile frag for Linux v2.4

O_TARGET := built-in.o

obj-$(CONFIG_XENO_SKIN_RTDM) := xeno_rtdm.o

list-multi := xeno_rtdm.o

xeno_rtdm-objs := core.o device.o drvlib.o module.o

opt_objs-y :=
opt_objs-$(CONFIG_XENO_OPT_PERVASIVE) += syscall.o
opt_objs-$(CONFIG_PROC_FS) += proc.o

xeno_rtdm-objs += $(opt_objs-y)

export-objs := $(xeno_rtdm-objs)

EXTRA_CFLAGS += -D__IN_XENOMAI__ -I$(TOPDIR)/include/xenomai -I$(TOPDIR)/include/xenomai/compat -I..

include $(TOPDIR)/Rules.make

xeno_rtdm.o: $(xeno_rtdm-objs)
	$(LD) -r -o $@ $(xeno_rtdm-objs)

endif
