ifeq ($(PATCHLEVEL),6)

# Makefile frag for Linux v2.6

obj-$(CONFIG_XENO_SKIN_NATIVE) += xeno_native.o

xeno_native-y := module.o task.o timer.o

xeno_native-$(CONFIG_XENO_OPT_PERVASIVE) += syscall.o

xeno_native-$(CONFIG_XENO_OPT_NATIVE_PIPE) += pipe.o

xeno_native-$(CONFIG_XENO_OPT_NATIVE_SEM) += sem.o

xeno_native-$(CONFIG_XENO_OPT_NATIVE_EVENT) += event.o

xeno_native-$(CONFIG_XENO_OPT_NATIVE_MUTEX) += mutex.o

xeno_native-$(CONFIG_XENO_OPT_NATIVE_COND) += cond.o

xeno_native-$(CONFIG_XENO_OPT_NATIVE_QUEUE) += queue.o

xeno_native-$(CONFIG_XENO_OPT_NATIVE_HEAP) += heap.o

xeno_native-$(CONFIG_XENO_OPT_NATIVE_ALARM) += alarm.o

xeno_native-$(CONFIG_XENO_OPT_NATIVE_INTR) += intr.o

EXTRA_CFLAGS += -D__IN_XENOMAI__ -Iinclude/xenomai

else

# Makefile frag for Linux v2.4

O_TARGET := built-in.o

obj-$(CONFIG_XENO_SKIN_NATIVE) := xeno_native.o

xeno_native-objs := module.o task.o timer.o

opt_objs-y :=
opt_objs-$(CONFIG_XENO_OPT_PERVASIVE) += syscall.o
opt_objs-$(CONFIG_XENO_OPT_NATIVE_PIPE) += pipe.o
opt_objs-$(CONFIG_XENO_OPT_NATIVE_SEM) += sem.o
opt_objs-$(CONFIG_XENO_OPT_NATIVE_EVENT) += event.o
opt_objs-$(CONFIG_XENO_OPT_NATIVE_MUTEX) += mutex.o
opt_objs-$(CONFIG_XENO_OPT_NATIVE_COND) += cond.o
opt_objs-$(CONFIG_XENO_OPT_NATIVE_QUEUE) += queue.o
opt_objs-$(CONFIG_XENO_OPT_NATIVE_HEAP) += heap.o
opt_objs-$(CONFIG_XENO_OPT_NATIVE_ALARM) += alarm.o
opt_objs-$(CONFIG_XENO_OPT_NATIVE_INTR) += intr.o

xeno_native-objs += $(opt_objs-y)

export-objs := $(xeno_native-objs)

EXTRA_CFLAGS += -D__IN_XENOMAI__ -I$(TOPDIR)/include/xenomai -I$(TOPDIR)/include/xenomai/compat

include $(TOPDIR)/Rules.make

xeno_native.o: $(xeno_native-objs)
	$(LD) -r -o $@ $(xeno_native-objs)

endif
