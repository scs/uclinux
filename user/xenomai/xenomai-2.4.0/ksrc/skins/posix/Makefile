ifeq ($(PATCHLEVEL),6)

# Makefile frag for Linux v2.6

obj-$(CONFIG_XENO_SKIN_POSIX) += xeno_posix.o

xeno_posix-y := sched.o thread_attr.o thread.o mutex_attr.o mutex.o \
		cond_attr.o cond.o sem.o cancel.o once.o signal.o tsd.o \
		clock.o timer.o registry.o mq.o module.o

xeno_posix-$(CONFIG_XENO_OPT_POSIX_SHM) += shm.o

xeno_posix-$(CONFIG_XENO_OPT_POSIX_INTR) += intr.o

xeno_posix-$(CONFIG_XENO_OPT_PERVASIVE) += syscall.o

EXTRA_CFLAGS += -D__IN_XENOMAI__ -I$(srctree)/include/xenomai/posix -I$(src)/.. -Iinclude/xenomai

else

# Makefile frag for Linux v2.4

O_TARGET := built-in.o

obj-$(CONFIG_XENO_SKIN_POSIX) := xeno_posix.o

list-multi := xeno_posix.o

xeno_posix-objs := sched.o thread_attr.o thread.o mutex_attr.o mutex.o \
		cond_attr.o cond.o sem.o cancel.o once.o signal.o tsd.o \
		clock.o timer.o registry.o mq.o module.o

opt_objs-y :=
opt_objs-$(CONFIG_XENO_OPT_PERVASIVE) += syscall.o

opt_objs-$(CONFIG_XENO_OPT_POSIX_SHM) += shm.o

opt_objs-$(CONFIG_XENO_OPT_POSIX_INTR) += intr.o

xeno_posix-objs += $(opt_objs-y)

export-objs := $(xeno_posix-objs)

EXTRA_CFLAGS += -D__IN_XENOMAI__ -I$(TOPDIR)/include/xenomai -I$(TOPDIR)/include/xenomai/compat -I.. -I$(TOPDIR)/include/xenomai/posix

include $(TOPDIR)/Rules.make

xeno_posix.o: $(xeno_posix-objs)
	$(LD) -r -o $@ $(xeno_posix-objs)

endif
