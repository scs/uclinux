ifeq ($(PATCHLEVEL),6)

# Makefile frag for Linux v2.6

obj-$(CONFIG_XENO_SKIN_RTAI) += xeno_rtai.o

xeno_rtai-y := intr.o module.o task.o timer.o

xeno_rtai-$(CONFIG_XENO_OPT_PERVASIVE) += syscall.o

xeno_rtai-$(CONFIG_XENO_OPT_RTAI_FIFO) += fifo.o

xeno_rtai-$(CONFIG_XENO_OPT_RTAI_SEM) += sem.o

xeno_rtai-$(CONFIG_XENO_OPT_RTAI_SHM) += shm.o

EXTRA_CFLAGS += -D__IN_XENOMAI__ -Iinclude/xenomai

else

# Makefile frag for Linux v2.4

O_TARGET := built-in.o

obj-$(CONFIG_XENO_SKIN_RTAI) := xeno_rtai.o

list-multi := xeno_rtai.o

xeno_rtai-objs := intr.o module.o task.o timer.o

opt_objs-y :=
opt_objs-$(CONFIG_XENO_OPT_PERVASIVE) += syscall.o
opt_objs-$(CONFIG_XENO_OPT_RTAI_FIFO) += fifo.o
opt_objs-$(CONFIG_XENO_OPT_RTAI_SEM) += sem.o
opt_objs-$(CONFIG_XENO_OPT_RTAI_SHM) += shm.o

xeno_rtai-objs += $(opt_objs-y)

export-objs := $(xeno_rtai-objs)

EXTRA_CFLAGS += -D__IN_XENOMAI__ -I$(TOPDIR)/include/xenomai -I$(TOPDIR)/include/xenomai/compat

include $(TOPDIR)/Rules.make

xeno_rtai.o: $(xeno_rtai-objs)
	$(LD) -r -o $@ $(xeno_rtai-objs)

endif
