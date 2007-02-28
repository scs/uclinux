
ifneq ($(KERNELRELEASE),)

obj-m := timerbench.o

else

KERNELDIR := $(ROOTDIR)/$(LINUXDIR)

all: timerbench latency

timerbench:
	LDFLAGS="" $(MAKE) -C $(KERNELDIR) M=$$PWD modules

latency: LDLIBS += -lm -lpthread -lrt

endif

romfs:
	$(ROMFSINST) -S /timerbench.ko
	$(ROMFSINST) -S /latency

clean:
	rm -f latency latency.gdb *.o
	rm -f Module.symvers *.ko *.mod.c .*.cmd
	rm -rf .tmp_versions
