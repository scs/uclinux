
ifneq ($(KERNELRELEASE),)
obj-m := timerbench.o

else

KERNELDIR := $(ROOTDIR)/$(LINUXDIR)

all: timerbench latency

timerbench:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

latency: LDLIBS += -lm -lpthread -lrt

endif

romfs:
	$(ROMFSINST) -S /timerbench.ko
	$(ROMFSINST) -S /latency

clean:
	rm -f latency 
	rm -f *.o 
	rm -f *.ko 
	rm -f *.mod.c 
