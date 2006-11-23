
ifneq ($(KERNELRELEASE),)
obj-m := timerbench.o

else

KERNELDIR := $(ROOTDIR)/linux-2.6.x
PWD := $(shell pwd)

CFLAGS :=
LDFLAGS :=
default: timerbench latency

timerbench:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

latency:
	bfin-uclinux-gcc -Wall -mfdpic -o latency latency.c -lm -lpthread -lrt

endif

romfs:
	$(ROMFSINST) -S /timerbench.ko
	$(ROMFSINST) -S /latency

clean:
	rm -f latency 
	rm -f *.o 
	rm -f *.ko 
	rm -f *.mod.c 
