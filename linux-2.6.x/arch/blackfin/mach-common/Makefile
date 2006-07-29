#
# arch/blackfin/mach-common/Makefile
#

obj-y := \
	cache.o cacheinit.o cplbhdlr.o cplbmgr.o entry.o \
	flush.o interrupt.o lock.o dpmc.o irqpanic.o

obj-$(CONFIG_CPLB_INFO)          += cplbinfo.o
obj-$(CONFIG_BFIN_HAVE_RTC)      += bf5xx_rtc.o
obj-$(CONFIG_BFIN_SINGLE_CORE)   += ints-priority-sc.o
obj-$(CONFIG_BFIN_DUAL_CORE)     += ints-priority-dc.o
