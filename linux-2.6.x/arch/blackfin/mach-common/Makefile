#
# Makefile for the linux kernel.
#

# Object file lists.
obj-y		+= cache.o cacheinit.o cplbhdlr.o cplbmgr.o entry.o \
			flush.o interrupt.o lock.o dpmc.o irqpanic.o

# Object files - Kernel configuration dependend features
obj-$(CONFIG_CPLB_INFO)		+= cplbinfo.o

# Object files - Machine dependend 
obj-$(CONFIG_BFIN_HAVE_RTC)     += bf5xx_rtc.o
obj-$(CONFIG_BFIN_SINGLE_CORE)	+= ints-priority-sc.o
obj-$(CONFIG_BFIN_DUAL_CORE)	+= ints-priority-dc.o
