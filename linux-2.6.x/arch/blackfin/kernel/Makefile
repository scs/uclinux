# Makefile for the linux kernel.
# modified for uClinux. 
#
extra-y += ../mach-bf533/head.o init_task.o vmlinux.lds.s

# Object file lists.
obj-y:= entry.o process.o bfin_ksyms.o ptrace.o semaphore.o setup.o signal.o sys_bfin.o time.o traps.o bf533_rtc.o

obj-$(CONFIG_MODULES)		+= module.o
obj-$(CONFIG_BLKFIN_DMA)	+= dma.o
obj-$(CONFIG_BLKFIN_SIMPLE_DMA)	+= simple_dma.o
