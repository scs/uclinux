# Makefile for the linux kernel.
# modified for uClinux.
#
extra-y += init_task.o vmlinux.lds
# Object file lists.
obj-y:= entry.o process.o bfin_ksyms.o ptrace.o setup.o signal.o sys_bfin.o time.o traps.o irqchip.o dma-mapping.o

obj-$(CONFIG_MODULES)		+= module.o
obj-$(CONFIG_BFIN_DMA_5XX)	+= bfin_dma_5xx.o
obj-$(CONFIG_DUAL_CORE_TEST_MODULE)	+= dualcore_test.o
