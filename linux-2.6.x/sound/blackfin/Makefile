#
# Makefile for the SuperH DMA specific kernel interface routines under Linux.
#

obj-$(CONFIG_SOUND_AD1981B)	+= ac97_sport.o ad1981b.o
obj-$(CONFIG_ADI_1836_AUDIO)	+= adi_1836.o
CFLAGS_adi_1836.o		+= -DLINUX -Iinclude/asm/board -D__ADSPLPBLACKFIN__ -O0

