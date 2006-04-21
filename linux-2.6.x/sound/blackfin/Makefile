#
# Makefile for the blackfin 53x sport/spi connected ad1836 and ad1981b
#

snd-adi1836-objs  := ad1836_spi.o adi1836.o  bf53x_sport.o 
snd-ad73311-objs := ad73311.o bf53x_sport.o
snd-adi1981b-objs := adi1981b.o bf53x_sport.o 

obj-$(CONFIG_SND_BLACKFIN_ADI1836)	+= snd-adi1836.o
obj-$(CONFIG_SND_BFIN_AD73311)		+= snd-ad73311.o
obj-$(CONFIG_SND_BLACKFIN_ADI1981B)	+= snd-adi1981b.o



