#
# Makefile for arch/m68knommu/platform/68VZ328/de2.
#

obj-$(CONFIG_DRAGEN2) := config.o

extra-$(CONFIG_DRAGEN2) := crt0_ram.o

$(obj)/config.o: $(obj)/screen.h

$(obj)/screen.h: $(src)/screen.xbm $(src)/xbm2lcd.pl
	perl $(src)/xbm2lcd.pl < $(src)/screen.xbm > $(obj)/screen.h

clean-files := $(obj)/screen.h
