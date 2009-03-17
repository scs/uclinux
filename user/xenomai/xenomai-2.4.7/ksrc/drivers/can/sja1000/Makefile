ifeq ($(PATCHLEVEL),6)

# Makefile frag for Linux v2.6

EXTRA_CFLAGS += -D__IN_XENOMAI__ -Iinclude/xenomai -Idrivers/xenomai/can -Idrivers/xenomai/can/sja1000

obj-$(CONFIG_XENO_DRIVERS_CAN_SJA1000) += xeno_can_sja1000.o
obj-$(CONFIG_XENO_DRIVERS_CAN_SJA1000_PEAK_PCI) += xeno_can_peak_pci.o
obj-$(CONFIG_XENO_DRIVERS_CAN_SJA1000_PEAK_DNG) += xeno_can_peak_dng.o
obj-$(CONFIG_XENO_DRIVERS_CAN_SJA1000_IXXAT_PCI) += xeno_can_ixxat_pci.o
obj-$(CONFIG_XENO_DRIVERS_CAN_SJA1000_EMS_PCI) += xeno_can_ems_pci.o
obj-$(CONFIG_XENO_DRIVERS_CAN_SJA1000_ISA) += xeno_can_isa.o
obj-$(CONFIG_XENO_DRIVERS_CAN_SJA1000_MEM) += xeno_can_mem.o

xeno_can_sja1000-y := rtcan_sja1000.o rtcan_sja1000_proc.o
xeno_can_peak_pci-y := rtcan_peak_pci.o
xeno_can_peak_dng-y := rtcan_peak_dng.o
xeno_can_ixxat_pci-y := rtcan_ixxat_pci.o
xeno_can_ems_pci-y := rtcan_ems_pci.o
xeno_can_isa-y := rtcan_isa.o
xeno_can_mem-y := rtcan_mem.o

else

# Makefile frag for Linux v2.4

O_TARGET := built-in.o

obj-$(CONFIG_XENO_DRIVERS_CAN_SJA1000) += xeno_can_sja1000.o 
obj-$(CONFIG_XENO_DRIVERS_CAN_SJA1000_PEAK_PCI) += xeno_can_peak_pci.o 
obj-$(CONFIG_XENO_DRIVERS_CAN_SJA1000_PEAK_DNG) += xeno_can_peak_dng.o 
obj-$(CONFIG_XENO_DRIVERS_CAN_SJA1000_IXXAT_PCI) += xeno_can_ixxat_pci.o
obj-$(CONFIG_XENO_DRIVERS_CAN_SJA1000_EMS_PCI) += xeno_can_ems_pci.o
obj-$(CONFIG_XENO_DRIVERS_CAN_SJA1000_ISA) += xeno_can_isa.o 
obj-$(CONFIG_XENO_DRIVERS_CAN_SJA1000_MEM) += xeno_can_mem.o

list-multi := xeno_can_sja1000.o 

xeno_can_sja1000-objs := rtcan_sja1000.o rtcan_sja1000_proc.o
xeno_can_peak_pci-objs := rtcan_peak_pci.o
xeno_can_peak_dng-objs := rtcan_peak_dng.o
xeno_can_ixxat_pci-objs := rtcan_ixxat_pci.o
xeno_can_ems_pci-objs := rtcan_ems_pci.o
xeno_can_isa-objs := rtcan_isa.o
xeno_can_mem-objs := rtcan_mem.o

export-objs := $(xeno_can_sja1000-objs)

EXTRA_CFLAGS += -D__IN_XENOMAI__ -I$(TOPDIR)/include/xenomai -I$(TOPDIR)/include/xenomai/compat -I..  -I.

include $(TOPDIR)/Rules.make

xeno_can_sja1000.o: $(xeno_can_sja1000-objs)
	$(LD) -r -o $@ $(xeno_can_sja1000-objs)

xeno_can_peak_pci.o: $(xeno_can_peak_pci-objs)
	$(LD) -r -o $@ $(xeno_can_peak_pci-objs)

xeno_can_peak_dng.o: $(xeno_can_peak_dng-objs)
	$(LD) -r -o $@ $(xeno_can_peak_dng-objs)

xeno_can_ixxat_pci.o: $(xeno_can_ixxat_pci-objs)
	$(LD) -r -o $@ $(xeno_can_ixxat_pci-objs)

xeno_can_ems_pci.o: $(xeno_can_ems_pci-objs)
	$(LD) -r -o $@ $(xeno_can_ems_pci-objs)

xeno_can_isa.o: $(xeno_can_isa-objs)
	$(LD) -r -o $@ $(xeno_can_isa-objs)

xeno_can_mem.o: $(xeno_can_mem-objs)
	$(LD) -r -o $@ $(xeno_can_mem-objs)
endif
