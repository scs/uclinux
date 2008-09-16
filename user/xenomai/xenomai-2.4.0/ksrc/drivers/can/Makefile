ifeq ($(PATCHLEVEL),6)

# Makefile frag for Linux v2.6

EXTRA_CFLAGS += -D__IN_XENOMAI__ -Iinclude/xenomai -Idrivers/xenomai/can

obj-$(CONFIG_XENO_DRIVERS_CAN) += xeno_can.o mscan/ sja1000/
obj-$(CONFIG_XENO_DRIVERS_CAN_VIRT) += xeno_can_virt.o

xeno_can-y := rtcan_dev.o rtcan_socket.o rtcan_module.o rtcan_raw.o rtcan_raw_dev.o rtcan_raw_filter.o
xeno_can_virt-y := rtcan_virt.o

else

# Makefile frag for Linux v2.4

mod-subdirs := mscan sja1000

subdir-$(CONFIG_XENO_DRIVERS_CAN_MSCAN) += mscan
subdir-$(CONFIG_XENO_DRIVERS_CAN_SJA1000) += sja1000

O_TARGET := built-in.o

obj-$(CONFIG_XENO_DRIVERS_CAN) += xeno_can.o
obj-$(CONFIG_XENO_DRIVERS_CAN_VIRT) += xeno_can_virt.o

list-multi := xeno_can.o

xeno_can-objs := rtcan_dev.o rtcan_socket.o rtcan_module.o rtcan_raw.o rtcan_raw_dev.o rtcan_raw_filter.o
xeno_can_virt-objs := rtcan_virt.o

export-objs := $(xeno_can-objs)

EXTRA_CFLAGS += -D__IN_XENOMAI__ -I$(TOPDIR)/include/xenomai -I$(TOPDIR)/include/xenomai/compat -I.

include $(TOPDIR)/Rules.make

xeno_can.o: $(xeno_can-objs)
	$(LD) -r -o $@ $(xeno_can-objs)

xeno_can_virt.o: $(xeno_can_virt-objs)
	$(LD) -r -o $@ $(xeno_can_virt-objs)

endif
