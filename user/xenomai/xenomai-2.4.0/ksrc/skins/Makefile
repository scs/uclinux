ifeq ($(PATCHLEVEL),6)

# Makefile frag for Linux v2.6

obj-$(CONFIG_XENOMAI) += native/ posix/ rtdm/ psos+/ vrtx/ vxworks/ uitron/ rtai/

else

# Makefile frag for Linux v2.4

subdir-$(CONFIG_XENO_SKIN_NATIVE) += native
subdir-$(CONFIG_XENO_SKIN_POSIX) += posix
subdir-$(CONFIG_XENO_SKIN_RTDM) += rtdm
subdir-$(CONFIG_XENO_SKIN_PSOS) += psos+
subdir-$(CONFIG_XENO_SKIN_VRTX) += vrtx
subdir-$(CONFIG_XENO_SKIN_VXWORKS) += vxworks
subdir-$(CONFIG_XENO_SKIN_UITRON) += uitron
subdir-$(CONFIG_XENO_SKIN_RTAI) += rtai

include $(TOPDIR)/Rules.make

endif
