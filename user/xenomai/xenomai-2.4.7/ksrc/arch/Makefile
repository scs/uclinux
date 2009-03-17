ifeq ($(PATCHLEVEL),6)

# Makefile frag for Linux v2.6

obj-$(CONFIG_XENOMAI) += generic/

else

# Makefile frag for Linux v2.4

subdir-y += generic

include $(TOPDIR)/Rules.make

endif
