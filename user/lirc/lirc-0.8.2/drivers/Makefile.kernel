
EXTRA_CFLAGS += $(LIRC_EXTRA_CFLAGS)

obj-m=$(module_DATA)
MI_OBJS      = $(module_DATA)

all clean:
	$(warning **************************************************)
	$(warning *** Makefile trick not undone, trying to recover *)
	$(warning **************************************************)
	mv Makefile.automake Makefile
	$(MAKE) $@

# The following is needed for 2.5 kernels and also let's the makefile work
# when things get screwed.
ifneq (,$(wildcard $(KERNEL_LOCATION)/Rules.make))
include $(KERNEL_LOCATION)/Rules.make
endif
