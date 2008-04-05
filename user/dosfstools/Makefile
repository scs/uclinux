VER = dosfstools-2.10

all clean romfs:
ifeq ($(CONFIG_USER_DOSFSTOOLS_MKDOSFS),y)
	$(MAKE) -C $(VER)/mkdosfs $@
endif
ifeq ($(CONFIG_USER_DOSFSTOOLS_DOSFSCK),y)
	$(MAKE) -C $(VER)/dosfsck $@
endif

.PHONY: all clean romfs
