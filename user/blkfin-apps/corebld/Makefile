SUBDIRS = example test_module

all: corebld all_subdirs

clean: clean_subdirs
	rm -f corebld corebld.gdb

romfs: romfs_subdirs

%_subdirs:
	for d in $(SUBDIRS) ; do $(MAKE) -C $$d $(@:_subdirs=) || exit $$? ; done

.PHONY: all clean romfs
