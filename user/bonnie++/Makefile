DIRS = $(dir $(wildcard */configure))

all:
	set -e ; \
	for d in $(DIRS) ; do \
		cd $(DIRS) ;\
		./configure $(CONFIGURE_OPTS) ;\
		$(MAKE) || exit $$? ;\
	done

clean:
	set -e ; \
	for d in $(DIRS) ; do \
		cd $(DIRS) ;\
		$(MAKE) realclean ;\
		rm -f *.gdb ;\
	done

romfs:
	$(ROMFSINST) -d ./bonnie++-1.94/bonnie++ /usr/bin/bonnie++

.PHONY: all clean romfs
