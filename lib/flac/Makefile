all: my-build/Makefile
	$(MAKE) -C my-build install DESTDIR=$(STAGEDIR)

my-build/Makefile:
	find . -type f -print0 | xargs -0 touch -r configure
	set -e ; \
	rm -rf my-build ; \
	mkdir my-build ; \
	cd my-build ; \
	../configure $(CONFIGURE_OPTS)

clean:
	rm -rf my-build

romfs:

.PHONY: all clean romfs
