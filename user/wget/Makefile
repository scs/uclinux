VER = wget-1.9.1

all: build-$(VER)/Makefile
	$(MAKE) -C build-$(VER)

build-$(VER)/Makefile:
	find $(VER) -type f -print0 | xargs -0 touch -r $(VER)/configure
	set -e ; \
	rm -rf build-$(VER) ; \
	mkdir build-$(VER) ; \
	cd build-$(VER) ; \
	( \
		export CC="$(CC) $(CFLAGS)"; \
		export LDFLAGS="$(LDFLAGS)"; \
		export LIBS="$(LDLIBS)"; \
		../$(VER)/configure $(CONFIGURE_OPTS) --prefix= ; \
	)

clean:
	rm -rf build*

romfs:
	$(ROMFSINST) build-$(VER)/src/wget /bin/wget

.PHONY: all clean romfs
