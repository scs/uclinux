VER = bzip2-1.0.5

FILES = blocksort.c huffman.c crctable.c randtable.c compress.c decompress.c bzlib.c
VFILES = $(patsubst %,$(VER)/%,$(FILES) bzip2.c)
OBJS = $(FILES:.c=.o)
LIBS-y =
LIBS-$(CONFIG_FMT_USE_FDPIC_ELF) += $(VER)/libbz2.so.1
LIBS-y += $(VER)/libbz2.a
BINS = $(LIBS-y) $(VER)/bzip2

all: $(BINS)
	install -D -m 644 $(VER)/bzlib.h $(STAGEDIR)/include/bzlib.h
	install -D -m 644 $(VER)/libbz2.a $(STAGEDIR)/lib/libbz2.a
	set -e ; \
	if test -e $(VER)/libbz2.so.1 ; then \
		install -D -m 755 $(VER)/libbz2.so.1 $(STAGEDIR)/lib/libbz2.so.1 ; \
		ln -sf libbz2.so.1 $(STAGEDIR)/lib/libbz2.so ; \
	fi

$(VER)/libbz2.a: $(VFILES)
	set -e ; \
	cd $(VER) ; \
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $(FILES) ; \
	$(AR) rc $(notdir $@) $(FILES:.c=.o) ; \
	$(RANLIB) $(notdir $@)

$(VER)/libbz2.so.1: $(VFILES)
	set -e ; \
	cd $(VER) ; \
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -fPIC -shared -Wl,-soname,libbzip2.so.1 $(FILES) -o $(notdir $@)

$(VER)/bzip2: $(LIBS-y)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $@.c $<

clean:
	rm -f $(BINS) $(VER)/*.o

romfs:
	$(ROMFSINST) -e CONFIG_USER_BZIP2_BZIP2 $(VER)/bzip2 /bin/bzip2
	$(ROMFSINST) -e CONFIG_USER_BZIP2_BZIP2 -s bzip2 /bin/bunzip2
	$(ROMFSINST) -e CONFIG_USER_BZIP2_BZIP2 -s bzip2 /bin/bzcat
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/lib/libbz2.so.1 /lib/libbz2.so.1

.PHONY: all clean romfs
