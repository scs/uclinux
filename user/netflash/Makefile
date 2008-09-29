ifndef CONFIG_USER_NETFLASH_NETFLASH
# Not running under the uClinux build environment,
# so build a host version for debugging.
CFLAGS += -g -I../../include -DHOSTBUILD -DEMBED
LIBCRYPTO = -lcrypto
-include ../../config/.config
endif

CFLAGS += -Wall

EXEC = netflash
OBJS = tftpmain.o tftp.o tftpsubs.o http.o fileblock_ram.o
COBJS = netflash.o

ifdef CONFIG_USER_NETFLASH_WITH_FTP
CPPLAGS += -DFTP
OBJS += cmds.o cmdtab.o domacro.o ftp.o glob.o ftpmain.o ruserpass.o
endif

ifdef CONFIG_USER_NETFLASH_WITH_CGI
OBJS += cgi.o cgiparse.o kmp.o
endif

ifdef CONFIG_USER_NETFLASH_HMACMD5
EXEC += hmacmd5
OBJS += md5.o hmacmd5.o
endif

ifdef HW_COMPAT_VENDOR
CPPFLAGS += -DVENDOR=\"$(HW_COMPAT_VENDOR)\"
else
ifdef HW_VENDOR
CPPFLAGS += -DVENDOR=\"$(HW_VENDOR)\"
else
CPPFLAGS += -DVENDOR=\"$(CONFIG_VENDOR)\"
endif
endif

ifdef HW_COMPAT_PRODUCT
CPPFLAGS += -DPRODUCT=\"$(HW_COMPAT_PRODUCT)\"
else
ifdef HW_PRODUCT
CPPFLAGS += -DPRODUCT=\"$(HW_PRODUCT)\"
else
CPPFLAGS += -DPRODUCT=\"$(CONFIG_PRODUCT)\"
endif
endif

CPPFLAGS += -DVERSION=\"$(VERSIONPKG)\"
COBJS += versioning.o

ifdef CONFIG_USER_NETFLASH_DECOMPRESS
ADD_LIBZ  = -lz
endif

ifdef CONFIG_USER_NETFLASH_SETSRC
CPPFLAGS += -DSETSRC
endif

ifdef CONFIG_USER_NETFLASH_CRYPTO
CFLAGS += -I$(ROOTDIR)/include/aes
ADD_LIBZ += $(LIBAES) $(LIBCRYPTO)
endif
ifdef CONFIG_USER_NETFLASH_SHA256
ADD_LIBZ += $(LIBCRYPTO)
EXEC += sha256sum
endif

CPPFLAGS += -Dnetflashmain=main
# CPPFLAGS += -DDEBUG_CGI


all: $(EXEC)

netflash: $(OBJS) build_netflash build_versioning
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(COBJS) $(ADD_LIBZ) $(LDLIBS$(LDLIBS_$@))


build_netflash:
	$(CC) -c -o netflash.o netflash.c $(CFLAGS) $(CPPFLAGS)

build_versioning:
	$(CC) -c -o versioning.o versioning.c $(CFLAGS) $(CPPFLAGS)

hmacmd5: hmacmd5main.c hmacmd5.c md5.c
	gcc -o $@ $^

sha256sum: sha256sum.c sha256.c
	gcc -o $@ $^

versiontest: versioning.c
	gcc -DVERSIONTEST -o $@ $^

romfs:
	$(ROMFSINST) /bin/netflash

clean:
	-rm -f netflash hmacmd5 sha256sum *.elf *.gdb *.o

