.EXPORT_ALL_VARIABLES:

# Define the directories we are going to build.
# There are four base targets present here:
#	nessus-libraries libnasl nessus-core nessus-plugins

ALL_DIRS   := nessus-libraries libnasl
BUILD_DIRS :=
ifdef CONFIG_USER_NESSUS_NASL
BUILD_DIRS += libnasl
endif

.PHONY: all romfs clean
.PHONY: nessus-libraries libnasl nessus-core nessus-plugins

all: $(BUILD_DIRS)

clean:
	rm -rf lib
	-for i in $(ALL_DIRS) ; do $(MAKE) -C $$i distclean ; done

romfs:
	$(ROMFSINST) -e CONFIG_USER_NESSUS_NASL libnasl/nasl/nasl /bin/nasl

# The base libraries are needed for everything
nessus-libraries/config.status: Makefile
	-$(MAKE) -C nessus-libraries distclean
	cd nessus-libraries ; \
	chmod 755 configure; \
	CC="$(CC) $(CFLAGS)" LDFLAGS="$(LDFLAGS)" \
			LIBS="$(patsubst %.o,,$(LDLIBS)) -lresolv" \
		./configure --host=$(CROSS_COMPILE:-=) \
			--disable-fast-install --disable-shared	\
			--cache-file config.cache \
			--prefix=

nessus-libraries: nessus-libraries/config.status
	$(MAKE) -C nessus-libraries
	[ -d lib ] || mkdir lib
	cp `find nessus-libraries -type f -name '*.a'` lib/

# Includes the NASL scripting language
libnasl/config.status: Makefile
	-$(MAKE) -C libnasl distclean
	cd libnasl ; 						\
	chmod 755 configure;					\
	export LDFLAGS='-lc';					\
	export PATH="../nessus-libraries:$$PATH";		\
	CC="$(CC) $(CFLAGS)" LDFLAGS="$(LDFLAGS)" \
			LIBS="$(patsubst %.o,,$(LDLIBS)) -lresolv" \
		./configure --host=$(CROSS_COMPILE:-=) \
			--disable-fast-install --disable-shared	\
			--cache-file config.cache \
			--prefix=

libnasl: nessus-libraries libnasl/config.status
	$(MAKE) -C libnasl || exit $$?
	#cp `find nessus-libraries -type f -name '*.a'` lib/

# Not ported. Includes nessus and nessusd
nessus-core: libnasl

# Not ported. The scripts etc
nessus-plugins: nessus-core

