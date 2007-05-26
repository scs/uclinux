CONFTARGET := --build=$(shell config.guess) $(CONFIGURE_OPTS)

CONFOPTS += --with-readline --disable-nls

ifdef CONFIG_USER_GDB_TARGET
	TARGETS += build/target
else
	ifdef CONFIG_USER_GDB_GDBSERVER
		TARGETS += build/build
	endif
	ifdef CONFIG_USER_GDB_GDBREPLAY
		TARGETS += build/build
	endif
endif
ifdef CONFIG_USER_GDB_HOST
	TARGETS += host/build
endif

all: $(TARGETS)
	$(MAKE) -C build
	if [ "$(CONFIG_USER_GDB_HOST)" == "y" ]; then 	\
		$(MAKE) -C host;			\
	fi

build/build: makefile
	rm -rf build
	mkdir build
	(cd build; sh ../gdb/gdbserver/configure $(CONFTARGET) $(CONFOPTS))
	touch $@

build/target: makefile
	rm -rf build
	mkdir build
	(cd build; sh ../configure $(CONFTARGET)  $(CONFOPTS) )
	touch $@

host/build: makefile
	rm -rf host
	mkdir host
	(cd host; CC= CFLAGS= ../configure $(CONFIGURE_OPTS))
	touch $@

clean:
	rm -rf build host

romfs:
ifdef CONFIG_USER_GDB_TARGET
	$(ROMFSINST) build/gdb/gdb /bin/gdb
	$(ROMFSINST) -e CONFIG_USER_GDB_GDBSERVER build/gdb/gdbserver/gdbserver /bin/gdbserver
	$(ROMFSINST) -e CONFIG_USER_GDB_GDBREPLAY build/gdb/gdbreplay/gdbreplay /bin/gdbreplay
else
	$(ROMFSINST) -e CONFIG_USER_GDB_GDBSERVER build/gdbserver /bin/gdbserver
	$(ROMFSINST) -e CONFIG_USER_GDB_GDBREPLAY build/gdbreplay /bin/gdbreplay
endif
