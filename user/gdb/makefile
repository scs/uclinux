all: Makefile
	$(MAKE) -f Makefile
	( \
	export CC="$(CC) $(CFLAGS)"; \
	export LDFLAGS="$(LDFLAGS) $(LDLIBS)"; \
	cd gdb/gdbserver; \
	./configure --build=i386-redhat-linux --host=i386-redhat-linux --target $(CROSS_COMPILE:-=) ; \
	make ; \
    )

Makefile:
	( \
	unset CC; \
	unset LDFLAGS; \
	unset LIBS; \
	unset CFLAGS; \
	./configure --build=i386-redhat-linux --host=i386-redhat-linux --target=$(CROSS_COMPILE:-=) \
	)
clean: Makefile
	$(MAKE) -f Makefile clean
romfs:
	$(ROMFSINST) -e CONFIG_USER_GDB_GDBSERVER gdb/gdbserver/gdbserver /bin/gdbserver
	$(ROMFSINST) -e CONFIG_USER_GDB_GDBREPLAY gdb/gdbserver/gdbreplay /bin/gdbreplay
