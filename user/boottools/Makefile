EXECS = printbenv setbenv reset consume
SOURCES = xloader.c printbenv.c setbenv.c reset.c consume.c
CFLAGS += -I./include

all: md5.o xloader $(EXECS)

md5.o:	md5.c md5.h
	$(CC) $(LDFLAGS) -c md5.c

$(EXECS): $(SOURCES)
	$(CC) $(LDFLAGS) -o $@ $@.c $(LDLIBS)

xloader: xloader.c md5.c md5.h
	$(CC) $(LDFLAGS) -o $@ $@.c md5.o $(LDLIBS)

romfs:
	$(ROMFSINST) -e CONFIG_USER_BOOTTOOLS_LOADER		/bin/xloader
	$(ROMFSINST) -e CONFIG_USER_BOOTTOOLS_LOADER	     -s /bin/xloader /bin/flashloader
	$(ROMFSINST) -e CONFIG_USER_BOOTTOOLS_LOADER         -s /bin/xloader /bin/ramloader
	$(ROMFSINST) -e CONFIG_USER_BOOTTOOLS_PRINTBENV		/bin/printbenv
	$(ROMFSINST) -e CONFIG_USER_BOOTTOOLS_SETBENV		/bin/setbenv
	$(ROMFSINST) -e CONFIG_USER_BOOTTOOLS_RESET		/bin/reset


# host development system tools for uCimage file manipulation:
uCbootstrap-tools:
	make -C uCbootstrap-tools

clean:
	rm -f $(EXECS) xloader *.elf *.gdb *.[oa] *~ core 
	make -C uCbootstrap-tools clean


.PHONY:	uCbootstrap-tools
