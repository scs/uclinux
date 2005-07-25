EXECS = himemloader xloader printbenv setbenv reset
SOURCES = himemloader.c xloader.c printbenv.c setbenv.c reset.c
CFLAGS += -I./include

all: $(EXECS)

$(EXECS): $(SOURCES)
	$(CC) $(LDFLAGS) -o $@ $@.c $(LDLIBS)

romfs:
	$(ROMFSINST) -e CONFIG_USER_BOOTTOOLS_LOADER		/bin/xloader
	$(ROMFSINST) -e CONFIG_USER_BOOTTOOLS_LOADER		/bin/himemloader
	$(ROMFSINST) -e CONFIG_USER_BOOTTOOLS_LOADER	     -s /bin/xloader /bin/flashloader
	$(ROMFSINST) -e CONFIG_USER_BOOTTOOLS_LOADER         -s /bin/xloader /bin/ramloader
	$(ROMFSINST) -e CONFIG_USER_BOOTTOOLS_PRINTBENV		/bin/printbenv
	$(ROMFSINST) -e CONFIG_USER_BOOTTOOLS_SETBENV		/bin/setbenv
	$(ROMFSINST) -e CONFIG_USER_BOOTTOOLS_RESET		/bin/reset
#	$(ROMFSINST)						/bin/consume

clean:
	rm -f $(EXECS) *.elf *.gdb *.[oa] *~ core 
