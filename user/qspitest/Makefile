EXECS = qspitest qspirx

all: $(EXECS)

$(EXECS):
	$(CC) $(LDFLAGS) -o $@ $@.c $(LDLIBS)

romfs:
	$(ROMFSINST) -e CONFIG_USER_QSPITEST_TEST  /bin/qspitest
	$(ROMFSINST) -e CONFIG_USER_QSPITEST_RX    /bin/qspirx

#	cd $(ROMFSDIR); \
#		echo "#!/bin/sh" > etc/rc.qspi; \
#		echo insmod /`find lib -name mcf_qspi.o` >> etc/rc.qspi; \
#		chmod +x etc/rc.qspi

# Add an option to install the module at boot time?
#	$(ROMFSINST) -a "/sbin/insmod `find lib -name mcf_qspi.o`" /etc/rc

clean:
	rm -f $(EXECS) *.elf *.gdb *.[oa] *~ core 
