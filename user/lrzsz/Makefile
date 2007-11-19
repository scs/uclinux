FLTFLAGS += -s 16384

SUBDIRS = lib src 


SHUTDOWN = shutdown
SHUTDOWNOBJS = shutdown.o

LIBZMODEM = lib/libzmodem.a

all:
	list='$(SUBDIRS)'; for subdir in $$list; do \
	  target=$@ \
	  echo "Making $$target in $$subdir"; \
	  (cd $$subdir && $(MAKE) $$target) \
	  || case "$$amf" in *=*) exit 1;; *k*) fail=yes;; *) exit 1;; esac; \
	done && test -z "$$fail"


$(LIBZMODEM): dummy_target
	$(MAKE) -C lib

romfs:
	make -C src romfs
	$(ROMFSINST) -e CONFIG_USER_LRZSZ_LSZ -s lsz /bin/sz
	$(ROMFSINST) -e CONFIG_USER_LRZSZ_LRZ -s lrz /bin/rz

clean:
	-rm -f $(SH) $(SHUTDOWN) $(REBOOT) *.elf *.gdb *.o
	$(MAKE) -C lib clean
	$(MAKE) -C src clean

