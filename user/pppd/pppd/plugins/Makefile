CFLAGS += -I../../include -I.. -Itacc/include -Wall

.PHONY: tacacs
tacacs: tacacs.o
	make -C tacc/lib libtac.a


.PHONY: pppoe
pppoe: libpppoe.a

libpppoe.a:
	make -f Makefile.linux -C pppoe libpppoe.a

clean:
	make -C tacc/lib clean
	make -f Makefile.linux -C pppoe clean
	-rm -f *.o
