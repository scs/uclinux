# $Header$

CFLAGS+=-Wall -Wshadow

OFILES = tpt.o util.o build.o dump.o massage.o

tpt: $(OFILES)

romfs:
	$(ROMFSINST) /bin/tpt

$(OFILES): tpt.h

clean:
	rm -f $(OFILES) tpt
