ifndef CFLAGS
CFLAGS = -O2 -Wall
endif

# Include directory for CVS version
CFLAGS += -I../driver/modules

all: prism2_srec hostap_crypt_conf hostap_diag hostap_io_debug hostap_rid

prism2_srec: prism2_srec.o util.o

prism2_srec.o: prism2_srec.c util.h

hostap_crypt_conf: hostap_crypt_conf.c

hostap_diag: hostap_diag.o util.o
	$(CC) -o hostap_diag $(CFLAGS) hostap_diag.o util.o

hostap_diag.o: hostap_diag.c util.h

util.o: util.c util.h

hostap_io_debug: hostap_io_debug.c
	$(CC) -o hostap_io_debug $(CFLAGS) hostap_io_debug.c

hostap_rid: hostap_rid.o util.o
	$(CC) -o hostap_rid $(CFLAGS) hostap_rid.o util.o

hostap_rid.o: hostap_rid.c util.h

clean:
	rm -f prism2_srec hostap_crypt_conf hostap_diag hostap_rid *.o
