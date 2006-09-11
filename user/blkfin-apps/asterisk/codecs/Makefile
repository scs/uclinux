#
# Asterisk -- A telephony toolkit for Linux.
# 
# Makefile for PBX frontends (dynamically loaded)
#
# Copyright (C) 1999, Mark Spencer
#
# Mark Spencer <markster@linux-support.net>
#
# This program is free software, distributed under the terms of
# the GNU General Public License
#
# Modified by David Rowe May 2006 for static modules

include ../Makefile.include
CODECS = $(patsubst %.so, %.la, $(CODECS_SO))


#
# Uncomment if you have g723.1 code (with the same API as the Annex-A code
# and have placed it in the g723.1 directory and/or the Annex-B code in 
# g723.1b)
#
#MODG723=codec_g723_1.so codec_g723_1b.so
#MODG723=$(shell [ -f g723.1/coder.c ] && echo "codec_g723_1.so")
#MODG723+=$(shell [ -f g723.1b/coder2.c ] && echo "codec_g723_1b.so")
#MODSPEEX=$(shell [ -f /usr/include/speex.h ] || [ -f /usr/include/speex/speex.h ] || [ -f /usr/local/include/speex.h ] || [ -f /usr/local/include/speex/speex.h ] && echo "codec_speex.so")
#MODILBC=$(shell [ -f ilbc/iLBC_decode.h ] && echo "codec_ilbc.so")
#CFLAGS+=-fPIC
#CFLAGS+=$(shell [ -f /usr/local/include/speex.h ] && echo "-I/usr/local/include")
#CFLAGS+=$(shell [ -f /usr/local/include/speex/speex.h ] && echo "-I/usr/local/include/speex")
#CFLAGS+=$(shell [ -f /usr/include/speex/speex.h ] && echo "-I/usr/include/speex")

#LIBG723=g723.1/libg723.a
#LIBG723B=g723.1b/libg723b.a
#LIBGSM=gsm/lib/libgsm.a
#LIBGSMT=gsm/lib/libgsm.a
#LIBLPC10=lpc10/liblpc10.a
#LIBSPEEX=$(shell [ -f /usr/local/lib/libspeex.a ] && echo "-L/usr/local/lib")
#LIBSPEEX+=-lspeex -lm
#LIBILBC=ilbc/libilbc.a


all: depend $(CODECS)

clean:
	rm -f *.la *.lo .depend

#$(LIBG723):
#	$(MAKE) -C g723.1 all

# GSM for the Blackfin is part of a separate package now

#gsm/lib/libgsm.a:
#	$(MAKE) -C gsm lib/libgsm.a

#$(LIBG723B):
#	$(MAKE) -C g723.1b all

#$(LIBLPC10):
#	$(MAKE) -C lpc10 all

#$(LIBILBC):
#	$(MAKE) -C ilbc all

#codec_ilbc.so: codec_ilbc.o $(LIBILBC)
#	$(CC) $(SOLINK) -o $@ $< $(LIBILBC)

#codec_g723_1.so : codec_g723_1.o $(LIBG723)
#	$(CC) $(SOLINK) -o $@ $< $(LIBG723)

#codec_g723_1b.o : codec_g723_1.c
#	$(CC) -c -o $@ $(CFLAGS) -DANNEX_B -Dsingle $<

#codec_g723_1b.so : codec_g723_1b.o $(LIBG723B)
#	$(CC) $(SOLINK) -o $@ $< $(LIBG723B) -lm

#codec_gsm.la: codec_gsm.lo

#codec_speex.so: codec_speex.o
#	$(CC) $(SOLINK) -o $@ $< $(LIBSPEEX)

#codec_lpc10.so: codec_lpc10.o $(LIBLPC10)
#	$(CC) $(SOLINK) -o $@ $< $(LIBLPC10) -lm

#%.so : %.o
#	$(CC) $(SOLINK) -o $@ $<

ifneq ($(wildcard .depend),)
include .depend
endif

install: all
	for x in $(CODECS_SO); do touch $(DESTDIR)$(MODULES_DIR)/$$x ; done

depend: .depend

.depend:
	../mkdep $(CFLAGS) `ls *.c`
