# Generated automatically from Makefile.in by configure.
#
# Generic Makefile for libedit.
#

SHELL = /bin/sh

CC = bfin-uclinux-gcc 
AR = /usr/bin/ar
RANLIB = bfin-uclinux-ranlib
CPPFLAGS = -I.  '-D__RCSID(x)=' '-D__COPYRIGHT(x)=' '-D__RENAME(x)=' '-D_DIAGASSERT(x)=' 
CFLAGS = -I. -pipe  -Wall -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -g  -Iinclude -I../include -D_REENTRANT -D_GNU_SOURCE  -O6    -DZAPTEL_OPTIMIZATIONS -DASTERISK_VERSION=\"1.0.9\" -DINSTALL_PREFIX=\"\" -DASTETCDIR=\"/etc/asterisk\" -DASTLIBDIR=\"/usr/lib/asterisk\" -DASTVARLIBDIR=\"/var/lib/asterisk\" -DASTVARRUNDIR=\"/var/run\" -DASTSPOOLDIR=\"/var/spool/asterisk\" -DASTLOGDIR=\"/var/log/asterisk\" -DASTCONFPATH=\"/etc/asterisk/asterisk.conf\" -DASTMODDIR=\"/usr/lib/asterisk/modules\" -DASTAGIDIR=\"/var/lib/asterisk/agi-bin\"     -DBUSYDETECT_MARTIN     -DLOW_MEMORY  -I/home/cvshdr/sandbox/uClinux-dist/lib/libtool/libltdl -I/home/cvshdr/sandbox/uClinux-dist/lib/libssl/include -I/home/cvshdr/sandbox/uClinux-dist/lib/ncurses/include -I/home/cvshdr/sandbox/uClinux-dist/lib/zlib -I/home/cvshdr/sandbox/uClinux-dist/user/blkfin-apps/threadstack-0.1 -I/home/cvshdr/sandbox/uClinux-dist/lib/blackfin-gsm/gsm/inc -I/home/cvshdr/sandbox/uClinux-dist/lib/speex/include/speex -I/home/cvshdr/sandbox/uClinux-dist/user/blkfin-apps/zaptel -O
A_CFLAGS = 
S_CFLAGS = -fPIC -DPIC
LDFLAGS = -Wl,-elf2flt
S_LDFLAGS = -shared
LIBS = -lncurses -lltdl -lm -lncurses -lssl -lz -lcrypto -ltonezone  -lpthread -lgsm -lspeex -lm  -L/home/cvshdr/sandbox/uClinux-dist/lib/libtool/libltdl/.libs/ -L/home/cvshdr/sandbox/uClinux-dist/lib/libssl -L/home/cvshdr/sandbox/uClinux-dist/lib/ncurses/lib  -L/home/cvshdr/sandbox/uClinux-dist/lib  /home/cvshdr/sandbox/uClinux-dist/user/blkfin-apps/threadstack-0.1/threadstack.o -lpthread  -L/home/cvshdr/sandbox/uClinux-dist/lib/blackfin-gsm/gsm/lib  -L/home/cvshdr/sandbox/uClinux-dist/lib/speex/libspeex/.libs  -L/home/cvshdr/sandbox/uClinux-dist/user/blkfin-apps/zaptel  -L/home/cvshdr/sandbox/uClinux-dist/user/blkfin-apps/asterisk/editline 

INSTALL = install
PREFIX = /home/cvshdr/uclinux-outcvs/uClinux-dist

# .c files.
ACSRCS = common.c emacs.c vi.c
BCSRCS = chared.c el.c hist.c key.c map.c parse.c prompt.c read.c refresh.c search.c sig.c term.c tty.c
CCSRCS =  np/fgetln.c np/vis.c np/unvis.c history.c tokenizer.c readline.c

# Generated .c files.
AGCSRCS = fcns.c help.c
BGCSRCS = editline.c

# .h files.
HDRS = chared.h el.h hist.h key.h map.h parse.h prompt.h refresh.h search.h sig.h sys.h term.h tokenizer.h tty.h

# Generated .h files.
AGHDRS = common.h emacs.h vi.h
BGHDRS = fcns.h help.h

# Installed .h files.
IHDRS = histedit.h readline/readline.h
IHDR_LINKS = readline.h readline/history.h
HDR_DIRS = include include/readline

# Man pages.
MAN3 = editline.3
MAN5 = editrc.5
MAN3_LINKS =  editline.3 el_init.3 editline.3 el_end.3 editline.3 el_reset.3 editline.3 el_gets.3 editline.3 el_getc.3 editline.3 el_push.3 editline.3 el_parse.3 editline.3 el_set.3 editline.3 el_get.3 editline.3 el_source.3 editline.3 el_resize.3 editline.3 el_line.3 editline.3 el_insertstr.3 editline.3 el_deletestr.3 editline.3 history_init.3 editline.3 history_end.3 editline.3 history.3
MAN_DIRS = man/man3 man/man5

# Library.
LIB_DIRS = lib
LIB_VER = 
LIB_A = libedit.a
LIB_A_LINKS =  libedit.a libreadline.a
LIB_S = libedit.so.2
LIB_S_LINKS = libedit.so.2 libedit.so libedit.so libreadline.so

# Test program.
TEST = TEST/test
TCSRCS = TEST/test.c

# Clear out all paths, then set just one (default path) for the main build
# directory.
.PATH :
.PATH : .

.SUFFIXES :
.SUFFIXES : .c .o .o_a .o_s

all :  lib_a lib_s

lib_a : $(LIB_A)
lib_s : $(LIB_S)

test : $(TEST)

install : install_hdr install_lib install_man

install_hdr :
	@for i in $(HDR_DIRS) ; do \
		echo "$(INSTALL) -d $(PREFIX)/$$i/"; \
		$(INSTALL) -d $(PREFIX)/$$i/; \
	done
	@for i in $(IHDRS); do \
		echo "$(INSTALL) -m 0444 $$i $(PREFIX)/include/`dirname $$i`/"; \
		$(INSTALL) -m 0444 $$i $(PREFIX)/include/`dirname $$i`/; \
	done
	@f=; \
	for i in $(IHDR_LINKS) ""; do \
		if test -z "$$f" ; then \
			f=$$i; \
		else \
			echo "rm -f $(PREFIX)/include/$$i"; \
			rm -f $(PREFIX)/include/$$i; \
			echo "ln -s $$f $(PREFIX)/include/$$i"; \
			ln -s $$f $(PREFIX)/include/$$i; \
			f=; \
		fi; \
	done

install_lib : install_lib_a install_lib_s

install_lib_common :
	@for i in $(LIB_DIRS) ; do \
		echo "$(INSTALL) -d $(PREFIX)/$$i/"; \
		$(INSTALL) -d $(PREFIX)/$$i/; \
	done

install_lib_a : $(LIB_A) install_lib_common
	$(INSTALL) -m 0644 $(LIB_A) $(PREFIX)/lib/
	@f=; \
	for i in $(LIB_A_LINKS) ""; do \
		if test -z "$$f" ; then \
			f=$$i; \
		else \
			echo "rm -f $(PREFIX)/lib/$$i"; \
			rm -f $(PREFIX)/lib/$$i; \
			echo "ln -s $$f $(PREFIX)/lib/$$i"; \
			ln -s $$f $(PREFIX)/lib/$$i; \
			f=; \
		fi; \
	done

install_lib_s : $(LIB_S) install_lib_common
	$(INSTALL) -m 0755 $(LIB_S) $(PREFIX)/lib/
	@f=; \
	for i in $(LIB_S_LINKS) ""; do \
		if test -z "$$f" ; then \
			f=$$i; \
		else \
			echo "rm -f $(PREFIX)/lib/$$i"; \
			rm -f $(PREFIX)/lib/$$i; \
			echo "ln -s $$f $(PREFIX)/lib/$$i"; \
			ln -s $$f $(PREFIX)/lib/$$i; \
			f=; \
		fi; \
	done

install_man :
	@for i in $(MAN_DIRS) ; do \
		echo "$(INSTALL) -d $(PREFIX)/$$i/"; \
		$(INSTALL) -d $(PREFIX)/$$i/; \
	done
	@for i in $(MAN3); do \
		echo $(INSTALL) -m 0444 $$i $(PREFIX)/man/man3/; \
		$(INSTALL) -m 0444 $$i $(PREFIX)/man/man3/; \
	done
	@f=; \
	for i in $(MAN3_LINKS) ""; do \
		if test -z "$$f" ; then \
			f=$$i; \
		else \
			echo "rm -f $(PREFIX)/man/man3/$$i"; \
			rm -f $(PREFIX)/man/man3/$$i; \
			echo "ln -s $$f $(PREFIX)/man/man3/$$i"; \
			ln -s $$f $(PREFIX)/man/man3/$$i; \
			f=; \
		fi; \
	done
	@for i in $(MAN5); do\
		echo $(INSTALL) -m 0444 $$i $(PREFIX)/man/man5/; \
		$(INSTALL) -m 0444 $$i $(PREFIX)/man/man5/; \
	done

clean :
	rm -f $(AGCSRCS) $(BGCSRCS) $(AGHDRS) $(BGHDRS) $(LIB_A) $(LIB_S)
	rm -f $(BGCSRCS:.c=.o_a) $(CCSRCS:.c=.o_a)
	rm -f $(BGCSRCS:.c=.o_s) $(CCSRCS:.c=.o_s)
	rm -f $(TCSRCS:.c=.o) $(TEST)

distclean : clean
	rm -f config.cache config.log config.status config.h Makefile

#
# Internal targets and rules.
#

$(LIB_A) : $(BGCSRCS:.c=.o_a) $(CCSRCS:.c=.o_a)
	$(AR) cru $@ $?
	$(RANLIB) $@

$(LIB_S) : $(BGCSRCS:.c=.o_s) $(CCSRCS:.c=.o_s)
	$(CC) $(S_LDFLAGS) -o $@ $(BGCSRCS:.c=.o_s) $(CCSRCS:.c=.o_s)

$(TEST) : $(TCSRCS:.c=.o) $(LIB_A)
	$(CC) -o $@ $(TCSRCS:.c=.o) $(LIB_A) $(LIBS)

common.h : common.c
	$(SHELL) makelist -h common.c > $@

emacs.h : emacs.c
	$(SHELL) makelist -h emacs.c> $@

vi.h : vi.c
	$(SHELL) makelist -h vi.c > $@

fcns.h : $(AGHDRS)
	$(SHELL) makelist -fh $(AGHDRS) > $@

fcns.c : $(AGHDRS) fcns.h
	$(SHELL) makelist -fc $(AGHDRS) > $@

help.h : $(ACSRCS)
	$(SHELL) makelist -bh $(ACSRCS) > $@

help.c : $(ACSRCS) help.h
	$(SHELL) makelist -bc $(ACSRCS) > $@

editline.c : $(ACSRCS) $(BCSRCS) $(AGCSRCS)
	$(SHELL) makelist -e $(ACSRCS) $(BCSRCS) $(AGCSRCS) > $@

.c.o :
	$(CC) -c $(A_CFLAGS) $(CFLAGS) $(CPPFLAGS) $< -o $@

.c.o_a : $(AGHDRS) $(BGHDRS)
	$(CC) -c $(A_CFLAGS) $(CFLAGS) $(CPPFLAGS) $< -o $@

.c.o_s : $(AGHDRS) $(BGHDRS)
	$(CC) -c $(S_CFLAGS) $(CFLAGS) $(CPPFLAGS) $< -o $@
