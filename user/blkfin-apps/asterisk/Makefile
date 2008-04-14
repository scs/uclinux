#
# Asterisk -- A telephony toolkit for Linux.
# 
# Top level Makefile
#
# Copyright (C) 1999, Mark Spencer
#
# Mark Spencer <markster@linux-support.net>
#
# This program is free software, distributed under the terms of
# the GNU General Public License
#

.EXPORT_ALL_VARIABLES:

AR=$(CROSS_COMPILE)ar
AS=$(CROSS_COMPILE)as
LD=$(CROSS_COMPILE)ld
NM=$(CROSS_COMPILE)nm 
CC=$(CROSS_COMPILE)gcc 
GCC=$(CROSS_COMPILE)gcc 
CXX=$(CROSS_COMPILE)g++ 
RANLIB=$(CROSS_COMPILE)ranlib

# Create OPTIONS variable
OPTIONS=

OSARCH=Linux

ifeq (${OSARCH},Linux)
MPG123TARG=linux
endif

ifeq ($(findstring BSD,${OSARCH}),BSD)
PROC=$(shell uname -m)
endif

# Pentium Pro Optimize
#PROC=i686

# Pentium & VIA processors optimize
#PROC=i586

#PROC=k6
#PROC=ppc
PROC=bfin-uclinux

PWD=$(shell pwd)
ASTERISKDIR=$(PWD)/ipkg/asterisk

######### More GSM codec optimization
######### Uncomment to enable MMXTM optimizations for x86 architecture CPU's
######### which support MMX instructions.  This should be newer pentiums,
######### ppro's, etc, as well as the AMD K6 and K7.  
#K6OPT  = -DK6OPT

#Tell gcc to optimize the asterisk's code
OPTIMIZE+=-O6

#Include debug symbols in the executables (-g) and profiling info (-pg)
DEBUG=-g #-pg

# If you are running a radio application, define RADIO_RELAX so that the DTMF
# will be received more reliably
#OPTIONS += -DRADIO_RELAX

# If you don't have a lot of memory (e.g. embedded Asterisk), uncomment the
# following to reduce the size of certain static buffers
OPTIONS += -DLOW_MEMORY

# Optional debugging parameters
DEBUG_THREADS = #-DDEBUG_THREADS #-DDO_CRASH 

# Uncomment next one to enable ast_frame tracing (for debugging)
TRACE_FRAMES = #-DTRACE_FRAMES

# Uncomment next one to enable malloc debugging
# You can view malloc debugging with:
#   *CLI> show memory allocations [filename]
#   *CLI> show memory summary [filename]
#
MALLOC_DEBUG = #-include $(PWD)/include/asterisk/astmm.h

# Where to install asterisk after compiling
# Default -> leave empty
INSTALL_PREFIX=

# Staging directory
# Files are copied here temporarily during the install process
# For example, make DESTDIR=/tmp/asterisk woud put things in
# /tmp/asterisk/etc/asterisk
DESTDIR=

# Original busydetect routine
BUSYDETECT = #-DBUSYDETECT

# Improved busydetect routine, comment the previous one if you use this one
BUSYDETECT+= -DBUSYDETECT_MARTIN 
# Detect the busy signal looking only at tone lengths
# For example if you have 3 beeps 100ms tone, 100ms silence separated by 500 ms of silence
BUSYDETECT+= #-DBUSYDETECT_TONEONLY
# Inforce the detection of busy singal (get rid of false hangups)
# Don't use together with -DBUSYDETECT_TONEONLY
BUSYDETECT+= #-DBUSYDETECT_COMPARE_TONE_AND_SILENCE

ASTLIBDIR=$(INSTALL_PREFIX)/usr/lib/asterisk
ASTVARLIBDIR=$(INSTALL_PREFIX)/var/lib/asterisk
ASTETCDIR=$(INSTALL_PREFIX)/etc/asterisk
ASTSPOOLDIR=$(INSTALL_PREFIX)/var/spool/asterisk
ASTLOGDIR=$(INSTALL_PREFIX)/var/log/asterisk
ASTHEADERDIR=$(INSTALL_PREFIX)/usr/include/asterisk
ASTCONFPATH=$(ASTETCDIR)/asterisk.conf
ASTBINDIR=$(INSTALL_PREFIX)/usr/bin
ASTSBINDIR=$(INSTALL_PREFIX)/usr/sbin
ASTVARRUNDIR=$(INSTALL_PREFIX)/var/run
ASTMANDIR=$(INSTALL_PREFIX)/usr/share/man

MODULES_DIR=$(ASTLIBDIR)/modules
AGI_DIR=$(ASTVARLIBDIR)/agi-bin

INCLUDE=-Iinclude -I../include
CFLAGS+=-pipe  -Wall -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations $(DEBUG) $(INCLUDE) -D_REENTRANT -D_GNU_SOURCE #-DMAKE_VALGRIND_HAPPY
CFLAGS+=$(OPTIMIZE)

ifneq ($(PROC),ultrasparc)
CFLAGS+=$(shell if $(CC) -march=$(PROC) -S -o /dev/null -xc /dev/null >/dev/null 2>&1; then echo "-march=$(PROC)"; fi)
endif

CFLAGS+=$(shell if uname -m | grep -q ppc; then echo "-fsigned-char"; fi)
CFLAGS+=$(shell if [ -f /usr/include/osp/osp.h ]; then echo "-DOSP_SUPPORT -I/usr/include/osp" ; fi)

ifeq (${OSARCH},FreeBSD)
OSVERSION=$(shell make -V OSVERSION -f /usr/share/mk/bsd.port.subdir.mk)
CFLAGS+=$(shell if test ${OSVERSION} -lt 500016 ; then echo "-D_THREAD_SAFE"; fi)
LIBS+=$(shell if test  ${OSVERSION} -lt 502102 ; then echo "-lc_r"; else echo "-pthread"; fi)
INCLUDE+=-I/usr/local/include
CFLAGS+=$(shell if [ -d /usr/local/include/spandsp ]; then echo "-I/usr/local/include/spandsp"; fi)
MPG123TARG=freebsd
endif # FreeBSD

ifeq (${OSARCH},NetBSD)
CFLAGS+=-pthread
INCLUDE+=-I/usr/local/include -I/usr/pkg/include
MPG123TARG=netbsd
endif

ifeq (${OSARCH},OpenBSD)
CFLAGS+=-pthread
endif

#Uncomment this to use the older DSP routines
#CFLAGS+=-DOLD_DSP_ROUTINES

# uCasterisk - leave thse lines out to avoid mix up with i386 zaptel install
# CFLAGS+=$(shell if [ -f /usr/include/linux/zaptel.h ]; then echo "-DZAPTEL_OPTIMIZATIONS"; fi)
# CFLAGS+=$(shell if [ -f /usr/local/include/zaptel.h ]; then echo "-DZAPTEL_OPTIMIZATIONS"; fi)
# uCasterisk - do this instead
CFLAGS+= -DZAPTEL_OPTIMIZATIONS

ASTERISKVERSION=$(shell if [ -f .version ]; then cat .version; else if [ -d CVS ]; then if [ -f CVS/Tag ] ; then echo "CVS-`sed 's/^T//g' CVS/Tag`-`date +"%D-%T"`"; else echo "CVS-HEAD-`date +"%D-%T"`"; fi; fi; fi)
HTTPDIR=$(shell if [ -d /var/www ]; then echo "/var/www"; else echo "/home/httpd"; fi)
RPMVERSION=$(shell if [ -f .version ]; then sed 's/[-\/:]/_/g' .version; else echo "unknown" ; fi)
CFLAGS+=-DASTERISK_VERSION=\"$(ASTERISKVERSION)\"
CFLAGS+=-DINSTALL_PREFIX=\"$(INSTALL_PREFIX)\"
CFLAGS+=-DASTETCDIR=\"$(ASTETCDIR)\"
CFLAGS+=-DASTLIBDIR=\"$(ASTLIBDIR)\"
CFLAGS+=-DASTVARLIBDIR=\"$(ASTVARLIBDIR)\"
CFLAGS+=-DASTVARRUNDIR=\"$(ASTVARRUNDIR)\"
CFLAGS+=-DASTSPOOLDIR=\"$(ASTSPOOLDIR)\"
CFLAGS+=-DASTLOGDIR=\"$(ASTLOGDIR)\"
CFLAGS+=-DASTCONFPATH=\"$(ASTCONFPATH)\"
CFLAGS+=-DASTMODDIR=\"$(MODULES_DIR)\"
CFLAGS+=-DASTAGIDIR=\"$(AGI_DIR)\"

CFLAGS+= $(DEBUG_THREADS)
CFLAGS+= $(TRACE_FRAMES)
CFLAGS+= $(MALLOC_DEBUG)
CFLAGS+= $(BUSYDETECT)
CFLAGS+= $(OPTIONS)
CFLAGS+=# -fomit-frame-pointer 
#SUBDIRS=res channels pbx apps codecs formats agi cdr astman stdtime
SUBDIRS=res channels pbx apps codecs formats cdr editline db1-ast stdtime
ifeq (${OSARCH},Linux)
#LIBS+=-ldl -lpthread
endif
LIBS+=-lncurses -lm
ifeq (${OSARCH},Linux)
LIBS+=-lresolv  #-lnjamd
endif
ifeq (${OSARCH},Darwin)
LIBS+=-lresolv
endif
ifeq (${OSARCH},FreeBSD)
LIBS+=-lcrypto
endif
ifeq (${OSARCH},NetBSD)
LIBS+=-lpthread -lcrypto -lm -L/usr/local/lib -L/usr/pkg/lib -lncurses
endif
ifeq (${OSARCH},OpenBSD)
LIBS=-lcrypto -lpthread -lm -lncurses
endif

# uCasterisk LIBS+=-lssl
#LIBS+=-lpthread -lltdl

OBJS=io.o sched.o logger.o frame.o loader.o config.o channel.o \
	translate.o file.o say.o pbx.o cli.o md5.o term.o \
	ulaw.o alaw.o callerid.o fskmodem.o image.o app.o \
	cdr.o tdd.o acl.o rtp.o manager.o asterisk.o ast_expr.o \
	dsp.o chanvars.o indications.o autoservice.o db.o privacy.o \
	astmm.o enum.o srv.o dns.o aescrypt.o aestab.o aeskey.o \
	utils.o 


ifeq (${OSARCH},Darwin)
OBJS+=poll.o dlfcn.o
ASTLINK=-Wl,-dynamic
SOLINK=-dynamic -bundle -undefined suppress -force_flat_namespace
else
# uCasterisk ASTLINK=-Wl,-E 
# note adjust this line to change main thread
ASTLINK= $(EXTRA_MODS)
# uCasterisk SOLINK=-shared -Xlinker -x
endif

# uCasterisk CC=gcc (C compiler is passed in from top level makefile) 
LIBS+=-lltdl -lm -lncurses -lssl -lz -lcrypto -ltonezone 
LIBS+=-lpthread -lgsm -lspeex -lm

#uClinux libtool
LIBTOOL=$(STAGEDIR)/usr/bin/libtool
CFLAGS+=-I$(ROOTDIR)/user/blkfin-apps/zaptel

LIBS+= -L$(ROOTDIR)/user/blkfin-apps/zaptel 
LIBS+= -L$(ROOTDIR)/user/blkfin-apps/asterisk/editline 

FLTFLAGS=-s 32000

INSTALL=install


_all: all
	@echo " +--------- Asterisk Build Complete ---------+"  
	@echo " + Asterisk has successfully been built, but +"  
	@echo " + cannot be run before being installed by   +"  
	@echo " + running:                                  +"  
	@echo " +                                           +"
	@echo " +               $(MAKE) install                +"  
	@echo " +-------------------------------------------+"  

# uCasterisk all: depend asterisk subdirs
all: depend subdirs asterisk

ifneq ($(wildcard .depend),)
include .depend
endif

gentone:
	$(MAKE) -C "./channels" \
	CC="$(CC)" \
	gentone
					   

.PHONY: _version

_version: 
	if [ -d CVS ] && ! [ -f .version ]; then echo $(ASTERISKVERSION) > .version; fi 

.version: _version

.y.c:
	bison $< --name-prefix=ast_yy -o $@

ast_expr.o: ast_expr.c

cli.o: cli.c build.h

asterisk.o: asterisk.c build.h

manpage: asterisk.8.gz

asterisk.8.gz: asterisk.sgml
	rm -f asterisk.8
	docbook2man asterisk.sgml
	mv ./*.8 asterisk.8
	gzip asterisk.8

ifneq ($(strip $(ASTERISKVERSION)),)
build.h: .version
	./make_build_h
else
build.h:
	./make_build_h
endif

stdtime/libtime.a: FORCE
	@if [ -d stdtime ]; then \
		$(MAKE) -C stdtime libtime.a ; \
	else \
		echo "You need to do a cvs update -d not just cvs update"; \
		exit 1; \
	fi 

# uCasterisk - start support for static linking of modules using GNU
# 'libtool' to emulate dynamic linking.  The .so targets are modified
# to be static libtool .la libs.  Modify the lists below to change the
# modules included in the build.

CHANNELS_SO = chan_sip.so chan_iax2.so chan_agent.so chan_local.so \
              chan_skinny.so chan_modem.so chan_zap.so
RES_SO = res_adsi.so res_features.so res_crypto.so res_musiconhold.so \
         res_indications.so res_monitor.so res_agi.so
PBX_SO = pbx_config.so pbx_wilcalu.so pbx_spool.so
APPS_SO = app_dial.so app_playback.so app_voicemail.so app_directory.so app_mp3.so\
     app_system.so app_echo.so app_record.so app_image.so app_url.so app_disa.so \
     app_qcall.so app_adsiprog.so app_getcpeid.so app_milliwatt.so \
     app_zapateller.so app_setcallerid.so app_festival.so \
     app_queue.so app_senddtmf.so app_parkandannounce.so app_striplsd.so \
     app_setcidname.so app_lookupcidname.so app_substring.so app_macro.so \
     app_authenticate.so app_softhangup.so app_lookupblacklist.so \
     app_waitforring.so app_privacy.so app_db.so app_chanisavail.so \
     app_enumlookup.so app_transfer.so app_setcidnum.so app_cdr.so \
     app_hasnewvoicemail.so app_sayunixtime.so app_cut.so app_read.so \
     app_setcdruserfield.so app_random.so app_ices.so app_eval.so \
     app_nbscat.so app_sendtext.so app_exec.so app_sms.so \
     app_groupcount.so app_txtcidname.so app_controlplayback.so \
     app_talkdetect.so app_alarmreceiver.so app_userevent.so app_verbose.so \
     app_test.so app_forkcdr.so
FORMATS_SO = format_gsm.so format_wav.so \
	     format_wav_gsm.so format_vox.so format_pcm.so format_g729.so \
	     format_pcm_alaw.so format_h263.so format_g726.so format_ilbc.so \
	     format_sln.so
CDR_SO = cdr_csv.so cdr_manager.so
CODECS_SO = codec_adpcm.so codec_alaw.so codec_a_mu.so codec_gsm.so \
            codec_ulaw.so codec_speex.so

CHANNELS_LA = $(patsubst %.so, channels/%.la, $(CHANNELS_SO))
RES_LA = $(patsubst %.so, res/%.la, $(RES_SO))
PBX_LA = $(patsubst %.so, pbx/%.la, $(PBX_SO))
APPS_LA = $(patsubst %.so, apps/%.la, $(APPS_SO))
FORMATS_LA = $(patsubst %.so, formats/%.la, $(FORMATS_SO))
CDR_LA = $(patsubst %.so, cdr/%.la, $(CDR_SO))
CODECS_LA = $(patsubst %.so, codecs/%.la, $(CODECS_SO))
DB1_LA = $(patsubst %.so, db1-ast/%.a, libdb1.so)
EDITLINE_LA = $(patsubst %.so, editline/%.a, libedit.so)
STDTIME_LA = $(patsubst %.so, stdtime/%.a, libtime.so)

ALL_LA = $(CHANNELS_LA) $(RES_LA) $(PBX_LA) $(APPS_LA) $(FORMATS_LA) \
         $(CDR_LA)  $(CODECS_LA)
LINK_LA = $(patsubst %,"-dlopen" %, $(ALL_LA))

# uCasterisk - end static linking

asterisk: $(OBJS) gentone
	$(LIBTOOL) --tag=CC --mode=link $(CC) $(DEBUG) -o asterisk $(CFLAGS) $(LDFLAGS) \
	$(ASTLINK) $(OBJS) $(DB1_LA) $(EDITLINE_LA) $(STDTIME_LA) $(LIBS) $(LINK_LA)

muted: muted.o
	$(CC) -o muted muted.o

subdirs: 
	for x in $(SUBDIRS); do $(MAKE) -C $$x || exit 1 ; done

distclean clean:
	for x in $(SUBDIRS); do $(MAKE) -C $$x clean || exit 1 ; done
	rm -f *.o *.so asterisk .depend
	rm -f build.h 
	rm -f ast_expr.c
	@if [ -e editline/Makefile ]; then $(MAKE) -C editline distclean ; fi
	@if [ -d mpg123-0.59r ]; then $(MAKE) -C mpg123-0.59r clean; fi	
	$(MAKE) -C db1-ast clean
	$(MAKE) -C stdtime clean

datafiles: all
	mkdir -p $(DESTDIR)$(ASTVARLIBDIR)/sounds/digits
	for x in sounds/digits/*.gsm; do \
		if grep -q "^%`basename $$x`%" sounds.txt; then \
			install -m 644 $$x $(DESTDIR)$(ASTVARLIBDIR)/sounds/digits ; \
		else \
			echo "No description for $$x"; \
			exit 1; \
		fi; \
	done
	mkdir -p $(DESTDIR)$(ASTVARLIBDIR)/sounds/letters
	for x in sounds/letters/*.gsm; do \
		if grep -q "^%`basename $$x`%" sounds.txt; then \
			install -m 644 $$x $(DESTDIR)$(ASTVARLIBDIR)/sounds/letters ; \
		else \
			echo "No description for $$x"; \
			exit 1; \
		fi; \
	done
	mkdir -p $(DESTDIR)$(ASTVARLIBDIR)/sounds/phonetic
	for x in sounds/phonetic/*.gsm; do \
		if grep -q "^%`basename $$x`%" sounds.txt; then \
			install -m 644 $$x $(DESTDIR)$(ASTVARLIBDIR)/sounds/phonetic ; \
		else \
			echo "No description for $$x"; \
			exit 1; \
		fi; \
	done
	for x in sounds/vm-* sounds/transfer* sounds/pbx-* sounds/ss-* sounds/beep* sounds/dir-* sounds/conf-* sounds/agent-* sounds/invalid* sounds/tt-* sounds/auth-* sounds/privacy-* sounds/queue-*; do \
		if grep -q "^%`basename $$x`%" sounds.txt; then \
			install -m 644 $$x $(DESTDIR)$(ASTVARLIBDIR)/sounds ; \
		else \
			echo "No description for $$x"; \
			exit 1; \
		fi; \
	done
	mkdir -p $(DESTDIR)$(ASTVARLIBDIR)/mohmp3
	mkdir -p $(DESTDIR)$(ASTVARLIBDIR)/images
	for x in images/*.jpg; do \
		install -m 644 $$x $(DESTDIR)$(ASTVARLIBDIR)/images ; \
	done
	mkdir -p $(DESTDIR)$(AGI_DIR)

update: 
	@if [ -d CVS ]; then \
		echo "Updating from CVS..." ; \
		cvs -q -z3 update -Pd; \
		rm -f .version; \
	else \
		echo "Not CVS";  \
	fi

bininstall: all
	mkdir -p $(DESTDIR)$(MODULES_DIR)
	mkdir -p $(DESTDIR)$(ASTSBINDIR)
	mkdir -p $(DESTDIR)$(ASTETCDIR)
	mkdir -p $(DESTDIR)$(ASTBINDIR)
	mkdir -p $(DESTDIR)$(ASTSBINDIR)
	mkdir -p $(DESTDIR)$(ASTVARRUNDIR)
	mkdir -p $(DESTDIR)$(ASTSPOOLDIR)/voicemail
	mkdir -p $(DESTDIR)$(ASTSPOOLDIR)/tmp
	install -m 755 asterisk $(DESTDIR)$(ASTSBINDIR)/
	install -m 755 contrib/scripts/astgenkey $(DESTDIR)$(ASTSBINDIR)/
	install -m 755 contrib/scripts/autosupport $(DESTDIR)$(ASTSBINDIR)/
	if [ ! -f $(DESTDIR)$(ASTSBINDIR)/safe_asterisk ]; then \
		install -m 755 contrib/scripts/safe_asterisk $(DESTDIR)$(ASTSBINDIR)/ ;\
	fi
	for x in $(SUBDIRS); do $(MAKE) -C $$x install || exit 1 ; done
	install -d $(DESTDIR)$(ASTHEADERDIR)
	install -m 644 include/asterisk/*.h $(DESTDIR)$(ASTHEADERDIR)
	rm -f $(DESTDIR)$(ASTVARLIBDIR)/sounds/vm
	rm -f $(DESTDIR)$(ASTVARLIBDIR)/sounds/voicemail
	if [ ! -h $(DESTDIR)$(ASTSPOOLDIR)/vm ] && [ -d $(DESTDIR)$(ASTSPOOLDIR)/vm ]; then \
		mv $(DESTDIR)$(ASTSPOOLDIR)/vm $(DESTDIR)$(ASTSPOOLDIR)/voicemail/default; \
	else \
		mkdir -p $(DESTDIR)$(ASTSPOOLDIR)/voicemail/default; \
		rm -f $(DESTDIR)$(ASTSPOOLDIR)/vm; \
	fi
	ln -s $(ASTSPOOLDIR)/voicemail/default $(DESTDIR)$(ASTSPOOLDIR)/vm
	mkdir -p $(DESTDIR)$(ASTVARLIBDIR)/sounds
	mkdir -p $(DESTDIR)$(ASTLOGDIR)/cdr-csv
	mkdir -p $(DESTDIR)$(ASTVARLIBDIR)/keys
	mkdir -p $(DESTDIR)$(ASTVARLIBDIR)/firmware
	mkdir -p $(DESTDIR)$(ASTVARLIBDIR)/firmware/iax
	mkdir -p $(DESTDIR)$(ASTMANDIR)/man8
	install -m 644 keys/iaxtel.pub $(DESTDIR)$(ASTVARLIBDIR)/keys
	install -m 644 keys/freeworlddialup.pub $(DESTDIR)$(ASTVARLIBDIR)/keys
	install -m 644 asterisk.8.gz $(DESTDIR)$(ASTMANDIR)/man8
	if [ -d contrib/firmware/iax ]; then \
		install -m 644 contrib/firmware/iax/iaxy.bin $(DESTDIR)$(ASTVARLIBDIR)/firmware/iax/iaxy.bin; \
	else \
		echo "You need to do cvs update -d not just cvs update" ; \
	fi 
	( cd $(DESTDIR)$(ASTVARLIBDIR)/sounds  ; ln -s $(ASTSPOOLDIR)/vm . )
	( cd $(DESTDIR)$(ASTVARLIBDIR)/sounds  ; ln -s $(ASTSPOOLDIR)/voicemail . )
	if [ -f mpg123-0.59r/mpg123 ]; then $(MAKE) -C mpg123-0.59r install; fi
	@echo " +---- Asterisk Installation Complete -------+"  
	@echo " +                                           +"
	@echo " +    YOU MUST READ THE SECURITY DOCUMENT    +"
	@echo " +                                           +"
	@echo " + Asterisk has successfully been installed. +"  
	@echo " + If you would like to install the sample   +"  
	@echo " + configuration files (overwriting any      +"
	@echo " + existing config files), run:              +"  
	@echo " +                                           +"
	@echo " +               $(MAKE) samples                +"
	@echo " +                                           +"
	@echo " +-----------------  or ---------------------+"
	@echo " +                                           +"
	@echo " + You can go ahead and install the asterisk +"
	@echo " + program documentation now or later run:   +"
	@echo " +                                           +"
	@echo " +              $(MAKE) progdocs                +"
	@echo " +                                           +"
	@echo " + **Note** This requires that you have      +"
	@echo " + doxygen installed on your local system    +"
	@echo " +-------------------------------------------+"
	@echo " +                                           +"
	@echo " + ** NOTE FOR DOWNGRADING FROM CVS HEAD **  +"
	@echo " +                                           +"
	@echo " + If you are downgrading from CVS HEAD to   +"
	@echo " + a stable release, remember to delete      +"
	@echo " + everything from your asterisk modules     +"
	@echo " + directory (/usr/lib/asterisk/modules/)    +"
	@echo " + and the asterisk header directory         +"
	@echo " + (/usr/include/asterisk/)                  +"
	@echo " + before doing a '$(MAKE) install'.            +"
	@echo " +                                           +"
	@echo " +-------------------------------------------+"


install: all datafiles bininstall

upgrade: all bininstall

adsi: all
	mkdir -p $(DESTDIR)$(ASTETCDIR)
	for x in configs/*.adsi; do \
		if ! [ -f $(DESTDIR)$(ASTETCDIRX)/$$x ]; then \
			install -m 644 $$x $(DESTDIR)$(ASTETCDIR)/`basename $$x` ; \
		fi ; \
	done

samples: all datafiles adsi
	mkdir -p $(DESTDIR)$(ASTETCDIR)
	for x in configs/*.sample; do \
		if [ -f $(DESTDIR)$(ASTETCDIR)/`basename $$x .sample` ]; then \
			mv -f $(DESTDIR)$(ASTETCDIR)/`basename $$x .sample` $(DESTDIR)$(ASTETCDIR)/`basename $$x .sample`.old ; \
		fi ; \
		install -m 644 $$x $(DESTDIR)$(ASTETCDIR)/`basename $$x .sample` ;\
	done
	echo "[directories]" > $(DESTDIR)$(ASTETCDIR)/asterisk.conf
	echo "astetcdir => $(ASTETCDIR)" >> $(DESTDIR)$(ASTETCDIR)/asterisk.conf
	echo "astmoddir => $(MODULES_DIR)" >> $(DESTDIR)$(ASTETCDIR)/asterisk.conf
	echo "astvarlibdir => $(ASTVARLIBDIR)" >> $(DESTDIR)$(ASTETCDIR)/asterisk.conf
	echo "astagidir => $(AGI_DIR)" >> $(DESTDIR)$(ASTETCDIR)/asterisk.conf
	echo "astspooldir => $(ASTSPOOLDIR)" >> $(DESTDIR)$(ASTETCDIR)/asterisk.conf
	echo "astrundir => $(ASTVARRUNDIR)" >> $(DESTDIR)$(ASTETCDIR)/asterisk.conf
	echo "astlogdir => $(ASTLOGDIR)" >> $(DESTDIR)$(ASTETCDIR)/asterisk.conf
	for x in sounds/demo-*; do \
		if grep -q "^%`basename $$x`%" sounds.txt; then \
			install -m 644 $$x $(DESTDIR)$(ASTVARLIBDIR)/sounds ; \
		else \
			echo "No description for $$x"; \
			exit 1; \
		fi; \
	done
	for x in sounds/*.mp3; do \
		install -m 644 $$x $(DESTDIR)$(ASTVARLIBDIR)/mohmp3 ; \
	done
	rm -f $(DESTDIR)$(ASTVARLIBDIR)/mohmp3/sample-hold.mp3
	mkdir -p $(DESTDIR)$(ASTSPOOLDIR)/voicemail/default/1234/INBOX
	:> $(DESTDIR)$(ASTSPOOLDIR)/voicemail/default/1234/unavail.gsm
	for x in vm-theperson digits/1 digits/2 digits/3 digits/4 vm-isunavail; do \
		cat $(DESTDIR)$(ASTVARLIBDIR)/sounds/$$x.gsm >> $(DESTDIR)$(ASTSPOOLDIR)/voicemail/default/1234/unavail.gsm ; \
	done
	:> $(DESTDIR)$(ASTSPOOLDIR)/voicemail/default/1234/busy.gsm
	for x in vm-theperson digits/1 digits/2 digits/3 digits/4 vm-isonphone; do \
		cat $(DESTDIR)$(ASTVARLIBDIR)/sounds/$$x.gsm >> $(DESTDIR)$(ASTSPOOLDIR)/voicemail/default/1234/busy.gsm ; \
	done

webvmail:
	@[ -d $(DESTDIR)$(HTTPDIR) ] || ( echo "No HTTP directory" && exit 1 )
	@[ -d $(DESTDIR)$(HTTPDIR)/html ] || ( echo "No http directory" && exit 1 )
	@[ -d $(DESTDIR)$(HTTPDIR)/cgi-bin ] || ( echo "No cgi-bin directory" && exit 1 )
	install -m 4755 -o root -g root contrib/scripts/vmail.cgi $(DESTDIR)$(HTTPDIR)/cgi-bin/vmail.cgi
	mkdir -p $(DESTDIR)$(HTTPDIR)/html/_asterisk
	for x in images/*.gif; do \
		install -m 644 $$x $(DESTDIR)$(HTTPDIR)/html/_asterisk/; \
	done
	@echo " +--------- Asterisk Web Voicemail ----------+"  
	@echo " +                                           +"
	@echo " + Asterisk Web Voicemail is installed in    +"
	@echo " + your cgi-bin directory.  IT USES A SETUID +"
	@echo " + ROOT PERL SCRIPT, SO IF YOU DON'T LIKE    +"
	@echo " + THAT, UNINSTALL IT!                       +"
	@echo " +                                           +"
	@echo " +-------------------------------------------+"  

mailbox:
	./contrib/scripts/addmailbox 

rpm: __rpm

__rpm: _version
	rm -rf /tmp/asterisk ; \
	mkdir -p /tmp/asterisk/redhat/RPMS/i386 ; \
	$(MAKE) DESTDIR=/tmp/asterisk install ; \
	$(MAKE) DESTDIR=/tmp/asterisk samples ; \
	mkdir -p /tmp/asterisk/etc/rc.d/init.d ; \
	cp -f redhat/asterisk /tmp/asterisk/etc/rc.d/init.d/ ; \
	sed "s/^Version:.*/Version: $(RPMVERSION)/g" redhat/asterisk.spec > asterisk.spec ; \
	rpmbuild --rcfile /usr/lib/rpm/rpmrc:redhat/rpmrc -bb asterisk.spec

#uCasterisk for Blackfin
romfs: 
	$(MAKE)  \
	DESTDIR="$(ASTERISKDIR)" \
	install samples
							
	rm -rf $(ASTERISKDIR)/usr/sbin/astgenkey
	rm -rf $(ASTERISKDIR)/usr/bin
	rm -rf $(ASTERISKDIR)/usr/share
	rm -rf $(ASTERISKDIR)/usr/include
	(cd $(ASTERISKDIR)/usr/lib/asterisk; \
		cd modules; \
		rm -rf  *adsi* *festival* *modem* *meetme* *oss* *phone* *intercom* \
		*nbscat* *mysql* *postgres* *pgsql*\
		*zapateller* *jpeg*; \
		rm -f {codec,format}_ilbc.so ; \
		rm -f codec_lpc10.so ; \
		rm -f pbx_dundi.so ; \
	)
	(cd $(ASTERISKDIR)/etc/asterisk; \
		rm -f   *odbc* *mysql* *postgres* *pgsql* *adsi* *oss* *alsa* \
			*festival* *modem* *meetme* *phone* *tds* *vofr* *rpt* *vpb* \
			; \
		rm -f dundi.conf ; \
	)
																
	# add our custom .conf files for testing
	cp -f files/*.conf $(ASTERISKDIR)/etc/asterisk
	# add mulaw demo files, they sound better and work faster
	cp -f files/*.ulaw $(ASTERISKDIR)/var/lib/asterisk/sounds/
	# directories needed at run time
	mkdir -p $(ASTERISKDIR)/var/lib/asterisk
	mkdir -p $(ASTERISKDIR)/var/log/asterisk/cdr-csv
	# rm actual executable as we download this separately
	rm -f $(ASTERISKDIR)/usr/sbin/asterisk

	#romfs install
	mkdir -p $(ROMFSDIR)/usr/var
	cp -r $(ASTERISKDIR)/etc/* $(ROMFSDIR)/etc
	cp -r $(ASTERISKDIR)/usr/* $(ROMFSDIR)/usr
	cp -r $(ASTERISKDIR)/var/* $(ROMFSDIR)/usr/var
	chmod u+x asterisk 
	cp asterisk $(ROMFSDIR)/bin

progdocs:
	doxygen contrib/asterisk-ng-doxygen

mpg123:
	@wget -V >/dev/null || (echo "You need wget" ; false )
	[ -f mpg123-0.59r.tar.gz ] || wget http://www.mpg123.de/mpg123/mpg123-0.59r.tar.gz
	[ -d mpg123-0.59r ] || tar xfz mpg123-0.59r.tar.gz
	$(MAKE) -C mpg123-0.59r $(MPG123TARG)

config:
	if [ -d /etc/rc.d/init.d ]; then \
		install -m 755 contrib/init.d/rc.redhat.asterisk /etc/rc.d/init.d/asterisk; \
		/sbin/chkconfig --add asterisk; \
	elif [ -d /etc/init.d ]; then \
		install -m 755 init.asterisk /etc/init.d/asterisk; \
	fi 

dont-optimize:
	$(MAKE) OPTIMIZE= K6OPT= install

valgrind: dont-optimize

depend: .depend
	for x in $(SUBDIRS); do $(MAKE) -C $$x depend || exit 1 ; done

.depend:
	@if ! which mpg123 &>/dev/null ; then \
		echo "*** You don't have mpg123 installed. You're going to need ***";\
		echo "***       it if you want MusicOnHold                      ***";\
	elif ! mpg123 --longhelp 2>&1 | grep .59r &>/dev/null ; then \
			echo "*************************************************************";\
			echo "*** You have the WRONG version of mpg123... you need .59r ***";\
			echo "*** Use 'make mpg123' to get the right verison            ***";\
			echo "*************************************************************";\
	fi
	./mkdep ${CFLAGS} `ls *.c`

FORCE:

%_env:
	$(MAKE) -C $(shell echo $@ | sed "s/_env//g") env

env:
	env
