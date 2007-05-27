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

# Create OPTIONS variable
OPTIONS=

OSARCH=Linux

ifeq (${OSARCH},Linux)
MPG123TARG=linux
endif

# Pentium Pro Optimize
#PROC=i686

# Pentium & VIA processors optimize
#PROC=i586

#PROC=k6
#PROC=ppc

PWD=$(shell pwd)

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
#OPTIONS += -DLOW_MEMORY

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

AGI_DIR=$(ASTVARLIBDIR)/agi-bin

INCLUDE=-Iinclude -I../include
CFLAGS += -pipe  -Wall -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations $(DEBUG) $(INCLUDE) -D_REENTRANT -D_GNU_SOURCE #-DMAKE_VALGRIND_HAPPY
CFLAGS += $(OPTIMIZE)
#CFLAGS += -D__NO_INLINES__
CFLAGS += -I$(PWD)/tinytcap

export CFLAGS

#Uncomment this to use the older DSP routines
#CFLAGS+=-DOLD_DSP_ROUTINES

HTTPDIR=/home/httpd
RPMVERSION=unknown
CFLAGS+=-DASTERISK_VERSION=\"1.0.7\"
#CFLAGS+=-DINSTALL_PREFIX=\"$(INSTALL_PREFIX)\"
CFLAGS+=-DASTETCDIR=\"/etc/config/asterisk\"
CFLAGS+=-DASTLIBDIR=\"/lib/asterisk\"
CFLAGS+=-DASTVARLIBDIR=\"/var/lib/asterisk\"
CFLAGS+=-DASTVARRUNDIR=\"/var/run\"
CFLAGS+=-DASTSPOOLDIR=\"/var/spool/asterisk\"
CFLAGS+=-DASTLOGDIR=\"/var/log/asterisk\"
CFLAGS+=-DASTCONFPATH=\"/etc/config/asterisk/asterisk.conf\"
CFLAGS+=-DASTMODDIR=\"/lib/asterisk/modules\"
CFLAGS+=-DASTAGIDIR=\"$(AGI_DIR)\"

CFLAGS+= $(DEBUG_THREADS)
CFLAGS+= $(TRACE_FRAMES)
CFLAGS+= $(MALLOC_DEBUG)
CFLAGS+= $(BUSYDETECT)
CFLAGS+= $(OPTIONS)
CFLAGS+=# -fomit-frame-pointer 
SUBDIRS=res channels pbx apps codecs formats agi cdr astman stdtime

LDLIBS += $(LIBSSL) $(LIBCRYPTO) -lpthread -lm -ldl #-lresolv

OBJS=io.o sched.o logger.o frame.o loader.o config.o channel.o \
	translate.o file.o say.o pbx.o cli.o md5.o term.o \
	ulaw.o alaw.o callerid.o fskmodem.o image.o app.o \
	cdr.o tdd.o acl.o rtp.o manager.o asterisk.o ast_expr.o \
	dsp.o chanvars.o indications.o autoservice.o db.o privacy.o \
	astmm.o enum.o srv.o dns.o aescrypt.o aestab.o aeskey.o \
	utils.o 

ASTLINK=-Wl,-E 
SOLINK=-shared $(SH_LDFLAGS)

export CC CFLAGS LDFLAGS LIBS LDLIBS CROSS_COMPILE

all: asterisk subdirs 

editline/config.h:
	cd editline && \
		CC="$(CC) $(CFLAGS)" LDFLAGS="$(LDFLAGS)" LIBS="$(LDLIBS)" \
			sh configure $(CONFIGURE_OPTS)


db1-ast/libdb1.a: FORCE
	@if [ -d db1-ast ]; then \
		$(MAKE) -C db1-ast libdb1.a ; \
	else \
		echo "You need to do a cvs update -d not just cvs update"; \
		exit 1; \
	fi

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

editline/libedit.a: FORCE
	cd editline && unset CFLAGS LIBS && test -f config.h || \
		CC="$(CC) $(CFLAGS)" LDFLAGS="$(LDFLAGS) -L../tinytcap" LIBS="$(LDLIBS)" \
			sh configure $(CONFIGURE_OPTS)
	$(MAKE) -C editline libedit.a

tinytcap/libtermcap.a: FORCE
	$(MAKE) -C tinytcap libtermcap.a

asterisk: db1-ast/libdb1.a tinytcap/libtermcap.a editline/libedit.a stdtime/libtime.a $(OBJS)
	$(CC) $(DEBUG) $(LDFLAGS) -o asterisk $(ASTLINK) $(OBJS) $(LIBEDIT) db1-ast/libdb1.a editline/libedit.a tinytcap/libtermcap.a stdtime/libtime.a $(LDLIBS)

muted: muted.o
	$(CC) -o muted muted.o

subdirs: 
	for x in $(SUBDIRS); do $(MAKE) -C $$x || exit 1 ; done

clean:
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
	@echo " + before doing a '$(MAKE) install'.            +"
	@echo " +                                           +"
	@echo " +-------------------------------------------+"


install: all datafiles bininstall

upgrade: all bininstall

# Choose some modules to install
MODULES=apps/app_db.so apps/app_echo.so apps/app_read.so \
	apps/app_senddtmf.so apps/app_verbose.so cdr/cdr_csv.so cdr/cdr_manager.so \
	channels/chan_local.so channels/chan_phone.so channels/chan_sip.so \
	codecs/codec_a_mu.so codecs/codec_adpcm.so codecs/codec_alaw.so \
	codecs/codec_g726.so codecs/codec_gsm.so codecs/codec_ulaw.so \
	pbx/pbx_config.so pbx/pbx_wilcalu.so res/res_features.so \
	res/res_musiconhold.so

romfs:
	$(ROMFSINST) /bin/asterisk
	mkdir -p $(ROMFSDIR)/etc/config/asterisk $(ROMFSDIR)/var/lib/asterisk $(ROMFSDIR)/lib/asterisk/modules $(ROMFSDIR)/var/spool/asterisk
	for i in $(MODULES); do $(ROMFSINST) $$i /lib/asterisk/modules/$$i; done
	cp configs.romfs/*.conf configs.romfs/*.adsi $(ROMFSDIR)/etc/config/asterisk/

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
