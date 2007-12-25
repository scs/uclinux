## Process this file with automake to produce Makefile.in

EXTRA_DIST = TODO COPYING INSTALL sdlroids.6.in README README.orig \
	README.xhyperoid README.petopt \
	sounds/bonusgot.wav sounds/bshot.wav sounds/bwound.wav \
	sounds/explode2.wav sounds/explode.wav sounds/newbad.wav \
	sounds/newbonus.wav sounds/phit.wav sounds/pshot.wav \
	sounds/swarmsplit.wav sounds/thrust.wav sounds/title.wav \
	bmp/blank.bmp bmp/bomb.bmp bmp/icon.bmp bmp/level.bmp		\
	bmp/life.bmp bmp/num0.bmp bmp/num1.bmp bmp/num2.bmp bmp/num3.bmp \
	bmp/num4.bmp bmp/num5.bmp bmp/num6.bmp bmp/num7.bmp bmp/num8.bmp \
	bmp/num9.bmp bmp/plus.bmp bmp/score.bmp bmp/shield.bmp \
	sdlroids.spec.in sdlroids-mdk.spec.in icons/sdlroids-16x16.xpm \
	icons/sdlroids-32x32.xpm icons/sdlroids-48x48.xpm 
bin_PROGRAMS = sdlroids
man_MANS = sdlroids.6
LDADD=@SRRES@
sdlroids_SOURCES = hyperoid.c roidsupp.c sdlsound.c sdl.c \
		 graphics.h hyperoid.h misc.h roidsupp.h sdlsound.h \
		 petopt.c petopt.h getargs.h getargs.c rand.c rand.h 

SOUNDSDIR="$(datadir)/sdlroids/sounds/"
GFXDIR="$(datadir)/sdlroids/bmp/"

install-data-local:
	@/bin/sh $(srcdir)/mkinstalldirs $(SOUNDSDIR) $(GFXDIR)
	$(INSTALL_DATA) $(srcdir)/sounds/*.wav $(SOUNDSDIR)
	$(INSTALL_DATA)  $(srcdir)/bmp/*.bmp $(GFXDIR)

# Data directories
INCLUDES=-Wall 	-Wcast-align -DDATADIR=\"$(datadir)/sdlroids/\"

# Rule to build tar-gzipped distribution package
$(PACKAGE)-$(VERSION).tar.gz: dist

# Rules to make a bzip2 archive
$(PACKAGE)-$(VERSION).tar.bz2: $(PACKAGE)-$(VERSION).tar.gz
	@gunzip < $(PACKAGE)-$(VERSION).tar.gz | bzip2 > $(PACKAGE)-$(VERSION).tar.bz2
dist-bz2: $(PACKAGE)-$(VERSION).tar.bz2

# Rule to build RPM distribution package
rpm: $(PACKAGE)-$(VERSION).tar.bz2
	if [ -d "$$HOME/rpm/" ]; then \
		cp $(PACKAGE)-$(VERSION).tar.bz2 $$HOME/rpm/SOURCES; \
	elif [ -d "/usr/src/RPM/" ]; then \
		cp $(PACKAGE)-$(VERSION).tar.bz2 /usr/src/RPM/SOURCES; \
	else \
		cp $(PACKAGE)-$(VERSION).tar.bz2 /usr/src/redhat/SOURCES; \
	fi
	rpm -ba sdlroids.spec

rpm-mdk: $(PACKAGE)-$(VERSION).tar.bz2
	if [ -d "$$HOME/rpm/" ]; then \
		cp $(PACKAGE)-$(VERSION).tar.bz2 $$HOME/rpm/SOURCES; \
		cp $(srcdir)/icons/*.xpm $$HOME/rpm/SOURCES; \
	elif [ -d "/usr/src/RPM/" ]; then \
		cp $(PACKAGE)-$(VERSION).tar.bz2 /usr/src/RPM/SOURCES; \
		cp $(srcdir)/icons/*.xpm /usr/src/RPM/SOURCES; \
	else \
		cp $(PACKAGE)-$(VERSION).tar.bz2 /usr/src/redhat/SOURCES; \
		cp $(srcdir)/icons/*.xpm /usr/src/redhat/SOURCES; \
	fi
	rpm --clean --sign -bs sdlroids-mdk.spec

SDLRoids.txt: sdlroids.6
	 groff -P-b -P-u -Tlatin1 -man sdlroids.6 |tr '\255' '-'> SDLRoids.txt

# Special rules to brand the files in BeOS
beos: sdlroids sdlroids.rsrc
	xres -o sdlroids sdlroids.rsrc
	@cp sdlroids.rsrc ..
	mimeset -f .
	@mv ../sdlroids.rsrc .
sdlroids.coff: sdlroids.rc 
	i386-mingw32msvc-windres sdlroids.rc sdlroids.coff
.rc.coff: 

TODOS=pike -e 'write(replace(Stdio.File("stdin")->read(), "\n", "\r\n"))'
windows: sdlroids.coff sdlroids SDLRoids.txt
	@echo -n "Building SDLRoids-$(VERSION).zip..."
	@rm -rf SDLRoids SDLRoids*.zip
	@/bin/sh $(srcdir)/mkinstalldirs SDLRoids/sounds SDLRoids/bmp/ >/dev/null 2>&1
	@$(INSTALL) -s sdlroids SDLRoids/SDLRoids.exe
	@@rm sdlroids
	@$(INSTALL) /usr/local/cross-tools/i386-mingw32msvc/lib/SDL.dll SDLRoids/
	@$(INSTALL_DATA) $(srcdir)/sounds/*.wav SDLRoids/sounds/
	@$(INSTALL_DATA)  $(srcdir)/bmp/*.bmp SDLRoids/bmp/
	@$(TODOS) < SDLRoids.txt > SDLRoids/SDLRoids.txt
	@$(TODOS) < $(srcdir)/README > SDLRoids/README.txt
	@$(TODOS) < $(srcdir)/README.orig > SDLRoids/README-orig.txt
	@$(TODOS) < $(srcdir)/TODO > SDLRoids/TODO.txt
	@$(TODOS) < $(srcdir)/README.petopt > SDLRoids/README-petopt.txt
	@$(TODOS) < $(srcdir)/COPYING > SDLRoids/COPYING.txt
	@$(TODOS) < $(srcdir)/ChangeLog > SDLRoids/ChangeLog.txt
	@zip -rq SDLRoids-$(VERSION).zip SDLRoids
	@rm -rf SDLRoids
	@echo  "done."
