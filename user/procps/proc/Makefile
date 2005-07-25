# Auto-adaptive C library Makefile adapted for libproc, Chuck Blake.
# Assumptions are basically that all the .c files in the CWD are modules
# for the library and that all .h files are the interface to the library.

# PROJECT SPECIFIC MACROS
NAME       =  proc

# INSTALLATION OPTIONS
TOPDIR     = /usr
HDRDIR     = $(TOPDIR)/include/$(NAME)#	where to put .h files
LIBDIR     = $(TOPDIR)/lib#		where to put library files
SHLIBDIR   = /lib#			where to put shared library files
HDROWN     = $(OWNERGROUP) #		owner of header files
LIBOWN     = $(OWNERGROUP) #		owner of library files
INSTALL    = install

# ----------------------------------------------------------------#
# The rest is the auto-magic section -- highly GNU make dependent #
# You should never need to edit this.                             #
# ----------------------------------------------------------------#

VC_SUF     =  ,v
VC_PFX     =  RCS/
RCSFILES   =  $(patsubst $(VC_PFX)%$(VC_SUF),%,$(wildcard $(VC_PFX)*$(VC_SUF)))

# We take the union of RCS files and other files in CWD so that new files do
# not need to alter this makefile.  'sort' removes duplicates.  This allows the
# convenience of compiling and testing new files before the initial check-in.

SRC        =  $(sort $(wildcard *.c) $(filter %.c,$(RCSFILES)))
HDR        =  $(sort $(wildcard *.h) $(filter %.h,$(RCSFILES)))

OBJ        =  $(SRC:.c=.o)
SONAME     =  lib$(NAME).so.$(LIBVERSION)

ifeq ($(SHARED),1)
CFLAGS += -fpic
all: lib$(NAME).a $(SONAME)
else
all: lib$(NAME).a
endif

lib$(NAME).a: .depend $(OBJ)
	$(AR) rcs $@ $^

$(SONAME): $(OBJ)
	$(CC) $(SH_LDFLAGS) -s -shared -Wl,-soname,$(SONAME) -o $@ $^ $(SH_LDLIBS)
	ln -sf $(SONAME) lib$(NAME).so

# AUTOMATIC DEPENDENCY GENERATION -- GCC AND GNUMAKE DEPENDENT

.depend:
	$(strip $(CC) $(CFLAGS) -MM -MG $(SRC) > .depend)

ifeq (.depend,$(wildcard .depend))
include .depend
endif

# INSTALLATION

install: all
	if ! [ -d $(HDRDIR) ] ; then mkdir $(HDRDIR) ; fi
	$(INSTALL) $(HDROWN) $(HDR) $(TOPDIR)/include/$(NAME)
	$(INSTALL) $(LIBOWN) lib$(NAME).a $(LIBDIR)
ifeq ($(SHARED),1)
	$(INSTALL) $(LIBOWN) $(SONAME) $(SHLIBDIR)
	ln -sf $(SHLIBDIR)/$(SONAME) $(SHLIBDIR)/lib$(NAME).so
	ldconfig
endif

# VARIOUS SHORT CUT TARGETS
.PHONY:	all install dep clean distclean checkout checkclean

dep:	.depend

clean:
	$(RM) lib$(NAME).* *.o signames.h

distclean:	clean
	$(RM) .depend signames.h

checkout:
	$(CO) $(RCSFILES)

checkclean:
	$(RM) $(RCSFILES)

# CUSTOM c -> o rule so that command-line has minimal whitespace

%.o : %.c
	$(strip $(CC) $(CFLAGS) -c $<)

# PROJECT SPECIFIC DEPENDENCIES/BUILD RULES


version.o:	version.c version.h
ifdef MINORVERSION
	$(strip $(CC) $(CFLAGS) -DVERSION=\"$(VERSION)\" -DSUBVERSION=\"$(SUBVERSION)\" -DMINORVERSION=\"$(MINORVERSION)\" -c version.c)
else
	$(strip $(CC) $(CFLAGS) -DVERSION=\"$(VERSION)\" -DSUBVERSION=\"$(SUBVERSION)\" -c version.c)
endif

signals.o : signames.h

signames.h ../proc/signames.h : /usr/include/signal.h
	$(CPP) -dM /usr/include/signal.h |	\
	grep -v SIGSTKSZ | \
	tr -s '\t ' '  ' | sort -n +2 | sed		\
	's:#define SIG\([A-Z]\+[0-9]*\) \([0-9]\+\) *\(\|/\*.*\)$$:{\
\2,"\1" },:p;d'  > signames.h

