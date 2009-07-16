
# Nano-X11 library makefile - Greg Haerr <greg@censoft.com>
#
# note: if build fails, rebuild keysymstr.h by "make distclean",
#       then "make"
#
# 11 Aug 2003
#

# set to Microwindows and X11 include and lib directories

MWIN=$$PWD/../../src
X11=./X11

MWIN_INCLUDE=$(MWIN)/include
MWIN_LIB=$(MWIN)/lib
X11_LIB=$(X11)/lib

# set to font PCF file search directories, rgb.txt file location
X11_FONT_DIR1=$(X11)/fonts/100dpi
X11_FONT_DIR2=$(X11)/fonts/misc
X11_RGBTXT=$(X11)/rgb.txt

# set to Y to make shared X11 libs
SHAREDLIB=Y
LIBNAME = X11
xSOLIBREV = 6.1
SOLIBREV = 6.2

# set to Y to include (unmodifed X11) Xrm routines
INCLUDE_XRM=N

# shared library dependencies and shared library install dir
SOEXTRALIBS = -L$(MWIN_LIB) -lnano-X
INSTALL_DIR = $(X11_LIB)

# compiler flags
#CC = we got $CC from upper level config
LN = ln -s
MV = mv
RM = rm -f
DEBUG = -g
CFLAGS += -Wall $(DEBUG) -I$(MWIN_INCLUDE) 
CFLAGS += -DX11_FONT_DIR1=\"$(X11_FONT_DIR1)\"
CFLAGS += -DX11_FONT_DIR2=\"$(X11_FONT_DIR2)\"
CFLAGS += -DX11_RGBTXT=\"$(X11_RGBTXT)\"
xCFLAGS += -O2 -fno-strength-reduce

OBJS = DestWind.o MapWindow.o NextEvent.o OpenDis.o ClDisplay.o\
	Window.o CrGC.o FreeGC.o StName.o Sync.o Flush.o CrWindow.o\
	Text.o DrLine.o DrLines.o DrPoint.o DrRect.o DrArc.o\
	MapRaised.o RaiseWin.o LowerWin.o FillRct.o CrPixmap.o Clear.o\
	MoveWin.o ClearArea.o UnmapWin.o RepWindow.o\
	ChWindow.o Backgnd.o BdrWidth.o Border.o PmapBgnd.o LoadFont.o\
	UnloadFont.o\
	DefCursor.o UndefCurs.o CrCursor.o FontCursor.o\
	CrBFData.o CrPFBData.o Region.o SelInput.o Atom.o\
	QueryTree.o Image.o WindowProperty.o Misc.o SetWMProps.o Bell.o\
	Copy.o SetClip.o Visual.o SetAttributes.o FillPolygon.o\
	StrKeysym.o ChProperty.o QueryPointer.o ErrorHandler.o\
	ListPix.o GetGeom.o SetIFocus.o Shape.o\
	font.o Free.o stub.o\
	ClassHint.o Text16.o ListFonts.o QueryFont.o TextExt.o SetFontPath.o\
	AllocColor.o ParseColor.o QueryColor.o Colormap.o Colorname.o \
	Selection.o

ifeq ($(INCLUDE_XRM), Y)
OBJS += Quarks.o Xrm.o
xOBJS += xrm/Xrm.o xrm/ParseCmd.o xrm/Misc.o xrm/Quarks.o xrm/lcWrap.o \
    xrm/lcInit.o xrm/lcGenConv.o xrm/SetLocale.o xrm/lcConv.o xrm/lcUTF8.o \
    xrm/lcDefConv.o xrm/lcPubWrap.o xrm/lcDynamic.o xrm/lcCharSet.o \
    xrm/lcDB.o xrm/lcGeneric.o xrm/lcUtil.o xrm/lcCT.o xrm/lcFile.o \
    xrm/lcPublic.o xrm/lcRM.o xrm/imInt.o
CFLAGS += -I.
endif

LIBS = libnx11.a

ifeq ($(SHAREDLIB), Y)
CFLAGS += -fPIC
LIBS += lib$(LIBNAME).so.$(SOLIBREV)
endif

all: $(LIBS)

# static nx11 library
libnx11.a: keysymstr.h $(OBJS)
	ar r libnx11.a $(OBJS)

# shared X11 library
lib$(LIBNAME).so.$(SOLIBREV): $(OBJS)
	$(RM) $@~
	@SONAME=`echo $@ | sed 's/\.[^\.]*$$//'`; set -x; \
	$(CC) -o ./$@~ -shared -Wl,-soname,$$SONAME $(OBJS) $(SOEXTRALIBS) -lc; \
	$(RM) $$SONAME; $(LN) $@ $$SONAME;
	$(RM) $@
	$(MV) $@~ $@
	$(RM) lib$(LIBNAME).so; $(LN) $@ lib$(LIBNAME).so

install: $(LIBS)
	$(RM) $(INSTALL_DIR)/lib$(LIBNAME).so; \
	$(MV) lib$(LIBNAME).so $(INSTALL_DIR)
	@MAJREV=`expr $(SOLIBREV) : '\(.*\)\.'`; set -x; \
	$(RM) $(INSTALL_DIR)/lib$(LIBNAME).so.$$MAJREV; \
	$(MV) lib$(LIBNAME).so.$$MAJREV $(INSTALL_DIR)
	$(RM) $(INSTALL_DIR)/lib$(LIBNAME).so.$(SOLIBREV); \
	$(MV) lib$(LIBNAME).so.$(SOLIBREV) $(INSTALL_DIR)
##	$(MV) libnx11.a $(INSTALL_DIR)

clean: cleanlibs
	$(RM) *.o *~

cleanlibs:
	$(RM) libnx11.a
	$(RM) lib$(LIBNAME).so
	@MAJREV=`expr $(SOLIBREV) : '\(.*\)\.'`; \
	set -x; $(RM) lib$(LIBNAME).so.$$MAJREV
	$(RM) lib$(LIBNAME).so.$(SOLIBREV)

distclean: clean
	rm -f keysymstr.h

keysymstr.h: 
	perl ./keymap.pl $(X11_INCLUDE)/X11 > ./keysymstr.h

.SUFFIXES:
.SUFFIXES: .c .o

.c.o:
	$(CC) $(CFLAGS) -o $@ -c $<
