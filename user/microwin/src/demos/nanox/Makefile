##############################################################################
# Microwindows template Makefile
# Copyright (c) 2000 Martin Jolicoeur, Greg Haerr
##############################################################################

ifndef TOP
TOP = ../..
CONFIG = $(TOP)/config
endif

include $(CONFIG)

######################## Additional Flags section ############################

# Directories list for header files
INCLUDEDIRS +=
# Defines for preprocessor
DEFINES +=

# Compilation flags for C files OTHER than include directories
CFLAGS +=
# Preprocessor flags OTHER than defines
CPPFLAGS +=
# Linking flags
LDFLAGS +=

############################# targets section ################################

ifeq ($(NANOX), Y)
ifeq ($(NANOXDEMO), Y)

# If you want to create a library with the objects files, define the name here
LIBNAME =

# List of objects to compile
OBJS =	demo.o \
	move.o \
	landmine.o \
	world.o \
	nxclock.o \
	nxterm.o \
	nxview.o \
	nxlsclients.o \
	nxev.o \
	npanel.o \
	nterm.o \
	demo2.o \
	demo5.o \
	demo6.o \
	t1demo.o \
	ftdemo.o \
	logfont.o \
	slider.o \
	ntetris.o \
	launcher.o \
	nsaver.o \
	getselection.o \
	setselection.o

all: default $(TOP)/bin/demo $(TOP)/bin/move $(TOP)/bin/landmine \
	$(TOP)/bin/world $(TOP)/bin/nxclock $(TOP)/bin/nxterm \
	$(TOP)/bin/nxview $(TOP)/bin/nxlsclients $(TOP)/bin/nxev \
	$(TOP)/bin/npanel $(TOP)/bin/nterm \
	$(TOP)/bin/demo2 $(TOP)/bin/demo5 $(TOP)/bin/demo6 \
	$(TOP)/bin/t1demo $(TOP)/bin/ftdemo $(TOP)/bin/logfont \
	$(TOP)/bin/slider $(TOP)/bin/ntetris $(TOP)/bin/launcher \
	$(TOP)/bin/nsaver $(TOP)/bin/getselection $(TOP)/bin/setselection
	$(CP) world.map nanogui.ppm ntetris.ppm launcher.cnf tux.gif $(TOP)/bin
	

endif
endif

######################### Makefile.rules section #############################

include $(TOP)/Makefile.rules

ifeq ($(SHAREDLIBS), Y)
LD_NANOXCLIENTLIBS = $(CCNANOXCLIENTLIBS) $(LDLIBS)
else
LD_NANOXCLIENTLIBS = $(NANOXCLIENTLIBS) $(LDLIBS)
endif

######################## Tools targets section ###############################

$(TOP)/bin/demo: demo.o $(NANOXCLIENTLIBS) $(TOP)/config
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@ $(LD_NANOXCLIENTLIBS)

$(TOP)/bin/move: move.o $(NANOXCLIENTLIBS) $(TOP)/config
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@ $(LD_NANOXCLIENTLIBS)

$(TOP)/bin/landmine: landmine.o $(NANOXCLIENTLIBS) $(TOP)/config
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@ $(LD_NANOXCLIENTLIBS)

$(TOP)/bin/world: world.o $(NANOXCLIENTLIBS) $(TOP)/config
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@ $(LD_NANOXCLIENTLIBS)

$(TOP)/bin/nxclock: nxclock.o $(NANOXCLIENTLIBS) $(TOP)/config
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@ $(LD_NANOXCLIENTLIBS)

$(TOP)/bin/nxterm: nxterm.o $(NANOXCLIENTLIBS) $(TOP)/config
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@ $(LD_NANOXCLIENTLIBS)

$(TOP)/bin/nxview: nxview.o $(NANOXCLIENTLIBS) $(TOP)/config
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@ $(LD_NANOXCLIENTLIBS)

$(TOP)/bin/nxlsclients: nxlsclients.o $(NANOXCLIENTLIBS) $(TOP)/config
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@ $(LD_NANOXCLIENTLIBS)

$(TOP)/bin/nxev: nxev.o $(NANOXCLIENTLIBS) $(TOP)/config
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@ $(LD_NANOXCLIENTLIBS)

$(TOP)/bin/npanel: npanel.o $(NANOXCLIENTLIBS) $(TOP)/config
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@ $(LD_NANOXCLIENTLIBS)

$(TOP)/bin/nterm: nterm.o $(NANOXCLIENTLIBS) $(TOP)/config
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@ $(LD_NANOXCLIENTLIBS)

$(TOP)/bin/demo2: demo2.o $(NANOXCLIENTLIBS) $(TOP)/config
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@ $(LD_NANOXCLIENTLIBS)

$(TOP)/bin/demo5: demo5.o $(NANOXCLIENTLIBS) $(TOP)/config
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@ $(LD_NANOXCLIENTLIBS)

$(TOP)/bin/demo6: demo6.o $(NANOXCLIENTLIBS) $(TOP)/config
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@ $(LD_NANOXCLIENTLIBS)

$(TOP)/bin/t1demo: t1demo.o $(NANOXCLIENTLIBS) $(TOP)/config
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@ $(LD_NANOXCLIENTLIBS)

$(TOP)/bin/ftdemo: ftdemo.o $(NANOXCLIENTLIBS) $(TOP)/config
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@ $(LD_NANOXCLIENTLIBS)

$(TOP)/bin/logfont: logfont.o $(NANOXCLIENTLIBS) $(TOP)/config
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@ $(LD_NANOXCLIENTLIBS)

$(TOP)/bin/slider: slider.o $(NANOXCLIENTLIBS) $(TOP)/config
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@ $(LD_NANOXCLIENTLIBS)

$(TOP)/bin/ntetris: ntetris.o $(NANOXCLIENTLIBS) $(TOP)/config
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@ $(LD_NANOXCLIENTLIBS)

$(TOP)/bin/launcher: launcher.o $($NANOXCLIENTLIBS) $(TOP)/config
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@ $(LD_NANOXCLIENTLIBS)

$(TOP)/bin/nsaver: nsaver.o $($NANOXCLIENTLIBS) $(TOP)/config
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@ -lm $(LD_NANOXCLIENTLIBS)

$(TOP)/bin/getselection: getselection.o $($NANOXCLIENTLIBS) $(TOP)/config
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@ $(LD_NANOXCLIENTLIBS)

$(TOP)/bin/setselection: setselection.o $($NANOXCLIENTLIBS) $(TOP)/config
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@ $(LD_NANOXCLIENTLIBS)
