##############################################################################
# Microwindows template Makefile
# Copyright (c) 2000 Martin Jolicoeur, Greg Haerr
##############################################################################

include $(CONFIG)

######################## Additional Flags section ############################

# Directories list for header files
INCLUDEDIRS +=
# Defines for preprocessor
DEFINES += -DMWIN

# Compilation flags for C files OTHER than include directories
CFLAGS +=
# Preprocessor flags OTHER than defines
CPPFLAGS +=
# Linking flags
LDFLAGS +=

############################# targets section ################################

ifeq ($(NWIDGET), Y)

# If you want to create a library with the objects files, define the name here
LIBNAME = libnwidget.a
LIBNAMESO = libnwidget.so

# List of objects to compile
OBJS =	nclass.o \
	nwidget.o \
	nbutton.o \
	ntoggle.o \
	nradio.o \
	nslider.o \
	ntextfield.o \
	nrender.o \
	nlistview.o

endif

######################### Makefile.rules section #############################

include $(TOP)/Makefile.rules

######################## Tools targets section ###############################
