# src/skeleton/Makefile
#
# Copyright (C) 1999 AbsoluteValue Systems, Inc.  All Rights Reserved.
# --------------------------------------------------------------------
#
# linux-wlan
#
#   The contents of this file are subject to the Mozilla Public
#   License Version 1.1 (the "License"); you may not use this file
#   except in compliance with the License. You may obtain a copy of
#   the License at http://www.mozilla.org/MPL/
#
#   Software distributed under the License is distributed on an "AS
#   IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
#   implied. See the License for the specific language governing
#   rights and limitations under the License.
#
#   Alternatively, the contents of this file may be used under the
#   terms of the GNU Public License version 2 (the "GPL"), in which
#   case the provisions of the GPL are applicable instead of the
#   above.  If you wish to allow the use of your version of this file
#   only under the terms of the GPL and not to allow others to use
#   your version of this file under the MPL, indicate your decision
#   by deleting the provisions above and replace them with the notice
#   and other provisions required by the GPL.  If you do not delete
#   the provisions above, a recipient may use your version of this
#   file under either the MPL or the GPL.
#
# --------------------------------------------------------------------
#
# Inquiries regarding the linux-wlan Open Source project can be
# made directly to:
#
# AbsoluteValue Systems Inc.
# info@linux-wlan.com
# http://www.linux-wlan.com
#
# --------------------------------------------------------------------
#
# Portions of the development of this software were funded by 
# Intersil Corporation as part of PRISM(R) chipset product development.
#
# --------------------------------------------------------------------

include ../../config.mk

# Build options (just comment out the ones you don't want)
ifeq ($(WLAN_DEBUG), y)
WLAN_INCLUDE_DEBUG="-DWLAN_INCLUDE_DEBUG"
endif

# XXXXXX this is COMPLETELY out of date.

# Source and obj and target definitions
SKEL_MODULE=skelwlan_cs.o
SKEL_SRC=	skeleton.c
SKEL_OBJ=	skeleton.o 

# List of modules to build
MODULES=
MODULES+=$(SKEL_MODULE)

# Implicit rules to handle the separate obj dirs
OBJ_DIR=obj

$(OBJ_DIR)/%.o : ../shared/%.c
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $< -o $@

$(OBJ_DIR)/%.o : %.c
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $< -o $@


# Compiler Options
ifndef CFLAGS
CFLAGS = -O2 -Wall -Wstrict-prototypes -fomit-frame-pointer -pipe
ifeq ($(WLAN_TARGET_ARCH), alpha)
CFLAGS := $(CFLAGS) -mno-fp-regs -ffixed-8
endif
endif

# Preprocessor Options
ifeq ($(WLAN_KERN_PCMCIA), y)
CPPFLAGS=-D__LINUX_WLAN__ -D__KERNEL__ -DMODULE=1 \
	-I../include \
	-I$(PCMCIA_SRC)/include/static \
	-I$(LINUX_SRC)/include \
	-I$(PCMCIA_SRC)/include \
	$(WLAN_INCLUDE_DEBUG) $(WLAN_INCLUDE_SNIF)
else
CPPFLAGS=-D__LINUX_WLAN__ -D__KERNEL__ -DMODULE=1 \
	-I../include \
	-I$(PCMCIA_SRC)/include \
	-I$(LINUX_SRC)/include \
	$(WLAN_INCLUDE_DEBUG) $(WLAN_INCLUDE_SNIF)
endif
# Dependency Source List
DEP_SRC=$(SKEL_SRC)

# Rules
all : .depend dirs $(MODULES)

dep .depend: $(DEP_SRC) ../../config.mk
	$(CPP) -M $(CPPFLAGS) $(DEP_SRC) > .depend

dirs : 
	mkdir -p $(OBJ_DIR)

$(SKEL_MODULE) : $(SKEL_OBJ)
	$(LD) -r -o $@ $(SKEL_OBJ)
	chmod -x $@

# It's a demo. Don't actually install it.
install : $(MODULES)
#	mkdir -p $(TARGET_MODDIR)/pcmcia
#	cp $(SKEL_MODULE) $(TARGET_MODDIR)/pcmcia

clean: 
	rm -f .depend .depend*
	rm -f core core.* *.o .*.o *.s *.a tmp_make *~ tags
	rm -fr $(OBJ_DIR) 
	rm -fr $(MODULES)

#
# Include a dependency file (if one exists)
#
ifeq (.depend,$(wildcard .depend))
include .depend
endif
