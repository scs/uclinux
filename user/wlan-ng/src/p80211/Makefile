# src/p80211/Makefile 
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

include $(WLAN_SRC)../../config.mk

ifeq ($(WLAN_DEBUG), y)
WLAN_INCLUDE_DEBUG=-DWLAN_INCLUDE_DEBUG
endif

ifeq ($(CONFIG_NETLINK), y)
WLAN_CS_CONFIG_SNIFF=-DCONFIG_NETLINK=1
endif

ifeq ($(CONFIG_PACKET), y)
WLAN_CS_CONFIG_SNIFF+=-DCONFIG_PACKET=1
endif

ifeq ($(KERN_25), y)

ifneq ($(KERNELRELEASE),)

EXTRA_CFLAGS += -I$(src)/../include $(WLAN_INCLUDE_DEBUG) $(WLAN_CS_CONFIG_SNIFF)
obj-m += p80211.o 
p80211-objs := p80211mod.o p80211conv.o p80211req.o p80211frm.o p80211wep.o p80211wext.o p80211netdev.o

else

PWD := $(shell pwd)
default:
	$(MAKE) -C $(LINUX_SRC) SUBDIRS=$(PWD) WLAN_SRC=$(PWD)/ modules

endif  # KERNELRELEASE

clean:
	rm -f *.o *.ko .*.cmd *.mod.c

install:
	mkdir -p $(TARGET_MODDIR)/kernel/drivers/net
	cp *.ko	$(TARGET_MODDIR)/kernel/drivers/net

else   # not KERN_25

# Source and obj and target definitions
P80211_MODULE=p80211.o
P80211_SRC=	p80211conv.c \
		p80211req.c \
		p80211frm.c \
		p80211wext.c \
		p80211wep.c \
		p80211netdev.c

P80211_OBJ=	p80211conv.o \
		p80211req.o \
		p80211frm.o \
		p80211wext.o \
		p80211wep.o \
		p80211netdev.o

# List of modules to build
MODULES=
MODULES+=$(P80211_MODULE)

# Compiler Options
CFLAGS = $(KERNEL_CFLAGS) $(KERNEL_MODFLAGS)
# Preprocessor Options
CPPFLAGS=-I../include $(WLAN_INCLUDE_DEBUG) $(WLAN_CS_CONFIG_SNIFF)

%.o : ../shared/%.c
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $< -o $@

%.o : %.c
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $< -o $@

# Dependency Source List
DEP_SRC=$(P80211_SRC) p80211mod.c

# Rules
all : .depend $(MODULES)
	echo $(MODULES)

dep .depend: $(DEP_SRC) ../../config.mk $(wildcard $(LINUX_SRC)/.config)

ifdef MODULES
	$(CPP) -M $(CFLAGS) $(CPPFLAGS) $(DEP_SRC) > .depend
endif

p80211mod.o :
	$(CC) -c $(CFLAGS) $(CPPFLAGS) -DEXPORT_SYMTAB p80211mod.c -o p80211mod.o 

$(P80211_MODULE) : p80211mod.o $(P80211_OBJ) 
	$(LD) -r -o $@ $(P80211_OBJ) p80211mod.o
	chmod -x $@

install : $(MODULES)
	mkdir -p $(TARGET_MODDIR)/net
	cp $(P80211_MODULE) $(TARGET_MODDIR)/net

romfs:
	mkdir -p $(ROMFSDIR)/lib/modules/$(KERNELRELEASE)/net
	$(ROMFSINST) /lib/modules/$(KERNELRELEASE)/net/$(P80211_MODULE)

clean: 
	rm -f core core.* *.o .*.o *.s *.a .depend tmp_make *~ tags
	rm -fr $(MODULES)

#
# Include a dependency file (if one exists)
#
ifneq ($(MAKECMDGOALS), clean)
ifeq (.depend,$(wildcard .depend))
include .depend
endif
endif

endif  # 2.5 stuff.
