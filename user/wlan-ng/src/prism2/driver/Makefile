# src/prism2/driver/Makefile
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

include $(WLAN_SRC)../../../config.mk

ifeq ($(WLAN_DEBUG), y)
WLAN_INCLUDE_DEBUG=-DWLAN_INCLUDE_DEBUG
endif

ifeq ($(KERN_25), y)
ifneq ($(KERNELRELEASE),)

EXTRA_CFLAGS += -I$(src)/../../include -I$(src)/../include $(WLAN_INCLUDE_DEBUG)

ifeq ($(PRISM2_PCMCIA), y)
	obj-m += prism2_cs.o
endif

ifeq ($(PRISM2_PCI), y)
	obj-m += prism2_pci.o
endif

ifeq ($(PRISM2_PLX), y)
	obj-m += prism2_plx.o
endif

ifeq ($(PRISM2_USB), y)
	obj-m += prism2_usb.o
endif

else

PWD := $(shell pwd)
default:
	$(MAKE) -C $(LINUX_SRC) SUBDIRS=$(PWD) WLAN_SRC=$(PWD)/ modules

endif  #KERNELRELEASE

clean:
	rm -f *.o *.ko .*.cmd *.mod.c

install:
	mkdir -p $(TARGET_MODDIR)/kernel/drivers/net
	cp *.ko	$(TARGET_MODDIR)/kernel/drivers/net

else  # not KERN_25

# Source and obj and target definitions
CS_OBJ_DIR=obj_cs
PLX_OBJ_DIR=obj_plx
PCI_OBJ_DIR=obj_pci
USB_OBJ_DIR=obj_usb

SRC=prism2sta.c prism2mgmt.c prism2mib.c 

CS_MODULE=prism2_cs.o
PLX_MODULE=prism2_plx.o
PCI_MODULE=prism2_pci.o
USB_MODULE=prism2_usb.o

CS_OBJ=		$(CS_OBJ_DIR)/prism2sta.o \
		$(CS_OBJ_DIR)/prism2mgmt.o \
		$(CS_OBJ_DIR)/prism2mib.o \
		$(CS_OBJ_DIR)/hfa384x.o

PLX_OBJ=	$(PLX_OBJ_DIR)/prism2sta.o \
		$(PLX_OBJ_DIR)/prism2mgmt.o \
		$(PLX_OBJ_DIR)/prism2mib.o \
		$(PLX_OBJ_DIR)/hfa384x.o

PCI_OBJ=	$(PCI_OBJ_DIR)/prism2sta.o \
		$(PCI_OBJ_DIR)/prism2mgmt.o \
		$(PCI_OBJ_DIR)/prism2mib.o \
		$(PCI_OBJ_DIR)/hfa384x.o

USB_OBJ=	$(USB_OBJ_DIR)/prism2sta.o \
		$(USB_OBJ_DIR)/prism2mgmt.o \
		$(USB_OBJ_DIR)/prism2mib.o \
		$(USB_OBJ_DIR)/hfa384x_usb.o

# List of modules to build
MODULES=
ifeq ($(PRISM2_PCMCIA), y)
MODULES+=$(CS_MODULE)
endif
ifeq ($(PRISM2_PLX), y)
MODULES+=$(PLX_MODULE)
endif
ifeq ($(PRISM2_PCI), y)
MODULES+=$(PCI_MODULE)
endif
ifeq ($(PRISM2_USB), y)
MODULES+=$(USB_MODULE)
endif

# Preprocessor Options
CPPFLAGS=-I../../include -I../include $(WLAN_INCLUDE_DEBUG)
CFLAGS = $(KERNEL_CFLAGS) $(KERNEL_MODFLAGS)

# Use the following if building for kernel pcmcia
ifeq ($(WLAN_KERN_PCMCIA), y)
CS_CFLAGS= $(CFLAGS)
else
CS_CFLAGS=-I$(PCMCIA_SRC)/include $(KERNEL_CFLAGS) $(PCMCIA_MODFLAGS)
endif

# Implicit rules to handle the separate obj dirs
$(CS_OBJ_DIR)/%.o : %.c
	$(CC) -c $(CS_CFLAGS) $(CPPFLAGS) \
	-DWLAN_HOSTIF=WLAN_PCMCIA $< -o $@

$(PLX_OBJ_DIR)/%.o : %.c
	$(CC) -c $(CFLAGS) $(CPPFLAGS) \
	-DWLAN_HOSTIF=WLAN_PLX $< -o $@

$(PCI_OBJ_DIR)/%.o : %.c
	$(CC) -c $(CFLAGS) $(CPPFLAGS) \
	-DWLAN_HOSTIF=WLAN_PCI $< -o $@

$(USB_OBJ_DIR)/%.o : %.c
	$(CC) -c $(CFLAGS) $(CPPFLAGS) \
	-DWLAN_HOSTIF=WLAN_USB $< -o $@

# Dependency Source List
DEP_SRC=$(SRC)

# Rules
all : .depend dirs $(MODULES)

dirs : 
	mkdir -p $(CS_OBJ_DIR)
	mkdir -p $(PLX_OBJ_DIR)
	mkdir -p $(PCI_OBJ_DIR)
	mkdir -p $(USB_OBJ_DIR)

$(CS_MODULE) : $(CS_OBJ)
	$(LD) -r -o $@ $(CS_OBJ)
	chmod -x $@

$(PLX_MODULE) : $(PLX_OBJ)
	$(LD) -r -o $@ $(PLX_OBJ)
	chmod -x $@

$(PCI_MODULE) : $(PCI_OBJ)
	$(LD) -r -o $@ $(PCI_OBJ)
	chmod -x $@

$(USB_MODULE) : $(USB_OBJ)
	$(LD) -r -o $@ $(USB_OBJ)
	chmod -x $@

install : $(MODULES)
ifeq ($(PRISM2_PCMCIA), y)
	mkdir -p $(TARGET_MODDIR)/pcmcia
	cp -f $(CS_MODULE) $(TARGET_MODDIR)/pcmcia 
endif
ifeq ($(PRISM2_PCI), y)
	mkdir -p $(TARGET_MODDIR)/net
	cp -f $(PCI_MODULE) $(TARGET_MODDIR)/net 
endif
ifeq ($(PRISM2_PLX), y)
	mkdir -p $(TARGET_MODDIR)/net
	cp -f $(PLX_MODULE) $(TARGET_MODDIR)/net 
endif
ifeq ($(PRISM2_USB), y)
	mkdir -p $(TARGET_MODDIR)/usb
	cp -f $(USB_MODULE) $(TARGET_MODDIR)/usb 
endif

romfs: $(MODULES)
ifeq ($(PRISM2_PCMCIA), y)
	mkdir -p $(ROMFSDIR)/lib/modules/$(KERNELRELEASE)/pcmcia
	$(ROMFSINST) /lib/modules/$(KERNELRELEASE)/net/$(CS_MODULE)
endif
ifeq ($(PRISM2_PCI), y)
	mkdir -p $(ROMFSDIR)/lib/modules/$(KERNELRELEASE)/net
	$(ROMFSINST) /lib/modules/$(KERNELRELEASE)/net/$(PCI_MODULE)
endif
ifeq ($(PRISM2_PLX), y)
	mkdir -p $(ROMFSDIR)/lib/modules/$(KERNELRELEASE)/net
	$(ROMFSINST) /lib/modules/$(KERNELRELEASE)/net/$(PLX_MODULE)
endif
ifeq ($(PRISM2_USB), y)
	mkdir -p $(ROMFSDIR)/lib/modules/$(KERNELRELEASE)/usb
	$(ROMFSINST) /lib/modules/$(KERNELRELEASE)/net/$(USB_MODULE)
endif

clean: 
	rm -f .depend*
	rm -f core core.* *.o .*.o *.s *.a .depend tmp_make *~ tags
	rm -fr $(CS_OBJ_DIR)
	rm -fr $(PLX_OBJ_DIR)
	rm -fr $(PCI_OBJ_DIR)
	rm -fr $(USB_OBJ_DIR)
	rm -fr $(MODULES)

# This probably isn't the best way to handle the dependencies, but it works.
DEPLIST=
ifeq ($(PRISM2_PCMCIA), y)
DEPLIST+=.depend.cs
endif
ifeq ($(PRISM2_PLX), y)
DEPLIST+=.depend.plx
endif
ifeq ($(PRISM2_PCI), y)
DEPLIST+=.depend.pci
endif
ifeq ($(PRISM2_USB), y)
DEPLIST+=.depend.usb
endif

dep .depend: $(DEPLIST)
ifdef DEPLIST
	cat $(DEPLIST) > .depend
endif

.depend.plx: $(DEP_SRC) hfa384x.c ../../../config.mk $(wildcard $(LINUX_SRC)/.config)
	rm -f $@
	for i in $(DEP_SRC) hfa384x.c ; do \
		(/bin/echo -n $(PLX_OBJ_DIR)/ ; \
		$(CPP) -DWLAN_HOSTIF=WLAN_PLX -M $(CFLAGS) $(CPPFLAGS) $$i ) \
		>> $@ ; \
	done

.depend.pci: $(DEP_SRC) hfa384x.c ../../../config.mk $(wildcard $(LINUX_SRC)/.config)
	rm -f $@
	for i in $(DEP_SRC) hfa384x.c ; do \
		(/bin/echo -n $(PCI_OBJ_DIR)/ ; \
		$(CPP) -DWLAN_HOSTIF=WLAN_PCI -M $(CFLAGS) $(CPPFLAGS) $$i ) \
		>> $@ ; \
	done

.depend.cs: $(DEP_SRC) hfa384x.c ../../../config.mk $(wildcard $(LINUX_SRC)/.config)
	rm -f $@
	for i in $(DEP_SRC) hfa384x.c ; do \
		(/bin/echo -n $(CS_OBJ_DIR)/ ; \
		$(CPP) -DWLAN_HOSTIF=WLAN_PCMCIA -M $(CS_CFLAGS) $(CPPFLAGS) \
		 $$i ) \
		>> $@ ; \
	done

.depend.usb: $(DEP_SRC) hfa384x_usb.c ../../../config.mk $(wildcard $(LINUX_SRC)/.config)
	rm -f $@
	for i in $(DEP_SRC) hfa384x_usb.c ; do \
		(/bin/echo -n $(USB_OBJ_DIR)/ ; \
		$(CPP) -DWLAN_HOSTIF=WLAN_USB -M $(CFLAGS) $(CPPFLAGS) $$i ) \
		>> $@ ; \
	done

#
# Include a dependency file (if one exists)
#
ifneq ($(MAKECMDGOALS), clean)
ifeq (.depend,$(wildcard .depend))
include .depend
endif
endif


endif # KERN_25
