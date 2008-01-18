# This makefile makes it very simple to build
# components from within user/xxx directories.
# Each user/xxx/Makefile should include the first line:
# -include ../user.mak
#
# This will pull in all the necessary definitions such that
# the targets: all, clean, romfs, image 
# will work from those directories
#
# If you need this to work in a lower subdirectory
# (say user/xxx/yyy) you should define _reldir=../..
# or as appropriate
#
ifndef ROOTDIR
_reldir ?= ..
ROOTDIR := $(shell pwd)/$(_reldir)/..

UCLINUX_BUILD_USER=1

include $(ROOTDIR)/.config

LINUXDIR := $(CONFIG_LINUXDIR)
LIBCDIR  := $(CONFIG_LIBCDIR)
PATH	 := $(PATH):$(ROOTDIR)/tools
HOSTCC   := cc
IMAGEDIR := $(ROOTDIR)/images
RELDIR   := $(ROOTDIR)/release
ROMFSDIR := $(ROOTDIR)/romfs
ROMFSINST:= romfs-inst.sh
TFTPDIR    := /tftpboot

LINUX_CONFIG  := $(ROOTDIR)/$(LINUXDIR)/.config
CONFIG_CONFIG := $(ROOTDIR)/config/.config
MODULES_CONFIG := $(ROOTDIR)/modules/.config
ARCH_CONFIG := $(ROOTDIR)/config.arch

MAKEARCH = $(MAKE) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE)

export VENDOR PRODUCT ROOTDIR LINUXDIR HOSTCC
export ARCH_CONFIG CONFIG_CONFIG LINUX_CONFIG MODULES_CONFIG ROMFSDIR
export VERSIONPKG VERSIONSTR ROMFSINST PATH IMAGEDIR RELDIR RELFILES TFTPDIR

-include $(LINUX_CONFIG)
-include $(CONFIG_CONFIG)
-include $(MODULES_CONFIG)
-include $(ARCH_CONFIG)

# Set up the default target
ALL: all

.PHONY: romfs image ALL all
image:
	$(MAKEARCH) -C $(ROOTDIR)/vendors image

endif
