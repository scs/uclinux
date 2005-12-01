OPROFILE_DIR=/home/ksh/cvs/commit/11-23/uClinux-dist/user/blkfin-apps/oprofile
VERSION=0.9.1
KVERS=
KSRC=

EXTRA_CFLAGS= -DEXPECT_OK -D__NO_VERSION__ \
	-I$(OPROFILE_DIR)/module/ -I$(OPROFILE_DIR) -I$(OPROFILE_DIR)/libutil -I$(OPROFILE_DIR)/libop

# NB: do not add a file here without adding it to EXTRA_DIST in ../Makefile.am

O_TARGET := oprofile-module.o
 
obj-y := compat.o op_init.o op_util.o op_dname.o oprofile.o /arch.o $(OPROFILE_DIR)/libop/libop.a
obj-m := $(O_TARGET)
O_OBJS := $(obj-y)
M_OBJS := $(O_TARGET)

TOPDIR := $(KSRC)
CONFIG_SHELL := TOPDIR=$(KSRC) /bin/bash
include $(KSRC)/Rules.make

# FIXME: deps
