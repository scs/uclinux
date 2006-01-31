#
#
# can4linux -- LINUX device driver Makefile
#
# Copyright (c) 2004 port GmbH Halle/Saale
#

# Used release tag for this software version
VERSION=3
REL=3.5
RELEASE=CAN4LINUX-$(VERSION)_$(REL)
DVERSION=$(VERSION).$(REL)


KVERSION= $(shell uname -r)
CONFIG := $(shell uname -n)

# be prepared for RTLinux
LINUXTARGET=LINUXOS
#LINUXTARGET=RTLinux


CTAGS =	ctags --c-types=dtvf
CTAGS =	elvtags -tsevl
ECHO  = /bin/echo

TITLE = LINUX driver module example 

#
# The driver major device number
# development starts with major=63
#  (LOCAL/EXPERIMENTAL USE)
# The new linux/Documentation/devices.txt defines major=91
CAN_MAJOR=	91





CAN_MODULE = can.ko


# definitions for the hardware target
#########################################################################
# Only AT-CAN-MINI can be compiled for 82c200 or PeliCAN mode.
# All other Targets are assuming to have an SJA1000
# CPC_PCI  implies PeliCAN
##
## Supported TARGET= IME_SLIMLINE | ATCANMINI_PELICAN | CPC_PCI | CPC_CARD 
## | IXXAT_PCI03 | PCM3680 | PC104_200 | SBS_PC7 | TRM816 | GENERIC_I82527
## | CC_CANPCI
##
## compile DigiTec FC-CAN as ATCANMINI_PELICAN
##


# up to now look for the CONFIG Settings and convert to TARGET= ----
# later we can improve it by checking directly
#
#   ifeq ($(CONFIG_CAN_MCF5282),m)
#   can_objs += mcf5282funcs.o
#   EXTRA_CFLAGS += -DMCF5282 -DMAX_CHANNELS=1 -DUSE_FASYNC
#   TARGET=ColdFire_FlexCAN
#   endif
##


##########################################################################
ifdef CONFIG_CAN_ATCANMINI
TARGET = ATCANMINI_PELICAN
endif

ifdef CONFIG_CAN_CPC_PCI
TARGET = CPC_PCI
endif

ifdef CONFIG_CAN_MCF5282
TARGET = ColdFire_FlexCAN
endif

ifdef CONFIG_CAN_CANPCI
TARGET = CC_CANPCI
endif

ifdef CONFIG_CAN_BLACKFIN
TARGET = AD_BLACKFIN
endif

ifdef THIS_IS_HERE_FOR_REFERENCE
#TARGET=IXXAT_PCI03
#TARGET=IME_SLIMLINE
#TARGET=PCM3680
#TARGET=PC104_200
#TARGET=CPC_CARD
#TARGET=ATCANMINI_PELICAN
#TARGET=CPC_PCI
#TARGET=TRM816
#TARGET=GENERIC_I82527
#TARGET=SBS_PC7
#TARGET=CC_CANPCI
#TARGET=AD_BLACKFIN
endif

##########################################################################


TARGET_MATCHED = false
# location of the compiled objects and the final driver module
OBJDIR = obj

# Debugging Code within the driver
# to use the Debugging option
# and the Debugging control via /proc/sys/Can/DbgMask
# the Makefile in subdir Can must called with the DEBUG set to
# DEBUG=1
# else
# NODEBUG
# doesn't compile any debug code into the driver
DEBUG=NODEBUG
DEBUG=DEBUG=1

# all definitions for compiling the sources
# CAN_PORT_IO		- use port I/O instead of memory I/O
# CAN_INDEXED_PORT_IO   - CAN registers adressed by a pair of registers
#			  one is selcting the register the other one does i/O
#			  used eg. on Elan CPUs
# CAN4LINUX_PCI
# IODEBUG               - all register write accesses are logged
# CONFIG_TIME_MEASURE=1 - enable Time measurement at parallel port
#



ifeq "$(TARGET)" "CPC_PCI"
# CPC-PCI PeliCAN  PCI (only with SJA1000) ------------------------------------
DEFS =  -D$(TARGET) -D$(DEBUG) -DDEFAULT_DEBUG -DCAN_MAJOR=$(CAN_MAJOR)\
	-DCAN4LINUX_PCI \
	-DCAN_SYSCLK=8

	#-DIODEBUG

TARGET_MATCHED = true
endif

ifeq "$(TARGET)" "CC_CANPCI"
# CPC-PCI PeliCAN  PCI (only with SJA1000) ------------------------------------
DEFS =  -D$(TARGET) -D$(DEBUG) -DDEFAULT_DEBUG -DCAN_MAJOR=$(CAN_MAJOR)\
	-DCAN4LINUX_PCI \
	-DCAN_PORT_IO   \
	-DCAN_SYSCLK=8

	#-DIODEBUG

TARGET_MATCHED = true
endif

ifeq "$(TARGET)" "ATCANMINI_PELICAN"
# AT-CAN-MINI PeliCAN ISA (only with SJA1000) --------------------------------
DEFS =  -D$(TARGET) -D$(DEBUG) -DDEFAULT_DEBUG -DCAN_MAJOR=$(CAN_MAJOR) \
	-DCAN_PORT_IO \
	-DCAN_SYSCLK=8
	#-DCONFIG_M586
	#-DCONFIG_TIME_MEASURE=1

TARGET_MATCHED = true
endif

ifeq "$(TARGET)" "CPC_CARD"
# CPC-Card PeliCAN  PC-Card  (only with SJA1000) -----------------------------
DEFS =  -D$(TARGET) -D$(DEBUG) -DDEFAULT_DEBUG -DCAN_MAJOR=$(CAN_MAJOR)\
	-DCAN4LINUX_PCCARD \
	-DCAN_SYSCLK=8

	#-DIODEBUG

TARGET_MATCHED = true
endif

ifeq "$(TARGET)" "IXXAT_PCI03"
# IXXAT PC-I 03 board ISA (only with SJA1000) ---------------------------------
DEFS =  -D$(TARGET) -D$(DEBUG) -DDEFAULT_DEBUG -DCAN_MAJOR=$(CAN_MAJOR) \
	-DCAN_SYSCLK=8

TARGET_MATCHED = true
endif

ifeq "$(TARGET)" "PCM3680"
# Advantech PCM3680 PC104 board 2xCAN (only with SJA1000) --------------------
# http://www.advantech.gr/epc/products/pcm3680.htm
DEFS =  -D$(TARGET) -D$(DEBUG) -DDEFAULT_DEBUG -DCAN_MAJOR=$(CAN_MAJOR) \
	-DCAN_SYSCLK=8

TARGET_MATCHED = true
endif

ifeq "$(TARGET)" "TRM816"
# TRM816 Onboard CAN-Controller (only with SJA1000) --------------------------
DEFS =  -D$(TARGET) -D$(DEBUG) -DDEFAULT_DEBUG -DCAN_MAJOR=$(CAN_MAJOR) \
	-DCAN_INDEXED_PORT_IO \
	-DCAN_SYSCLK=10
	-DMAX_CHANNELS=2

TARGET_MATCHED = true
endif

ifeq "$(TARGET)" "PC104_200"
# ESD PC104-200 PC104 board (with SJA1000) ----------------------------
DEFS =  -D$(TARGET) -D$(DEBUG) -DDEFAULT_DEBUG -DCAN_MAJOR=$(CAN_MAJOR) \
	-DCAN_PORT_IO -DPC104 \
	-DCAN_SYSCLK=8

TARGET_MATCHED = true
endif

ifeq "$(TARGET)" "IME_SLIMLINE"
# I+ME  PcSlimline ISA (only with SJA1000) -----------------------------------
DEFS =  -D$(TARGET) -D$(DEBUG) -DDEFAULT_DEBUG -DCAN_MAJOR=$(CAN_MAJOR) \
	-DCAN_SYSCLK=8

TARGET_MATCHED = true
endif

ifeq "$(TARGET)" "GENERIC_I82527"
# Generic i82527 card
DEFS =  -D$(TARGET) -D$(DEBUG) -DCAN_MAJOR=$(CAN_MAJOR) \
	-DCAN_SYSCLK=8 -DCAN_PORT_IO

TARGET_MATCHED = true
endif

ifeq "$(TARGET)" "SBS_PC7"
# SBS PC7compact DINrail mounted Industry PC (with i82527)
DEFS =  -D$(TARGET) -D$(DEBUG) -DCAN_MAJOR=$(CAN_MAJOR) \
	-DCAN_SYSCLK=8 -DCAN_PORT_IO

TARGET_MATCHED = true
endif


ifeq "$(TARGET)" "AD_BLACKFIN"
# integrated CAN of the Analog Devices BlackFin DSP
DEFS =  -D$(TARGET) -D$(DEBUG) -DCAN_MAJOR=$(CAN_MAJOR) \
	-DCAN_SYSCLK=125 \
	-DMAX_CHANNELS=1 -DCONFIG_TIME_MEASURE=1

TARGET_MATCHED = true
endif




ifneq ($(KERNELRELEASE),)

EXTRA_CFLAGS  = $(DEFS) -DVERSION=\"$(DVERSION)_$(TARGET)\"
obj-m		:= can.o
# add other object modules here
can-objs	:= core.o	\
	    open.o		\
	    read.o		\
	    write.o		\
	    ioctl.o		\
	    select.o	\
	    debug.o		\
	    error.o		\
	    util.o		\
	    sysctl.o	\
	    async.o		\
	    close.o		\

	    # include Chip/board specific object files and definitions
	    ##########################################################
	    ifeq "$(TARGET)" "CPC_PCI"
	    can-objs += sja1000funcs.o
	    endif
	    ifeq "$(TARGET)" "CPC_CARD"
	    can-objs += sja1000funcs.o
	    endif
	    ifeq "$(TARGET)" "CC_CANPCI"
	    can-objs += sja1000funcs.o
	    endif
	    ifeq "$(TARGET)" "ATCANMINI_PELICAN"
	    can-objs += sja1000funcs.o
	    endif
	    ifeq "$(TARGET)" "IXXAT_PCI03"
	    can-objs += sja1000funcs.o
	    endif
	    ifeq "$(TARGET)" "PCM3680"
	    can-objs += sja1000funcs.o
	    endif
	    ifeq "$(TARGET)" "TRM816"
	    can-objs += sja1000funcs.o
	    endif
	    ifeq "$(TARGET)" "PC104_200"
	    can-objs += sja1000funcs.o
	    endif
	    ifeq "$(TARGET)" "IME_SLIMLINE"
	    can-objs += sja1000funcs.o
	    endif
	    ifeq "$(TARGET)" "SBS_PC7"
	    can-objs += i82527funcs.o
	    endif
	    ifeq "$(TARGET)" "ColdFire_FlexCAN"
	    can-objs += mcf5282funcs.o
	    endif
	    ifeq "$(TARGET)" "AD_BLACKFIN"
	    can-objs += bf537funcs.o
	    endif


else
KDIR	:=/home/oertel/pakete/linux/
KDIR 	:= /lib/modules/$(shell uname -r)/build/
PWD	:= $(shell pwd)

ifndef TARGET
all:
	@echo "Plese specify TARGET= at command line" 
else
all:
	@echo "compile with KDIR=$(KDIR)"
	$(MAKE)	-C $(KDIR) M=$(PWD) TARGET=$(TARGET) modules
endif
endif



# load host specific driver
load:
	$(ECHO) ">>> " Loading Driver Module to Kernel
	/sbin/insmod $(CAN_MODULE)
	@echo "Loading etc/$(CONFIG).conf CAN configuration"
	./utils/cansetup ./etc/$(CONFIG).conf
	#echo 7 >/proc/sys/Can/dbgMask



# unload the driver module
unload:
	$(ECHO) ">>> " Removing Driver Module from Kernel
	-/sbin/rmmod $(CAN_MODULE:.o=)



clean:
	-rm -f tags
	-rm -f *.o *.ko
	-rm -f .*.cmd *.mod.c
	-rm -rf .tmp_versions


inodes:
	-mknod /dev/can0 c $(CAN_MAJOR) 0
	-mknod /dev/can1 c $(CAN_MAJOR) 1
	-mknod /dev/can2 c $(CAN_MAJOR) 2
	-mknod /dev/can3 c $(CAN_MAJOR) 3
	-mknod /dev/can4 c $(CAN_MAJOR) 4
	-mknod /dev/can5 c $(CAN_MAJOR) 5
	-mknod /dev/can6 c $(CAN_MAJOR) 6
	-mknod /dev/can7 c $(CAN_MAJOR) 7
	chmod 666 /dev/can[0-7]



ctags:
	$(CTAGS)  *.[ch] 


#### HTML Manual section. #################################
man:    port_footer.html
	doxygen

help:
	grep "^## " Makefile

# Henrik Maier's special load target
hm:
	make TARGET=SBS_PC7
	-/sbin/rmmod $(CAN_MODULE:.o=)
	/sbin/insmod $(CAN_MODULE)
	./utils/cansetup ./etc/pc7.conf
	echo 7 >/proc/sys/Can/dbgMask
