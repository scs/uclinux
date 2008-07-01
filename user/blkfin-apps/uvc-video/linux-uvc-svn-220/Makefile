ifeq ($(origin CC),default)
CC := bfin-uclinux-gcc
endif
MAKEARCH_KERNEL ?= $(MAKE) ARCH=blackfin CROSS_COMPILE=bfin-uclinux-
ROOTDIR  ?= $(PWD)/../../../../
LINUXDIR ?= linux-2.6.x

obj-m := hs_conv.o

EXTRA_CFLAGS += -Wall -g -O2


obj-m		:= uvcvideo.o
uvcvideo-objs   := uvc_driver.o uvc_queue.o uvc_v4l2.o uvc_video.o uvc_ctrl.o uvc_status.o uvc_isight.o

all: uvcvideo

uvcvideo:
	@echo "Building USB Video Class driver..."
	@sh svn-version.sh > version.h 2>/dev/null
	CFLAGS="" CPPFLAGS="" LDFLAGS="" \
	$(MAKEARCH_KERNEL) -C $(ROOTDIR)/$(LINUXDIR) SUBDIRS=$$PWD modules

romfs:
	$(ROMFSINST) -d -M uvcvideo.ko blkfindrvs/uvcvideo.ko

clean:
	-rm -f *.o *.ko .*.cmd .*.flags *.mod.c Module.symvers version.h modules.order
	-rm -rf .tmp_versions

