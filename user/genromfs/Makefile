VER = genromfs-0.5.2

BUILD_CC ?= gcc
BUILD_CFLAGS ?= -O2
BUILD_CFLAGS += -Wall
BUILD_CPPFLAGS ?=
BUILD_CPPFLAGS += -DVERSION=\"$(VER)\"
BUILD_LDFLAGS ?=

VPATH += $(VER)

all: genromfs

genromfs: CC = $(BUILD_CC)
genromfs: CFLAGS = $(BUILD_CFLAGS)
genromfs: CPPFLAGS = $(BUILD_CPPFLAGS)
genromfs: LDFLAGS = $(BUILD_LDFLAGS)
genromfs: genromfs.c

clean:
	rm -rf genromfs

romfs:

.PHONY: all clean romfs
