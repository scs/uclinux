CRAMFS_CFLAGS = -W -Wall
CRAMFS_CPPFLAGS = -I.
CRAMFS_CPPFLAGS += -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE
CRAMFS_CPPFLAGS += $(shell ./detectendian.sh)

CC ?= gcc
BUILD_CC ?= gcc
CFLAGS ?= -O2 -g
CPPFLAGS += $(CRAMFS_CPPFLAGS)
BUILD_CPPFLAGS += $(CRAMFS_CPPFLAGS)
LDLIBS = -lz
PROGS = mkcramfs cramfsck
HOST_PROGS = $(patsubst %,host_build/%,$(PROGS))

all: $(PROGS) $(HOST_PROGS)

HOST_FILE = $(patsubst host_build/%,%,$@)
host_build/%:
	mkdir -p host_build
	$(BUILD_CC) $(BUILD_CFLAGS) $(BUILD_CPPFLAGS) $(HOST_FILE).c -o $@ $(LDLIBS)

romfs:
	$(ROMFSINST) -e CONFIG_USER_CRAMFS_MKCRAMFS /bin/mkcramfs
	$(ROMFSINST) -e CONFIG_USER_CRAMFS_CRAMFSCK /bin/cramfsck

distclean clean:
	rm -rf $(PROGS) *.o */*.o host_build

.PHONY: all clean
