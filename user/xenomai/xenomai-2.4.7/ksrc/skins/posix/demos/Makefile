# Using a single source image, this demo illustrates the real-time
# guarantees provided by Xenomai's POSIX skin in user-space
# (accuracy_rt) compared to those available from the native
# NPTL/LinuxThreads supports (accuracy).

bin_PROGRAMS= accuracy accuracy_rt

all: $(bin_PROGRAMS)

# To use this makefile with xeno-config not located at /usr/xenomai/bin, type :
# make XENO_CONFIG=/path/to/xeno-config
XENO_CONFIG=$(DESTDIR)/usr/xenomai/bin/xeno-config
prefix := $(shell DESTDIR=$(DESTDIR) $(XENO_CONFIG) --prefix)

ifeq ($(prefix),)
$(error Please add <xenomai-install-path>/bin to your PATH variable or type: \
make XENO_CONFIG=<xenomai-install-path>/bin/xeno-config)
endif

CC:= $(shell $(XENO_CONFIG) --cc)
CFLAGS_RT:= $(shell DESTDIR=$(DESTDIR) $(XENO_CONFIG) --posix-cflags) -g
LDFLAGS_RT:= $(shell DESTDIR=$(DESTDIR) $(XENO_CONFIG) --posix-ldflags)
CFLAGS= -D_GNU_SOURCE -D_REENTRANT -Wstrict-prototypes -g -O2 -Wall
LDFLAGS= -lpthread -lrt

accuracy: CFLAGS+=-DSPERIOD=2000

accuracy_rt.o: CFLAGS_RT=-DSPERIOD=100

%_rt.o: %.c
	$(CC) $(CFLAGS_RT) $< -c -o $@

%_rt: LDFLAGS=$(LDFLAGS_RT)

clean:
	$(RM) $(bin_PROGRAMS) *.o
