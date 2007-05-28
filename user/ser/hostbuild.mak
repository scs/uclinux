CONFIG_USER_SER_RTPPROXY=y

LDLIBS += -lresolv
CFLAGS += -g -O0
LDFLAGS += -g

ALL: all

install: all
	mkdir -p lib/ser
	cp modules/*/*.so lib/ser

