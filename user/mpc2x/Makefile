
VER = mpc2x-0.2

PKG_CONFIG ?= $(CROSS_COMPILE)pkg-config

SDL_CFLAGS = $(shell $(PKG_CONFIG) sdl --cflags)
SDL_LIBS = $(shell $(PKG_CONFIG) sdl --libs)

CXXFLAGS += $(SDL_CFLAGS)
CPPFLAGS +=
LDLIBS += -lSDL_ttf -lfreetype -lSDL_image -ljpeg -lpng12 -lz $(SDL_LIBS)

VPATH += $(VER)

all: mpc2x

mpc2x: libmpdclient.o

clean:
	rm -f mpc2x *.o

romfs:
	$(ROMFSINST) -d mpc2x /usr/bin/mpc2x
	$(ROMFSINST) -d mpc2x.conf /etc/
	$(ROMFSINST) -d testskin  /etc/testskin

.PHONY: all clean romfs

