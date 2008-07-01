##############################
# spcaview Makefile
##############################

APP_BINARY=luvcview

SDL_CONFIG=$(STAGEDIR)/usr/bin/sdl-config
SDLLIBS = $(shell $(SDL_CONFIG) --libs)
SDLFLAGS = $(shell $(SDL_CONFIG) --cflags)

#LIBX11FLAGS= -I/usr/X11R6/include -L/usr/X11R6/lib
VERSION = 0.2.4

#WARNINGS = -Wall \
#           -Wundef -Wpointer-arith -Wbad-function-cast \
#           -Wcast-align -Wwrite-strings -Wstrict-prototypes \
#           -Wmissing-prototypes -Wmissing-declarations \
#           -Wnested-externs -Winline -Wcast-qual -W \
#           -Wno-unused
#           -Wunused

CFLAGS += -DUSE_SDL -O2 -DLINUX -DVERSION=\"$(VERSION)\" -I$(SDLFLAGS) -I../linux-uvc-svn-220 $(WARNINGS)
CPPFLAGS = $(CFLAGS)

OBJECTS= luvcview.o color.o utils.o v4l2uvc.o gui.o avilib.o

all:	luvcview

clean:
	@echo "Cleaning up directory."
	rm -f *.a *.o $(APP_BINARY) core *~ log errlog *.avi

# Applications:
luvcview:	$(OBJECTS)
	$(CC)	$(CFLAGS) $(OBJECTS) $(X11_LIB) $(XPM_LIB)\
		$(MATH_LIB) \
		$(SDLLIBS)\
		-o $(APP_BINARY)
	chmod 755 $(APP_BINARY)


romfs:
	$(ROMFSINST) -d $(APP_BINARY) /usr/bin/$(APP_BINARY)
