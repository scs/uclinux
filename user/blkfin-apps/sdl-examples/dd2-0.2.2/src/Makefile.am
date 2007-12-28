SUBDIRS = data

AUTOMAKE_OPTIONS = no-dependencies

bin_PROGRAMS = dd2
dd2_SOURCES = menu.c SDL_plus.c cfg.c engine.c control.c engine.h control.h cfg.h SDL_plus.h menu.h main.c main.h
EXTRA_DIST = menu.c SDL_plus.c cfg.c engine.c control.c engine.h control.h cfg.h SDL_plus.h menu.h main.c main.h

AM_CFLAGS = -DDD2_DATA=\"$(pkgdatadir)\" -Wall
