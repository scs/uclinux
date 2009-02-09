VER = lua-5.1.4
URL = http://www.lua.org/ftp/$(VER).tar.gz

CPPFLAGS-y := -DLUA_USE_POSIX
CPPFLAGS-$(CONFIG_FMT_USE_FDPIC_ELF) += -DLUA_USE_DLOPEN
CPPFLAGS-$(CONFIG_LIB_READLINE)      += -DLUA_USE_READLINE
CPPFLAGS += $(CPPFLAGS-y)

MYLIBS-y :=
MYLIBS-$(CONFIG_FMT_USE_FDPIC_ELF) += -ldl
MYLIBS-$(CONFIG_LIB_READLINE)      += -lreadline -lhistory

all:
	$(MAKE) \
		-C $(VER) \
		INSTALL_TOP=/usr \
		PLAT=generic \
		CC=$(CC) \
		AR="$(AR) rcu" \
		RANLIB=$(RANLIB) \
		MYLIBS="$(MYLIBS-y)"

clean:
	$(MAKE) -C $(VER) clean

romfs:
	$(ROMFSINST) -d $(VER)/src/lua /usr/bin/lua
	$(ROMFSINST) -d $(VER)/src/luac /usr/bin/luac

.PHONY: all clean romfs
