GDOTS   := g729

DIRS_ALL := $(patsubst %,%_all,$(GDOTS))
all: $(DIRS_ALL)
%_all:
	$(MAKE) -C $(patsubst %_all,%,$@)
ifneq ($(STAGEDIR),)
	$(MAKE) -C $(patsubst %_all,%,$@) DESTDIR=$(STAGEDIR) install
endif

DIRS_CLEAN := $(patsubst %,%_clean,$(GDOTS))
clean: $(DIRS_CLEAN)
%_clean:
	$(MAKE) -C $(patsubst %_clean,%,$@) clean

DIRS_TEST := $(patsubst %,%_check,$(GDOTS))
check test: $(DIRS_TEST)
%_check:
	$(MAKE) -C $(patsubst %_check,%,$@) check

dist:
	@echo "TODO: implement this :)"

romfs:
	set -e ; \
	cd $(STAGEDIR)/usr/lib ; \
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF libg729ab.so /lib/libg729ab.so ;

.PHONY: all check clean dist romfs test
