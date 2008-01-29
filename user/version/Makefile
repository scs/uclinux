ROOTDIR ?= ../..

include id.mk

EXEC = version
OBJS = version.o


all: $(EXEC) stamp.o

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

romfs:
	$(ROMFSINST) /bin/$(EXEC)

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o

.PHONY: .version
.version:
	@if [ ! -f .version ]; then \
		echo 1 > .version; \
	else \
		expr 0`cat .version` + 1 > .version; \
	fi

.PHONY: compile.h
compile.h: $(CONFIGURATION) version.h .version
	@if [ -f .name ]; then \
	  echo \#define TOOLCHAIN_VERSION \"\#`cat .version`-`cat .name` `date`\"; \
	 else \
	  echo \#define TOOLCHAIN_VERSION \"\#`cat .version` `date`\";  \
	 fi >> .ver
	@echo \#define TOOLCHAIN_COMPILE_TIME \"`date +%T`\" >> .ver
	@echo \#define TOOLCHAIN_COMPILE_BY \"`whoami`\" >> .ver
	@echo \#define TOOLCHAIN_COMPILE_HOST \"`hostname`\" >> .ver
	@if [ -x /bin/dnsdomainname ]; then \
	  echo \#define TOOLCHAIN_COMPILE_DOMAIN \"`dnsdomainname`\"; \
	elif [ -x /bin/domainname ]; then \
	  echo \#define TOOLCHAIN_COMPILE_DOMAIN \"`domainname`\"; \
	else \
	  echo \#define TOOLCHAIN_COMPILE_DOMAIN ; \
	fi >> .ver
	@echo \#define TOOLCHAIN_COMPILER \"`$(CC) -v 2>&1 | tail -1`\" >> .ver
	@echo \#define TOOLCHAIN_FILENAME \"$(CC)\" >> .ver
	@mv -f .ver $@

USER_DIST_VERSION = $(shell \
	test -d $(ROOTDIR)/.svn \
		&& (echo -n svn- ; svn info $(ROOTDIR) | sed -n '/^Last Changed Rev/s|^.*: ||p') \
		|| grep '^Version:' $(ROOTDIR)/release_notes | awk '{print $$NF}' \
)

.PHONY: version.h
version.h: Makefile id.mk
	@echo \#define TOOLCHAIN_BANNER \"$(BANNER)\" > .ver
	@echo \#define TOOLCHAIN_NAME \"$(TOOLCHAIN)\" >> .ver
	@echo \#define TOOLCHAIN_RELEASE \"$(VERSION).$(PATCHLEVEL).$(SUBLEVEL)\" >> .ver
	@echo \#define TOOLCHAIN_VERSION_CODE `expr $(VERSION) \\* 65536 + $(PATCHLEVEL) \\* 256 + $(SUBLEVEL)` >> .ver
	@echo \#define USER_DIST_VERSION \"$(USER_DIST_VERSION)\" >> .ver
	@mv -f .ver $@

version.o: version.c compile.h

stamp.o: stamp.c compile.h version.h

