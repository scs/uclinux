
EXEC = boa
OBJS = alias.o boa.o buffer.o cgi.o cgi_header.o config.o escape.o \
       get.o hash.o ip.o log.o mmap_cache.o pipe.o queue.o range.o \
       read.o request.o response.o signals.o util.o sublog.o select.o timestamp.o
       

FLTFLAGS += -s 65536

EXTRALIBS = $(LIBCRYPT)

ifdef CONFIG_PROP_BOA_SECURITY_COUNT
CFLAGS += -DSECURITY_COUNTS
endif

ifdef CONFIG_USER_BOA_WITH_SSL
CFLAGS += -DSERVER_SSL=1
EXTRALIBS += $(LIBSSL) $(LIBCRYPTO)
endif

ifdef CONFIG_USER_TINYLOGIN_SHADOWPASSWDS
CFLAGS += -DSHADOW_AUTH
endif

ifdef CONFIG_USER_FLATFSD_FLATFSD
CFLAGS += -DCONFIG_USER_FLATFSD_FLATFSD=1
endif

ifdef CONFIG_USER_OLD_PASSWORDS
CFLAGS += -DOLD_CONFIG_PASSWORDS
endif

ifdef CONFIG_PROP_AMAZON_BOA_LDAP
CFLAGS += -DLDAP_HACK
EXTRALIBS += -lldap -llber -static $(LIBSNAPGEAR) $(LIBCONFIG)
endif

ifdef CONFIG_USER_BOA_EMERG
FLAGS += -DSYSLOGS_AT_EMERG
endif

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(EXTRALIBS) $(LDLIBS)

romfs:
	 $(ROMFSINST) /bin/$(EXEC)

clean:
	-rm -f $(EXEC) *.gdb *.elf *.o


