
EXEC = boa
OBJS = alias.o auth.o boa.o cgi.o cgi_header.o config.o get.o hash.o \
	globals.o \
	log.o nls.o pipe.o queue.o read.o request.o response.o signals.o \
	timestamp.o util.o

FLTFLAGS += -s 8192

EXTRALIBS = $(LIBCRYPT)

ifeq ($(CONFIG_PRODUCT),AmazonSME550)
CFLAGS += -DCONFIG_AMAZON
endif

ifdef CONFIG_USER_BOA_WITH_SSL
CFLAGS += $(INCSSL) -DSERVER_SSL=1
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
CFLAGS += -DLDAP_HACK $(INCLDAP) $(INCSG)
EXTRALIBS += -lldap -llber -static $(LIBSNAPGEAR)
endif

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(EXTRALIBS) $(LDLIBS)

romfs:
	$(ROMFSINST) /bin/$(EXEC)

clean:
	-rm -f $(EXEC) *.gdb *.elf *.o


