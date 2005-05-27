SUBDIRS = libinetutils

ifdef CONFIG_USER_INETUTILS_RCP
SUBDIRS += rcp
endif

ifdef CONFIG_USER_INETUTILS_RSH
SUBDIRS += rsh
endif

ifdef CONFIG_USER_INETUTILS_RSHD
SUBDIRS += rshd
endif

all romfs:
	for i in $(SUBDIRS) ; do $(MAKE) -C $$i $@ || exit $? ; done

clean:
	for i in $(SUBDIRS) rcp rsh rshd ; do $(MAKE) -C $$i $@ || exit $? ; done

