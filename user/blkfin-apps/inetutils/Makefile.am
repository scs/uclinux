AUTOMAKE_OPTIONS = 1.7

EXTRA_DIST = README-alpha paths ChangeLog.0

SUBDIRS = headers libinetutils libtelnet glob \
	inetd telnetd libls ftpd rshd rlogind uucpd rexecd syslogd tftpd \
	talkd telnet ftp rsh rcp rlogin tftp logger gwhois talk \
	libicmp ping doc

DISTCLEANFILES = pathdefs.make paths.defs include/*.h include/*/*.h \
	include/stamp-h

release:
	$(MAKE) dist distdir=$(PACKAGE)-`date +"%Y%m%d"`
