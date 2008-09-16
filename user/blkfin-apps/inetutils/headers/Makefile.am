EXTRA_DIST = crypt.h err.h getopt.h obstack.h osockaddr.h paths.h poll.h \
        syslog-int.h tftpsubs.h confpaths.h.in stamp-h.in

dist-hook:
	mkdir $(distdir)/arpa
	cp -p $(srcdir)/arpa/ftp.h $(srcdir)/arpa/telnet.h \
		$(srcdir)/arpa/tftp.h $(distdir)/arpa
	mkdir $(distdir)/protocols
	cp -p $(srcdir)/protocols/talkd.h $(distdir)/protocols/talkd.h
