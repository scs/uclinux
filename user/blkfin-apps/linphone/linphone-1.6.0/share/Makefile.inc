linphone_manualdir = $(datadir)/gnome/help/linphone/$(HELPLANG)/

linphone_help = \
        $(top_builddir)/share/$(HELPLANG)/manual

if ENABLE_MANUAL
all-local:	$(linphone_help)/index.html
else
all-local:
endif

$(linphone_help)/index.html:
	rm -rf $(linphone_help)
	mkdir  $(linphone_help)
	-db2html --output $(linphone_help) manual.sgml

install-data-local:
			$(mkdir_p) $(DESTDIR)/$(linphone_manualdir)
			-cp -f $(linphone_help)/*.html $(DESTDIR)/$(linphone_manualdir)/.
			-cp -f $(linphone_help)/*.css $(DESTDIR)/$(linphone_manualdir)/.

uninstall-local:
			rm -rf $(linphone_manualdir)


EXTRA_DIST=  manual.lyx manual.sgml
