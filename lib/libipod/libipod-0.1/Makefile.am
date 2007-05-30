EXTRA_DIST = reconf python Makefile.cleanup Doxyfile docs
SUBDIRS = src examples include

libtool: @LIBTOOL_DEPS@
	cd $(srcdir) && $(SHELL) ./config.status --recheck
