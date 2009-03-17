SUBDIRS=docbook doxygen man txt

GENERATE_DOC=$(top_srcdir)/scripts/maint/generate-doc

generate-doc:
	@if test \! -e $(GENERATE_DOC) -o \! -e $(srcdir)/.svn ; then \
		echo "$@ may only be run from a SVN working copy." ; \
	else \
		srcdir=$(srcdir) $(GENERATE_DOC) ; \
	fi

dist-hook:
	find $(distdir) -name .svn -depth -exec rm -fr \{\} \;
