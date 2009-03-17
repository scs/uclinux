HTML_DOCS=api
PDF_DOCS= native-api.pdf nucleus-api.pdf posix-api.pdf rtdm-api.pdf

EXTRA_DIST = \
	Doxyfile.in Doxyfile-common.in Doxyfile-native.in Doxyfile-nucleus.in \
	Doxyfile-posix.in Doxyfile-rtdm.in

if !CONFIG_XENO_DOC_DOX
HTML_DOCSDIR = $(srcdir)/../generated/html/
PDF_DOCSDIR = $(srcdir)/../generated/pdf/
else
HTML_DOCSDIR = ./
PDF_DOCSDIR = ./

# Doxygen documentation
api: doxygen-api

all-local: $(HTML_DOCS) $(PDF_DOCS)

doxygen-api: Doxyfile
	$(DOXYGEN) $(DOXYDOC_OPTS)

%-api.pdf: FORCE
	$(MAKE) Doxyfile-$*
	$(DOXYGEN) $(DOXYDOC_OPTS) Doxyfile-$*
	$(MAKE) -C latex-$* refman.pdf
	mv latex-$*/refman.pdf $@

distclean-local:
	for dir in $(HTML_DOCS) latex-*; do \
	    if test -d $$dir ; then $(RM) -R $$dir ; fi ; \
	done

.PHONY: doxygen-api FORCE

.DELETE_ON_ERROR:

endif

include $(top_srcdir)/doc/install-dist.rules

install-data-local: install-docs-local

dist-hook: dist-docs-hook

uninstall-local: uninstall-docs
