TOPDIR := ..
export TOPDIR

pdf:	openobex.pdf
ps:	openobex.ps
html:	openobex

openobex.sgml: openobex.tmpl docproc ../src/obex.c
	$(top_srcdir)/doc/docproc <$< >$@

clean:
	-$(RM) openobex.sgml openobex.dvi openobex.ps openobex.tex openobex.log openobex.aux openobex.pdf
	-$(RM) -rf openobex
	
%.ps : %.sgml
	@(which db2ps > /dev/null 2>&1) || \
	 (echo "*** You need to install DocBook stylesheets ***"; \
	  exit 1)
	db2ps $<

%.pdf : %.sgml
	@(which db2pdf > /dev/null 2>&1) || \
	 (echo "*** You need to install DocBook stylesheets ***"; \
	  exit 1)
	db2pdf $<

%:	%.sgml
	@(which db2html > /dev/null 2>&1) || \
	 (echo "*** You need to install DocBook stylesheets ***"; \
	  exit 1)
	-$(RM) -r $@
	db2html $<
	if [ ! -z "$(JPG-$@)" ]; then cp $(JPG-$@) $@; fi


EXTRA_DIST = \
	kernel-doc \
	openobex.tmpl

docproc_SOURCES = docproc.c
noinst_PROGRAMS = docproc
