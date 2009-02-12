bin_PROGRAMS = gcic

gcic_SOURCES = gcic.cc

gcic_LDADD = \
	../vmutils/libmvmutils.la \
	@MVM_LDADD@ \
	-lm

INCLUDES = \
	-D__XENO_SIM__ \
	-DMVM_GCC_VERSION=\"$(GCCVER)\" \
	-I$(srcdir)/..

GCCTOP=$(shell basename @MVM_GCC_TARBALL@ | sed -e 's,^\(.*\)\.tar.*,\1,')
GCCVER=$(shell basename @MVM_GCC_TARBALL@ | sed -e 's,gcc-\(.*\)\.tar.*,\1,g')
GCCDEP=$(shell test -r $(libexecdir)/gcic/.gcic-installed || echo "$(libexecdir)/gcic/.gcic-installed")

all-local: $(GCCDEP)

$(GCCTOP)/.gcic-untarred: @MVM_GCC_TARBALL@
	@echo "Extracting @MVM_GCC_TARBALL@"
	@case "`basename @MVM_GCC_TARBALL@ | sed -e 's,^.*\.tar\(.*\),\1,'`" in \
	.gz) gzip -d < @MVM_GCC_TARBALL@ | tar xpf - ;; \
	.bz2) bzip2 -d < @MVM_GCC_TARBALL@ | tar xpf - ;; \
	*) tar xpf @MVM_GCC_TARBALL@ ;; \
	esac && touch $@ || $(RM) -Rf $(GCCTOP)

$(GCCTOP)/.gcic-patched: $(GCCTOP)/.gcic-untarred
	@( cd $(GCCTOP)* && @MVM_PROG_PATCH@ -p1 ) <\
	$(srcdir)/gcc-$(GCCVER).patch && touch $@

gcc-build/.gcic-configured: $(GCCTOP)/.gcic-patched $(top_builddir)/config.status
	@( $(RM) -Rf gcc-build ; mkdir gcc-build && cd gcc-build && \
	LC_ALL=C CC=$(CC) ../$(GCCTOP)/configure --prefix=$(libexecdir)/gcic \
	--with-gnu-ld --with-gnu-as && cd .. ) && touch $@

gcc-build/.gcic-built: gcc-build/.gcic-configured
	( cd gcc-build && $(MAKE) LANGUAGES="c c++" all \
	&& cd .. ) && touch $@

$(libexecdir)/gcic/.gcic-installed: gcc-build/.gcic-built
	test -d $(libexecdir) && chmod u+rw $(libexecdir) || :
	( cd gcc-build && $(MAKE) LANGUAGES="c c++" install \
	&& cd .. ) && touch $@

distclean-local:
	rm -rf -- gcc-build $(GCCTOP)

install-exec-local:
	$(mkinstalldirs) $(libexecdir)/gcic/lib/gcc-lib/$(host_alias)/$(GCCVER)
	cp @MVM_GCCLD@ $(libexecdir)/gcic/lib/gcc-lib/$(host_alias)/$(GCCVER)
	cp @MVM_GCCAS@ $(libexecdir)/gcic/lib/gcc-lib/$(host_alias)/$(GCCVER)

uninstall-local:
	$(RM) $(libexecdir)/gcic/.gcic-installed
	$(RM) -r $(libexecdir)/gcic

EXTRA_DIST = gcc-2.95.3.patch make-patch
