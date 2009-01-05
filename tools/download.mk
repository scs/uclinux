# Requirements:
# - set VER to the package directory
# - set URL to the download URL

$(DOWNLOADDIR)/$(VER).tar.gz:
	wget -c $(URL) -P $(DOWNLOADDIR)
.PHONY: download
download: $(DOWNLOADDIR)/$(VER).tar.gz

$(VER)/.unpacked: $(DOWNLOADDIR)/$(VER).tar.gz
	tar xf $<
	for p in $$PWD/patches/*.patch ; do ( cd $(VER) && patch -p1 < $$p ) || exit $$? ; done
	touch $(VER)/.unpacked
