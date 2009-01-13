# Requirements:
# - set VER to the package directory
# - set URL to the download URL
#
# TODO:
# - should make file format more dynamic ... not require .tar.gz ...

$(DOWNLOADDIR)/$(VER).tar.gz:
	wget -c $(URL) -P $(DOWNLOADDIR)
.PHONY: download
download: $(DOWNLOADDIR)/$(VER).tar.gz

$(VER)/.unpacked: $(DOWNLOADDIR)/$(VER).tar.gz
	tar zxf $<
	for p in $$PWD/patches/*.patch ; do ( cd $(VER) && patch -p1 < $$p ) || exit $$? ; done
	touch $(VER)/.unpacked
