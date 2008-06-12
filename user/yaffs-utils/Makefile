# version is based on current cvs snapshot from here (since releases are not
# made by the yaffs guys):
# http://www.aleph1.co.uk/cgi-bin/viewcvs.cgi/yaffs2.tar.gz?view=tar
VER = 20080611

all:
	$(MAKE) -C $(VER)/utils
	ln -sf $(VER)/utils/mkyaffsimage mkfs.yaffs
	ln -sf $(VER)/utils/mkyaffs2image mkfs.yaffs2

clean:
	$(MAKE) -C $(VER)/utils clean
	rm -f mkfs.yaffs mkfs.yaffs2

romfs:

.PHONY: all clean romfs
