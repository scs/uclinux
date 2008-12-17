VER = pictureflow-0.1.0

all: $(VER)/pictureflow-qt/Makefile
	$(MAKE) -C $(VER)/pictureflow-qt

$(VER)/pictureflow-qt/Makefile:
	cd $(VER)/pictureflow-qt && $(QMAKE)

clean:
ifneq ($(wildcard $(VER)/pictureflow-qt/Makefile),)
	$(MAKE) -C $(VER)/pictureflow-qt distclean
endif

romfs:
	$(ROMFSINST) -d $(VER)/pictureflow-qt/pictureflow /usr/bin/pictureflow

.PHONY: all clean romfs
