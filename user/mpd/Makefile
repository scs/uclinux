VER = mpd-0.10.0

all: $(VER)/Makefile
	$(MAKE) -C $(VER)

clean:
	$(MAKE) -C $(VER) clean

romfs:
	$(MAKE) -C $(VER) romfs
	$(ROMFSINST) /etc/mpd.conf

.PHONY: all clean romfs
