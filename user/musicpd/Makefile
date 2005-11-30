all:
	$(MAKE) -C mpd
	$(MAKE) -C mpc
clean:
	$(MAKE) -C mpd clean
	$(MAKE) -C mpc clean
romfs:
	$(MAKE) -C mpd romfs
	$(MAKE) -C mpc romfs
	$(ROMFSINST) /etc/mpd.conf
