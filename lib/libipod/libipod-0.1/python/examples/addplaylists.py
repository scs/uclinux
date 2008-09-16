from ipodlib import *
import sys

paths = IPod.Discover()
if len(paths):
	path = paths[0]
	print "Opening iPod at %s" % path
	ipod = IPod(path);
	args = sys.argv[1:]
	for arg in args:
		playlist = IPodPlaylist(ipod)
		if playlist:
			playlist.SetText(IPOD_TITLE,arg)
			print "Playlist ID %d: '%s'" % (playlist.GetAttribute(IPOD_PLAYLIST_PLAYLIST_ID_LO),playlist.GetText(IPOD_TITLE))
	ipod.Flush()
else:
	print "No iPods found"
