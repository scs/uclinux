from ipodlib import *
import sys

paths = IPod.Discover()
if len(paths):
	path = paths[0]
	print "Opening iPod at %s" % path
	ipod = IPod(path);
	args = sys.argv[1:]
	for arg in args:
		for i in xrange(ipod.PlaylistCount()):
			playlist = ipod.PlaylistByIndex(i)
			if playlist:
				if playlist.GetText(IPOD_TITLE)==arg:
					playlist.Remove()
					print "Removed playlist %s" % arg
					break;
	ipod.Flush()
else:
	print "No iPods found"
