from ipodlib import *
import sys,os,os.path

paths = IPod.Discover()
if len(paths):
	path = paths[0]
	print "Opening iPod at",path
	ipod = IPod(path)
	args = sys.argv[1:]
	for arg in args:
		if os.path.exists(arg):
			(root,ext) = os.path.splitext(arg)
			if ext in ['.mp3','.m4a','.wav']:
				track = IPodTrack(ipod,arg)
				if track:
					print "TrackID %d: '%s'" % (track.GetAttribute(IPOD_TRACK_ID),track.GetText(IPOD_TITLE))
				else:
					print "Problem adding track from file '%s'" % arg
			else:
				print "Skipping",arg
	ipod.Flush()
else:
	print "No iPods found"
	
