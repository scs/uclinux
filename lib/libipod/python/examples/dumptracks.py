from ipodlib import *

ipodPaths = IPod.Discover()
for ipodPath in ipodPaths:
	ipod = IPod(ipodPath)
	(total,free) = ipod.DiskUsage()
	print "iPod at %s (%d tracks, %d playlists, %dKB total, %dKB free)" % (ipodPath,ipod.TrackCount(),ipod.PlaylistCount(),total,free)
	for trackIndex in xrange(ipod.TrackCount()):
		track = ipod.TrackByIndex(trackIndex)
		trackID = track.GetAttribute(IPOD_TRACK_ID)
		print "  Index %d TrackID %d '%s' %s/%s" % (trackIndex,trackID,track.GetText(IPOD_TITLE),track.GetText(IPOD_ARTIST),track.GetText(IPOD_ALBUM))
	for playlistIndex in xrange(ipod.PlaylistCount()):
		playlist = ipod.PlaylistByIndex(playlistIndex)
		print "\nPlaylist: %d: %s" % (playlistIndex,playlist.GetText(IPOD_TITLE))
		for trackItemIndex in xrange(playlist.TrackItemCount()):
			trackItem = playlist.TrackItemByIndex(trackItemIndex)
			trackID = trackItem.GetAttribute(IPOD_TRACK_ITEM_TRACK_ID)
			track = ipod.TrackByTrackID(trackID)
			print "   Index %d TrackID %d '%s'" % (trackItemIndex,trackID,track.GetText(IPOD_TITLE))
