#
# ipod.py
#
# Duane Maxwell
# (c) Copyright Linspire. Inc, 2005
#
# This is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#

import ipodlib

""" This module provides a fairly high-level Python API for accessing the iPod
"""
class IPod:
	""" This class encapsulates an iPod
	"""

	def __init__(self,path):
		""" Constructor, takes an absolute path to the mount point of the iPod
		"""
		self.path = path
		self.ipod = ipodlib.IPod(path)
	
	def __str__(self):
		return "<IPod at %s>" % self.path

	def isIPod(self):
		return True

	def _version(self):
		return self.ipod.Version()
	version = property(_version)

	def flush(self):
		""" Write the iPod databases if necessary """
		self.ipod.Flush()
	
	def diskUsage(self):
		""" Return a tuple of the total and free space on the iPod, in Kb """
		return self.ipod.DiskUsage()
	
	def _trackCount(self):
		return self.ipod.TrackCount()
	trackCount = property(_trackCount)
	
	def trackAt(self,index):
		""" Return the track at the given index """
		return IPodTrack(self.ipod.TrackByIndex(index))
	
	def trackForID(self,id):
		""" Return the track with the given track ID, None if not present """
		return IPodTrack(self.ipod.TrackByTrackID(id))

	def _tracks(self):
		def track_iter(self):
			for i in xrange(self.trackCount):
				yield self.trackAt(i)
		return track_iter(self)
	tracks = property(_tracks)
	
	def _playlistCount(self):
		return self.ipod.PlaylistCount()
	playlistCount = property(_playlistCount)

	def playlistAt(self,index):
		""" Return the playlist at the given index """
		return IPodPlaylist(self.ipod.PlaylistByIndex(index))

	def _playlists(self):
		def playlist_iter(self):
			for i in xrange(self.playlistCount):
				yield self.playlistAt(i)
		return playlist_iter(self)
	playlists = property(_playlists)
	
	def _eqPresetCount(self):
		return self.ipod.EQPresetCount()
	eqPresetCount = property(_eqPresetCount)
	
	def eqPresetAt(self,index):
		""" return the EQ Preset at the given index """
		return IPodEQPreset(self.ipod.EQPresetByIndex(index))
	
	def _eqPresets(self):
		def eqPreset_iter(self):
			for i in xrange(self.eqPresetCount):
				yield self.eqPresetAt(i)
		return eqPreset_iter(self)
	eqPresets = property(_eqPresets)
		
	def paths():
		""" Return an array of path names for mounted iPods """
		return ipodlib.IPod.Discover()
	paths = staticmethod(paths)

class IPodTrack:
	_string_attributes = {
		'title':ipodlib.IPOD_TITLE,
		'location':ipodlib.IPOD_LOCATION,
		'album':ipodlib.IPOD_ALBUM,
		'artist':ipodlib.IPOD_ARTIST,
		'genre':ipodlib.IPOD_GENRE,
		'fileType':ipodlib.IPOD_FILETYPE,
		'eqSetting':ipodlib.IPOD_EQSETTING,
		'comment':ipodlib.IPOD_COMMENT,
		'composer':ipodlib.IPOD_COMPOSER,
		'grouping':ipodlib.IPOD_GROUPING,
		'description':ipodlib.IPOD_DESCRIPTION,
		'enclosureURL':ipodlib.IPOD_ENCLOSUREURL,
		'rssURL':ipodlib.IPOD_RSSURL,
		'chapter':ipodlib.IPOD_CHAPTER,
		'subtitle':ipodlib.IPOD_SUBTITLE
	}
	_number_attributes = {
		'id':ipodlib.IPOD_TRACK_ID,
		'rating':ipodlib.IPOD_TRACK_RATING,
		'size':ipodlib.IPOD_TRACK_RATING,
		'duration':ipodlib.IPOD_TRACK_DURATION,
		'trackNumber':ipodlib.IPOD_TRACK_TRACK_NUMBER,
		'trackCount':ipodlib.IPOD_TRACK_TRACK_COUNT,
		'year':ipodlib.IPOD_TRACK_YEAR,
		'bitRate':ipodlib.IPOD_TRACK_BIT_RATE,
		'sampleRate':ipodlib.IPOD_TRACK_SAMPLE_RATE,
		'volume':ipodlib.IPOD_TRACK_VOLUME,
		'playCount':ipodlib.IPOD_TRACK_PLAY_COUNT,
		'discNumber': ipodlib.IPOD_TRACK_DISC_NUMBER,
		'discCount': ipodlib.IPOD_TRACK_DISC_COUNT,
		'vbr':ipodlib.IPOD_TRACK_VBR
	}
	_boolean_attributes = {
		'visible':ipodlib.IPOD_TRACK_VISIBLE,
		'compilation':ipodlib.IPOD_TRACK_COMPILATION
	}
	_date_attributes = {
		'lastPlayed':ipodlib.IPOD_TRACK_LAST_PLAYED_TIME_NATIVE,
		'addedTime': ipodlib.IPOD_TRACK_ADDED_TIME_NATIVE,
		'lastModified': ipodlib.IPOD_TRACK_LAST_MODIFICATION_TIME_NATIVE
	}
	def __init__(self,item):
		try:
			if item.isIPod():
				self.track = ipodlib.IPodTrack(item.ipod)
			else:
				self.track = item
		except:
			self.track = item
	
	def __str__(self):
		return "<IPodTrack %s>" % self.track

	def __nonzero__(self): return True
	
	def __getattr__(self,key):
		try:
			tag = IPodTrack._string_attributes[key]
			return unicode(self.track.GetText(tag),'utf-8')
		except: pass
		try:
			tag = IPodTrack._number_attributes[key]
			return self.track.GetAttribute(tag)
		except: pass
		try:
			tag = IPodTrack._boolean_attributes[key]
			return self.track.GetAttribute(tag)!=0
		except: pass
		try:
			tag = IPodTrack._date_attributes[key]
			return self.track.GetAttribute(tag)
		except: pass
		return self.__dict__[key]

	def __setattr__(self,key,value):
		try:
			tag = IPodTrack._string_attributes[key]
			try: value = value.encode('utf-8')
			except: pass
			self.track.SetText(tag,value)
			return
		except: pass
		try:
			tag = IPodTrack._number_attributes[key]
			self.track.SetAttribute(tag,value)
			return
		except: pass
		try:
			tag = IPodTrack._boolean_attributes[key]
			if value: value=1
			else: value=0
			self.track.SetAttribute(tag,value)
			return
		except: pass
		try:
			tag = IPodTrack._date_attributes[key]
			self.track.SetAttribute(tag,value)
			return
		except: pass
		self.__dict__[key] = value

	def remove(self):
		""" remove this track from the iPod """
		self.track.Remove()
	
	def upload(self,path,callback,data):
		""" Upload this file to the iPod """
		self.track.Upload(path,callback,data)

	def download(self,path,callback,data):
		""" Download this file from the iPod """
		self.track.Download(path,callback,data)

class IPodPlaylist:
	def __init__(self,item):
		try:
			if item.isIPod():
				self.playlist = ipodlib.IPodPlaylist(item.ipod)
		except:
			self.playlist = item

	_string_attributes = {
		'name':ipodlib.IPOD_TITLE
	}
	_number_attributes = {
		'idlo':ipodlib.IPOD_PLAYLIST_PLAYLIST_ID_LO,
		'idhi':ipodlib.IPOD_PLAYLIST_PLAYLIST_ID_HI,
		'sortOrder':ipodlib.IPOD_PLAYLIST_SORT_ORDER
	}
	_boolean_attributes = {
		'hidden':ipodlib.IPOD_PLAYLIST_HIDDEN
	}
	_date_attributes = {
		'timeStamp':ipodlib.IPOD_PLAYLIST_TIMESTAMP_NATIVE
	}
	
	def isIPodPlaylist(self):
		return True

	def __str__(self):
		return "<IPodPlaylist %s>" % self.playlist

	def __nonzero__(self): return True
	
	def __getattr__(self,key):
		try:
			tag = IPodPlaylist._string_attributes[key]
			return unicode(self.playlist.GetText(tag),'utf-8')
		except: pass
		try:
			tag = IPodPlaylist._number_attributes[key]
			return self.playlist.GetAttribute(tag)
		except: pass
		try:
			tag = IPodPlaylist._boolean_attributes[key]
			return self.playlist.GetAttribute(tag)!=0
		except: pass
		try:
			tag = IPodPlaylist._date_attributes[key]
			return self.playlist.GetAttribute(tag)
		except: pass
		return self.__dict__[key]

	def __setattr__(self,key,value):
		try:
			tag = IPodPlaylist._string_attributes[key]
			try: value = value.encode('utf-8')
			except: pass
			self.playlist.SetText(tag,value)
			return
		except: pass
		try:
			tag = IPodPlaylist._number_attributes[key]
			self.playlist.SetAttribute(tag,value)
			return
		except: pass
		try:
			tag = IPodPlaylist._boolean_attributes[key]
			self.playlist.SetAttribute(tag,{True:1,False:0}[value])
			return
		except: pass
		try:
			tag = IPodPlaylist._date_attributes[key]
			self.playlist.SetAttribute(tag,value)
			return
		except: pass
		self.__dict__[key] = value

	def _trackItemCount(self):
		return self.playlist.TrackItemCount()
	trackItemCount = property(_trackItemCount)
	
	def trackItemAt(self,index):
		""" Returns the track item at the given index """
		return IPodTrackItem(self.playlist.TrackItemByIndex(index))
	
	def trackItemForID(self,id):
		""" Returns the track item for the given track ID """
		for trackItem in self.trackItems:
			if trackItem.id==id:
				return trackItem
		return None

	def removeTrackItemForID(self,id):
		""" Removes the track item for the given track ID from the playlist """
		trackItem = self.trackItemForID(id)
		if trackItem:
			trackItem.remove()

	def _trackItems(self):
		def track_item_iter(self):
			for i in xrange(self.trackItemCount):
				yield self.trackItemAt(i)
		return track_item_iter(self)
	trackItems = property(_trackItems)
	
	def _get_id(self):
		return (self.idhi<<32)+self.idlo
	def _set_id(self,id):
		self.idhi = id>>32
		t = 0xffffffff
		self.idlo = id & t
	id = property(_get_id,_set_id)

	def remove(self):
		""" Remove the playlist from the iPod """
		self.playlist.Remove()

class IPodTrackItem:
	def __init__(self,item):
		try:
			if item.isIPodPlaylist():
				self.trackItem = ipodlib.IPodTrackItem(item.playlist)
			else:
				self.trackItem = item
		except:
			self.trackItem = item

	_number_attributes = {
		'id':ipodlib.IPOD_TRACK_ITEM_TRACK_ID
	}
	_date_attributes = {
		'timeStamp':ipodlib.IPOD_TRACK_ITEM_TIMESTAMP_NATIVE
	}

	def __str__(self):
		return "<IPodTrackItem %s>" % self.trackItem

	def __nonzero__(self): return True

	def __getattr__(self,key):
		try:
			tag = IPodTrackItem._number_attributes[key]
			return self.trackItem.GetAttribute(tag)
		except: pass
		try:
			tag = IPodTrackItem._date_attributes[key]
			return self.trackItem.GetAttribute(tag)
		except: pass
		return self.__dict__[key]

	def __setattr__(self,key,value):
		try:
			tag = IPodTrackItem._number_attributes[key]
			self.trackItem.SetAttribute(tag,value)
			return
		except: pass
		try:
			tag = IPodTrackItem._date_attributes[key]
			self.trackItem.SetAttribute(tag,value)
			return
		except: pass
		self.__dict__[key] = value
	
	def remove(self):
		""" Remove the track item from the playlist """
		self.trackItem.Remove()

class IPodEQPreset:
	def __init__(self,item):
		try:
			if item.isIPod():
				self.preset = ipodlib.IPodEQPreset(item.ipod)
		except:
			self.preset = item

	_string_attributes = {
		'name':ipodlib.IPOD_TITLE
	}
	_number_attributes = {
		'preamp':ipodlib.IPOD_EQ_PRESET_PREAMP,
	}

	def __str__(self):
		return "<IPodEQPreset %s>" % self.preset

	def __getattr__(self,key):
		try:
			tag = IPodEQPreset._string_attributes[key]
			return unicode(self.preset.GetText(tag),'utf-8')
		except: pass
		try:
			tag = IPodEQPreset._number_attributes[key]
			return self.preset.GetAttribute(tag)
		except: pass
		return self.__dict__[key]

	def __setattr__(self,key,value):
		try:
			tag = IPodEQPreset._string_attributes[key]
			try: value = value.encode('utf-8')
			except: pass
			self.preset.SetText(tag,value)
			return
		except: pass
		try:
			tag = IPodEQPreset._number_attributes[key]
			self.preset.SetAttribute(tag,value)
			return
		except: pass
		self.__dict__[key] = value

	class __band:
		def __init__(self,obj,base,count):
			self.obj = obj
			self.base = base
			self.count = count
		def __getitem__(self,index):
			if index>=0 and index<self.count:
				return self.obj.preset.GetAttribute(self.base+index)
			else: return 0
		def __setitem(self,index,value):
			if index>=0 and index<self.count:
				self.obj.preset.SetAttribute(self.base+index,value)

	def _bandA(self):
		return self.__band(self,ipodlib.IPOD_EQ_PRESET_BAND_A_BASE,10)
	bandA = property(_bandA)
	
	def _bandB(self):
		return self.__band(self,ipodlib.IPOD_EQ_PRESET_BAND_B_BASE,5)
	bandB = property(_bandB)

	def remove(self):
		""" Removes this EQ Preset from the iPod """
		self.playlist.Remove()

if __name__=="__main__":
	paths = IPod.paths()
	if len(paths):
		ipod = IPod(paths[0])
		total,free = ipod.diskUsage()
		print "iPod at %s (total %dK, free %dK)" % (paths[0],total,free)
		for track in ipod.tracks:
			print "  TrackID %d:  %s - %s/%s (%s)" % (track.id,track.title,track.artist,track.album,track.fileType)
		for playlist in ipod.playlists:
			print "Playlist: %s" % playlist.name
			for trackItem in playlist.trackItems:
				print "  TrackID %d: %s" % (trackItem.id,ipod.trackForID(trackItem.id).title)
		for preset in ipod.eqPresets:
			print "Preset: %s preamp %d" % (preset.name,preset.preamp),
			print [preset.bandA[i] for i in xrange(10)],
			print [preset.bandB[i] for i in xrange(5)]
	else:
		print "no iPods found!"
