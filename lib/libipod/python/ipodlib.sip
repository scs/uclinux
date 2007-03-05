/*
#
# ipod.sip
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
*/

%Module ipodlib

%ModuleCode
#include "ipod_cpp.cpp"
%End

enum {
	IPOD_TITLE = 1,
	IPOD_LOCATION = 2,
	IPOD_ALBUM = 3,
	IPOD_ARTIST = 4,
	IPOD_GENRE = 5,
	IPOD_FILETYPE = 6,
	IPOD_EQSETTING = 7,
	IPOD_COMMENT = 8,
	IPOD_CATEGORY = 9,
	IPOD_COMPOSER = 12,
	IPOD_GROUPING = 13,
	IPOD_DESCRIPTION = 14, 
	IPOD_ENCLOSUREURL = 15,
	IPOD_RSSURL = 16,
	IPOD_CHAPTER = 17,
	IPOD_SUBTITLE = 18,
	IPOD_SMARTPLAYLIST_PREF = 50,
	IPOD_SMARTPLAYLIST_DATA = 51,
	IPOD_LIBRARYPLAYLIST_INDEX = 52,
	IPOD_PLAYLIST_SETTINGS = 100,

	IPOD_FULL_PATH	= 3000
};

enum {
	IPOD_TRACK_ID = 2000,
	IPOD_TRACK_VISIBLE = 2001,
	IPOD_TRACK_FILETYPE = 2002,
	IPOD_TRACK_VBR = 2003,
	IPOD_TRACK_COMPILATION = 2004,
	IPOD_TRACK_RATING = 2005,
	IPOD_TRACK_LAST_PLAYED_TIME = 2006,
	IPOD_TRACK_SIZE = 2007,
	IPOD_TRACK_DURATION = 2008,
	IPOD_TRACK_TRACK_NUMBER = 2009,
	IPOD_TRACK_TRACK_COUNT = 2010,
	IPOD_TRACK_YEAR = 2011,
	IPOD_TRACK_BIT_RATE = 2012,
	IPOD_TRACK_SAMPLE_RATE = 2013,
	IPOD_TRACK_VOLUME = 2014,
	IPOD_TRACK_START_TIME = 2015,
	IPOD_TRACK_END_TIME = 2016,
	IPOD_TRACK_SOUND_CHECK = 2017,
	IPOD_TRACK_PLAY_COUNT = 2018,
	IPOD_TRACK_ADDED_TIME = 2019,
	IPOD_TRACK_DISC_NUMBER = 2020,
	IPOD_TRACK_DISC_COUNT = 2021,
	IPOD_TRACK_USER_ID = 2022,
	IPOD_TRACK_LAST_MODIFICATION_TIME = 2023,
	IPOD_TRACK_BOOKMARK_TIME = 2024,
	IPOD_TRACK_DBIDLO = 2025,
	IPOD_TRACK_DBIDHI = 2026,
	IPOD_TRACK_CHECKED = 2027,
	IPOD_TRACK_APPLICATION_RATING = 2028,
	IPOD_TRACK_BEATS_PER_MINUTE = 2029,
	IPOD_TRACK_ARTWORK_COUNT = 2030,
	IPOD_TRACK_ARTWORK_SIZE = 2031,
	IPOD_TRACK_DBID2LO = 2032,
	IPOD_TRACK_DBID2HI = 2033,
	IPOD_TRACK_SAMPLE_COUNT = 2034,

	IPOD_TRACK_LAST_PLAYED_TIME_NATIVE = 2100,
	IPOD_TRACK_ADDED_TIME_NATIVE = 2101,
	IPOD_TRACK_LAST_MODIFICATION_TIME_NATIVE = 2102
};

enum {
	IPOD_PLAYLIST_HIDDEN = 1000,
	IPOD_PLAYLIST_TIMESTAMP = 1001,
	IPOD_PLAYLIST_PLAYLIST_ID_LO = 1002,
	IPOD_PLAYLIST_PLAYLIST_ID_HI = 1003,
	IPOD_PLAYLIST_SORT_ORDER = 1004,
	
	IPOD_PLAYLIST_TIMESTAMP_NATIVE = 1100
};

enum {
	IPOD_TRACK_ITEM_PODCAST_GROUPING_FLAG = 4000,
	IPOD_TRACK_ITEM_GROUP_ID = 4001,
	IPOD_TRACK_ITEM_TRACK_ID = 4002,
	IPOD_TRACK_ITEM_TIMESTAMP = 4003,
	IPOD_TRACK_ITEM_PODCAST_GROUPING_REFERENCE = 4004,
	
	IPOD_TRACK_ITEM_TIMESTAMP_NATIVE = 4100
};

enum {
	IPOD_VERSION_ANY = 0,

	IPOD_VERSION4_2 = 9,
	IPOD_VERSION4_5 = 10,
	IPOD_VERSION4_7 = 11,
	IPOD_VERSION4_8 = 12,
	IPOD_VERSION4_9 = 13,
	IPOD_VERSION5_0 = 14,
	IPOD_VERSION6_0 = 15
};

enum {
	IPOD_SORT_ORDER_MANUAL = 1,
	IPOD_SORT_ORDER_TITLE = 3,
	IPOD_SORT_ORDER_ALBUM = 4,
	IPOD_SORT_ORDER_ARTIST = 5,
	IPOD_SORT_ORDER_BITRATE = 6,
	IPOD_SORT_ORDER_GENRE = 7,
	IPOD_SORT_ORDER_KIND = 8,
	IPOD_SORT_ORDER_DATEMODIFIED = 9,
	IPOD_SORT_ORDER_TRACKNUM = 10,
	IPOD_SORT_ORDER_SIZE = 11,
	IPOD_SORT_ORDER_DURATION = 12,
	IPOD_SORT_ORDER_YEAR = 13,
	IPOD_SORT_ORDER_SAMPLERATE = 14,
	IPOD_SORT_ORDER_COMMENT = 15,
	IPOD_SORT_ORDER_DATEADDED = 16,
	IPOD_SORT_ORDER_EQUALIZER = 17,
	IPOD_SORT_ORDER_COMPOSER = 18,
	IPOD_SORT_ORDER_PLAYCOUNT = 20,
	IPOD_SORT_ORDER_LASTPLAYED = 21,
	IPOD_SORT_ORDER_DISCNUM = 22,
	IPOD_SORT_ORDER_RATING = 23,
	IPOD_SORT_ORDER_RELEASEDATE = 24,
	IPOD_SORT_ORDER_BPM = 25,
	IPOD_SORT_ORDER_GROUPING = 26,
	IPOD_SORT_ORDER_CATEGORY = 27,
	IPOD_SORT_ORDER_DESCRIPTION = 28
};

enum {
	IPOD_EQ_PRESET_PREAMP = 5000,
	IPOD_EQ_PRESET_BAND_A_BASE = 5001,
	IPOD_EQ_PRESET_BAND_B_BASE = 5011
};

class IPod {
%TypeHeaderCode
#include <ipod/ipod_cpp.h>
#include <ipod/ipod_constants.h>
%End
public:
	IPod(const char *);
	~IPod();
	
	void Flush();
	unsigned long Version();
	void DiskUsage(unsigned long */Out/, unsigned long */Out/);
%MethodCode
	uint64_t total,free;
	sipCpp->DiskUsage(&total,&free);
	a0 = (unsigned long)(total>>10);
	a1 = (unsigned long)(free>>10);
%End
	
	unsigned long TrackCount();
	IPodTrack TrackByIndex(unsigned long );
	IPodTrack TrackByTrackID(unsigned long );
	
	unsigned long PlaylistCount();
	IPodPlaylist PlaylistByIndex(unsigned long );
	
	unsigned long EQPresetCount();
	IPodEQPreset EQPresetByIndex(unsigned long );
	
	static SIP_PYLIST Discover();
%MethodCode
		std::string *paths;
		int count = IPod::Discover(&paths);
		PyObject *l;
		if ((l = PyList_New(count))==NULL) {
			sipRes = NULL;
		} else {
			for (int i=0;i<count;i++) {
				PyObject *item = sipBuildResult(0,"s",paths[i].c_str());
				if (PyList_SetItem(l,i,item)<0) {
					Py_DECREF(l);
					l = NULL;
					break;
				}
			}
			sipRes = l;
		}
%End
};

class IPodTrack {
%TypeHeaderCode
#include <ipod/ipod_cpp.h>
#include <ipod/ipod_constants.h>
%End
%TypeCode
typedef struct ipod_transfer_struct {
	PyObject *function;
	PyObject *param;
};

void ipod_transfer_callback(uint64_t sent, uint64_t total, void *data) {
	struct ipod_transfer_struct *s = (ipod_transfer_struct *)data;
	int retValue = 0;
	PyObject *p1 = PyLong_FromUnsignedLongLong(sent);
	PyObject *p2 = PyLong_FromUnsignedLongLong(total);
	PyObject *args = Py_BuildValue("(OOO)",p1,p2,s->param);
	PyObject *result = PyEval_CallObject(s->function,args);
	if (result && PyInt_Check(result)) {
		retValue = PyInt_AsLong(result);
	}
	Py_XDECREF(result);
	Py_DECREF(args);
	
}
%End
public:
	IPodTrack(IPod &);
	IPodTrack(IPod &,char *);
	~IPodTrack();
	
	void Remove();
	
	char *GetText(int);
%MethodCode
	std::string s = sipCpp->GetText(a0);
	sipRes = (char *)s.c_str();
%End
	void SetText(int, char *);
	
	bool HasText(int);
	
	unsigned long GetAttribute(int);
	void SetAttribute(int , unsigned long);
	
	void Upload(char *, SIP_PYCALLABLE,SIP_PYOBJECT);
%MethodCode
		struct ipod_transfer_struct s = {a1,a2};
		sipCpp->Upload(a0,ipod_transfer_callback,&s);
%End
	void Download(char *, SIP_PYCALLABLE,SIP_PYOBJECT);
%MethodCode
		struct ipod_transfer_struct s = {a1,a2};
		sipCpp->Download(a0,ipod_transfer_callback,&s);
%End
};

class IPodPlaylist {
%TypeHeaderCode
#include <ipod/ipod_cpp.h>
#include <ipod/ipod_constants.h>
%End
public:
	IPodPlaylist(IPod &);
	~IPodPlaylist();
	
	void Remove();
	
	char *GetText(int);
%MethodCode
	std::string s = sipCpp->GetText(a0);
	sipRes = (char *)s.c_str();
%End
	void SetText(int, char *);
	bool HasText(int);
	
	unsigned long GetAttribute(int );
	void SetAttribute(int , unsigned long );
	
	unsigned long TrackItemCount();
	IPodTrackItem TrackItemByIndex(unsigned long );
};

class IPodTrackItem {
%TypeHeaderCode
#include <ipod/ipod_cpp.h>
#include <ipod/ipod_constants.h>
%End
public:
	IPodTrackItem(IPodPlaylist &);
	~IPodTrackItem();
	
	void Remove();

	unsigned long GetAttribute(int );
	void SetAttribute(int , unsigned long );
};

class IPodEQPreset {
%TypeHeaderCode
#include <ipod/ipod_cpp.h>
#include <ipod/ipod_constants.h>
%End
public:
	IPodEQPreset(IPod &);
	~IPodEQPreset();
	
	void Remove();
	
	char *GetText(int);
%MethodCode
	std::string s = sipCpp->GetText(a0);
	sipRes = (char *)s.c_str();
%End
	void SetText(int, char *);
	bool HasText(int);
	
	long GetAttribute(int );
	void SetAttribute(int , long );
};
