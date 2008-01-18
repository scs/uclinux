/*
 * ipod_constants.h
 *
 * Duane Maxwell
 * (c) 2005 by Linspire Inc
 *
 * This library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTIBILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 */

#ifndef __IPOD_CONSTANTS_H__
#define __IPOD_CONSTANTS_H__

#ifdef __cplusplus
extern "C" {
#endif

/** \file ipod_constants.h
 *  \brief Various constants and selectors used to access attributes
 */

/** \brief Offsets between native and iPod epochs
 *
 * The iPod uses the Macintosh OS 9 epoch, which is based on midnight, Jan 1, 1904
 */
enum ipod_time_offset_enum {
	IPOD_MAC_EPOCH_OFFSET  = 2082844800L
};

/** \brief Selectors for accessing text attributes
 *
 * These selectors are use for ipod_XXX_get_text() and ipod_XXX_set_text() functions
 * All of the tags are used by tracks, and playlists and presets will also use the IPOD_TITLE
 * attribute.
 *
 * Four of the attributes are not actually text attributes, but are more complicated structures.
 * They will be supported in future versions of the library.
 */
enum ipod_text_attribute_enum {
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

/** \brief Selectors for accessing number attributes on audio tracks
 *
 * These selectors are used for ipod_track_get_attribute() and ipod_track_set_attribute() calls
 */
enum ipod_track_attribute_enum {
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

/** \brief Selectors for accessing number attributes on playlists
 *
 * These selectors are used for ipod_playlist_get_attribute() and ipod_playlist_set_attribute() calls
 */
enum ipod_playlist_attribute_enum {
	IPOD_PLAYLIST_HIDDEN = 1000,
	IPOD_PLAYLIST_TIMESTAMP = 1001,
	IPOD_PLAYLIST_PLAYLIST_ID_LO = 1002,
	IPOD_PLAYLIST_PLAYLIST_ID_HI = 1003,
	IPOD_PLAYLIST_SORT_ORDER = 1004,
	
	IPOD_PLAYLIST_TIMESTAMP_NATIVE = 1100
};

/** \brief Selectors for accessing number attributes on track items in playlists
 *
 * These selectors are used for ipod_track_item_get_attribute() and ipod_track_item_set_attribute() calls
 */
enum ipod_track_item_attribute_enum {
	IPOD_TRACK_ITEM_PODCAST_GROUPING_FLAG = 4000,
	IPOD_TRACK_ITEM_GROUP_ID = 4001,
	IPOD_TRACK_ITEM_TRACK_ID = 4002,
	IPOD_TRACK_ITEM_TIMESTAMP = 4003,
	IPOD_TRACK_ITEM_PODCAST_GROUPING_REFERENCE = 4004,
	
	IPOD_TRACK_ITEM_TIMESTAMP_NATIVE = 4100
};

/** \brief Selectors for accessing number attributes in EQ presets
 *
 * These selectors are used for ipod_eq_preset_get_attribute() and ipod_eq_preset_set_attribute() calls
 */
enum ipod_eq_preset_attribute_enum {
	IPOD_EQ_PRESET_PREAMP = 5000,
	IPOD_EQ_PRESET_BAND_A_BASE = 5001,
	IPOD_EQ_PRESET_BAND_B_BASE = 5011
};

/** \brief Versions of the iPod music database supported
 *
 * These values are returned by the ipod_version() call
 */
enum ipod_version_enum {
	IPOD_VERSION_ANY = 0,

	IPOD_VERSION4_2 = 9,
	IPOD_VERSION4_5 = 10,
	IPOD_VERSION4_7 = 11,
	IPOD_VERSION4_8 = 12,
	IPOD_VERSION4_9 = 13,
	IPOD_VERSION5_0 = 14,
	IPOD_VERSION6_0 = 15
};

/** \brief Track sort orders in playlists
 *
 * These are values for the playlist IPOD_PLAYLIST_SORT_ORDER attribute
 */
enum ipod_sort_order_enum {
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


#ifdef __cplusplus
};
#endif

#endif
