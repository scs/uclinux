/*
 * ipod_cpp.h
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

#ifndef __IPOD_CPP_H__
#define __IPOD_CPP_H__

#include <ipod/ipod.h>
#include <ipod/ipod_file_utils.h>
#include <string>

/** \mainpage libipod - a library for managing the Apple iPod
 *
 * \author Duane Maxwell, Linspire, Inc
 *
 * \section intro Introduction
 *
 * libipod is a lightweight library written in C for the management of the Apple iPod.
 * It includes wrappers for C++ and Python, as well as a number of example programs.
 * libipod is the basis for the iPod support in Lsongs, a GPL music manager/player for Linux
 * published by Linspire, Inc.  You can find more information about Lsongs at http://www.lsongs.com.
 *
 * libipod is licensed under the Lesser GNU Public License (LGPL), which basically means that this
 * the code may be used in either Open or Closed source programs, as long as the source of libipod
 * is made available on request.  For more information on the license, please read the the file
 * "COPYING", which is included with the source distribution, or view the text of the LGPL at
 * http://www.gnu.org/copyleft/lesser.html
 *
 * This project is hosted by Sourceforge, at http://libipod.sourceforge.net
 *
 * We encourage code contributions and assistance from the community on this project.  In particular,
 * we are interested in language bindings in order to make iPod support easy for developers to include
 * in their projects.
 *
 * \section cpp_example A simple C++ example
 *
 * \code
 * #include "ipod/ipod_cpp.h"
 * #include "ipod/ipod_constants.h"
 * #include <iostream>
 * 
 * using namespace std;
 * 
 * int main(int argc,char **argv) {
 * 	string *ipod_paths;
 * 	
 * 	int ipod_count = IPod::Discover(&ipod_paths);
 * 	for (int ipod_index=0;ipod_index<ipod_count;ipod_index++) {
 * 		string path = ipod_paths[ipod_index];
 * 		IPod ipod(path);
 * 		cout << "iPod at " << path << " (" << ipod.TrackCount() << " tracks, " << ipod.PlaylistCount() << " playlists)" << endl;
 * 		for (unsigned long i=0;i<ipod.TrackCount();i++) {
 * 			IPodTrack track = ipod.TrackByIndex(i);
 * 			string title = track.GetText(IPOD_TITLE);
 * 			string artist = track.GetText(IPOD_ARTIST);
 * 			uint32_t trackID = track.GetAttribute(IPOD_TRACK_ID);
 * 			cout << "  Index " << i << " TrackID " << trackID << ": '" << title << "' " << artist << endl;
 * 		}
 * 		for (unsigned long i=0;i<ipod.PlaylistCount();i++) {
 * 			IPodPlaylist playlist = ipod.PlaylistByIndex(i);
 * 			string name = playlist.GetText(IPOD_TITLE);
 * 			cout << endl << "Playlist " << i << ": '" << name << "' (" << playlist.TrackItemCount() << " tracks)" << endl;
 * 			for (unsigned long j=0;j<playlist.TrackItemCount();j++) {
 * 				IPodTrackItem item = playlist.TrackItemByIndex(j);
 * 				uint32_t trackID = item.GetAttribute(IPOD_TRACK_ITEM_TRACK_ID);
 * 				IPodTrack track = ipod.TrackByTrackID(trackID);
 * 				string title = track.GetText(IPOD_TITLE);
 * 				cout << "  Index " << j << " TrackID " << trackID << ": '" << title << "'" << endl;
 * 			}
 * 		}
 * 	}
 * }
 *
 * \endcode
 *
 * \section python Python support
 *
 * libipod also includes fairly high-level bindings for Python.  You may view the specific documentation
 * for Python by doing the following:
 * \code
 * user@host:~$ python -c "import ipod; help(ipod)"
 * \endcode
 *
 * \section python_example A simple Python example
 *
 * \code
 *	from ipod import *
 *
 *	paths = IPod.paths()
 *	if len(paths):
 *		ipod = IPod(paths[0])
 *		total,free = ipod.diskUsage()
 *		print "iPod at %s (total %dK, free %dK)" % (paths[0],total,free)
 *		for track in ipod.tracks:
 *			print "  TrackID %d:  %s - %s/%s (%s)" % (track.id,track.title,track.artist,track.album,track.fileType)
 *		for playlist in ipod.playlists:
 *			print "Playlist: %s" % playlist.name
 *			for trackItem in playlist.trackItems:
 *				print "  TrackID %d: %s" % (trackItem.id,ipod.trackForID(trackItem.id).title)
 *		for preset in ipod.eqPresets:
 *			print "Preset: %s preamp %d" % (preset.name,preset.preamp),
 *			print [preset.bandA[i] for i in xrange(10)],
 *			print [preset.bandB[i] for i in xrange(5)]
 *	else:
 *		print "no iPods found!"
 * \endcode
 *
 * \section acknowledgements Acknowledgements and Notices
 *
 * Thanks for Linspire, Inc for sponsoring this project.
 *
 * "Apple", "iPod", and "iTunes" are registered trademarks of Apple Computer, Inc.
 * "Shuffle" is a trademark of Apple Computer, Inc.
 * "iTunes Music Store" is a service mark of Apple Computer, Inc.
 *
 * "Linspire" is a trademark of Linspire, Inc.
 *
 * This project is neither sponsored nor endorsed by Apple Computer, Inc
 */

 /** \file ipod_cpp.h
 *  \brief C++ wrapper interface to the the libipod C library.
 */

class IPod;
class IPodTrack;
class IPodPlaylist;
class IPodTrackItem;
class IPodEQPreset;

 
/** \brief A class representing a connected iPod.
 */
class IPod {
	friend class IPodTrack;
	friend class IPodPlaylist;
	friend class IPodEQPreset;
public:
	/** \brief String encodings
	 */
	enum Encoding {
		IPOD_ENCODING_UTF_8, 		/*!< Selector to encode strings in UTF-8 (default) */
		IPOD_ENCODING_ISO_8859_1	/*!< Selector to encode strings in ISO-8859-1 (Latin-1) */
	};
	
	/** \brief Constructor, takes an absolute path to the mount point of the iPod.
	 *
	 * \param path an absolute path to the mount point of the iPod
	 *
	 * \code
	 *   IPod ipod("/mnt/sda1");
	 * \endcode
	 */
	IPod(std::string path);
	
	/** \brief Destructor, frees all data internal data structures
	 */
	~IPod();
	
	/** \brief Flushes any modifications to the iPod.
	 *
	 * If any changes have been made to the data structures, will write out any
	 * affected databases to the iPod storage
	 */
	void Flush(void);
	
	/** \brief Returns the database version found on the iPod.
	 *
	 * \return the version of the database
	 */
	unsigned long Version(void);
	
	/** \brief Returns information about the total and available storage on the iPod.
	 *
	 * \param total pointer to 64-bit integer that will contain the total size of the iPod in bytes
	 * \param free pointer to 64-bit integer that will contain the total available space on the iPod in bytes
	 *
	 * \code
	 *   uint64_t total,free;
	 *   ipod.DiskUsage(&total,&free);
	 *   cout << "Total storage on iPod: " << total << " bytes" << endl;
	 * \endcode
	 */
	void DiskUsage(uint64_t *total, uint64_t *free);
	
	/** \brief Returns the number of tracks on the iPod.
	 *
	 * \return the number of tracks on the iPod
	 */
	unsigned long TrackCount(void);
	
	/** \brief Returns an object encapsulating a single audio track.
	 *
	 * \param index the index of the track to be retrieved
	 * \return an object encapsulating the track
	 */
	IPodTrack TrackByIndex(unsigned long index);
	
	/** \brief Returns an object encapsulating the single track with the supplied unique track ID
	 *
	 * \param trackID unique ID for the track to be retrieved
	 * \return an object encapsulating the track
	 */
	IPodTrack TrackByTrackID(uint32_t trackID);
	
	/** \brief Returns the number of playlists on the iPod
	 *
	 * \return the number of playlists on the iPod
	 */
	unsigned long PlaylistCount(void);
	
	/** \brief Returns an object encapsulating a single playlist
	 *
	 * \param index the index of the playlist to be retrieved
	 * \return an object encapsulating the playlist
	 */
	IPodPlaylist PlaylistByIndex(unsigned long index);
	
	/** \brief Returns the number of EQ Presets on the iPod
	 *
	 * \return the number of EQ Presets on the iPod
	 */
	unsigned long EQPresetCount(void);
	
	/** \brief Returns an object encapsulating a single EQ preset
	 *
	 * \param index the index of the EQ preset to retrieve
	 * \return an object encapsulating the EQ preset
	 */
	IPodEQPreset EQPresetByIndex(unsigned long index);

	/** \brief Scans for mounted iPods
	 *
	 * Scans the /mnt directory looking for mounted iPods
	 *
	 * \param paths a pointer to a pointer in which an array of std:string instances will be returned
	 * \return the number of iPods found
	 */
	static int Discover(std::string **paths);
	
	/** \brief The current encoding used for strings
	 *
	 * \return the current string encoding, defaults to IPod::IPOD_ENCODING_UTF_8
	 */
	static Encoding StringEncoding(void);
	
	/** \brief Sets the current encoding for strings
	 *
	 * \param encoding either IPod::IPOD_ENCODING_ISO_8859_1 or IPod::IPOD_ENCODING_UTF_8 (default)
	 */
	static void SetStringEncoding(Encoding encoding);
	
private:
	ipod_t ipod;
	static IPod::Encoding g_encoding;
};

/** \brief A class representing an audio track on the iPod.
 */
class IPodTrack {
	friend class IPod;
public:
	/** \brief Constructor, creates a new, empty track on the iPod
	 *
	 * \param ipod the iPod on which to create the track
	 */
	IPodTrack(IPod &ipod);
	
	/** \brief Constuctor, creates a new track from the supplied file on the iPod
	 *
	 * This is a quick and dirty way to add audio files to the iPod - you only have to
	 * supply a local file path to a supported audio file. The file will be analyzed
	 * to extract the appropriate tag and format information to populate the data
	 * structures, and the file will be uploaded to the iPod
	 *
	 * \param ipod the iPod on which to create the track
	 * \param filePath path to a .mp3, .m4a or .wav file
	 */
	IPodTrack(IPod &ipod,std::string filePath);
	
	/** \brief Destructor, does not delete the track
	 */
	~IPodTrack();
	
	/** \brief Removes the track from the iPod
	 *
	 * This method will remove the track from all playlists and from the master track list,
	 * and will remove the audio file from the iPod
	 */
	void Remove(void);
	
	/** \brief Retrieves a text attribute from the track
	 *
	 * \param tag an identifier for the string to be retrieved
	 * \return the text of the string in the current encoding
	 * \code
	 *   cout << "Title is " << track.GetText(IPOD_TITLE) << endl;
	 * \endcode
	 */
	std::string GetText(int tag);
	
	/** \brief Sets a text attribute for the track
	 *
	 * \param tag an identifier for the string to be modified or added
	 * \param s the string to be assigned in the current encoding
	 *
	 * \code
	 *   std:string title = "Dead Puppies";
	 *   track.SetText(IPOD_TITLE,title);
	 * \endcode
	 */
	void SetText(int tag,std::string s);
	
	/** \brief Indicates whether the track currently has a particular string
	 *
	 * \param tag an identifier for the string being queried
	 * \return a boolean indicating whether or not the string item exists in the track
	 */
	bool HasText(int tag);
	
	/** \brief Return a numerical attribute for the track
	 *
	 * \param tag an identifier for the attribute to be retrieved
	 * \return the current value for the attribute
	 * \code
	 *  cout << "Sample rate is " << track.GetAttribute(IPOD_TRACK_SAMPLE_RATE) << endl;
	 * \endcode
	 */
	uint32_t GetAttribute(int tag);
	
	/** \brief Set the value of an attribute for the track
	 *
	 * \param tag an identifier for the attribute to be modified
	 * \param value the new value for the attribute
	 *
	 * \code
	 *   track.SetAttribute(IPOD_TRACK_ID,15);
	 * \endcode
	 */
	void SetAttribute(int tag, uint32_t value);
	
	/** \brief Upload an audio file corresponding to this track
	 *
	 * \param filePath a path to the audio file to be uploaded
	 * \param callback a function to be called as the file is uploaded
	 * \param userData a pointer to a structure to be proved to the callback
	 */
	void Upload(char *filePath, ipod_file_transfer_func callback = 0, void *userData = 0);
	
	/** \brief Download an audio file corresponding to this track
	 *
	 * \param filePath a path to the audio file to be downloaded
	 * \param callback a function to be called as the file is downloaded
	 * \param userData a pointer to a structure to be proved to the callback
	 */
void Download(char *filePath, ipod_file_transfer_func callback = 0, void *userData = 0);

private:
	IPodTrack(ipod_track_t t);
	ipod_track_t track;
};

/** \brief A class representing a playlist on the iPod.
 */
class IPodPlaylist {
	friend class IPod;
	friend class IPodTrackItem;
public:
	/** \brief Constructor, creates a new empty playlist on the iPod
	 *
	 * \param ipod the iPod on which to create the playlist
	 */
	IPodPlaylist(IPod &ipod);
	
	/** \brief Destructor, does not delete the playlist
	 */
	~IPodPlaylist();
	
	/** \brief Removes the playlist from the iPod
	 */ 
	void Remove(void);
	
	/** \brief Retrieves a text attribute from the playlist
	 *
	 * \param tag an identifier for the string to be retrieved, only IPOD_TITLE currently supported
	 * \return the text of the string in the current encoding
	 * \code
	 *   cout << "Playlist name is " << playlist.GetText(IPOD_TITLE) << endl;
	 * \endcode
	 */
	std::string GetText(int tag);
	
	/** \brief Sets a text attribute for the playlist
	 *
	 * \param tag an identifier for the string to be modified or added, only IPOD_TITLE currently supported
	 * \param s the string to be assigned in the current encoding
	 *
	 * \code
	 *   std:string title = "Favorites";
	 *   playlist.SetText(IPOD_TITLE,title);
	 * \endcode
	 */
	void SetText(int tag,std::string s);
	
	/** \brief Indicates whether the playlist currently has a particular string
	 *
	 * \param tag an identifier for the string being queried, true only for IPOD_TITLE
	 * \return a boolean indicating whether or not the string item exists in the playlist
	 */
	bool HasText(int tag);
	
	/** \brief Return a numerical attribute for the playlist
	 *
	 * \param tag an identifier for the attribute to be retrieved
	 * \return the current value for the attribute
	 * \code
	 *  cout << "Playlist is " << (playlist.GetAttribute(IPOD_PLAYLIST_HIDDEN)?"hidden":"visible") << endl;
	 * \endcode
	 */
	uint32_t GetAttribute(int tag);
	
	/** \brief Set the value of an attribute for the playlist
	 *
	 * \param tag an identifier for the attribute to be modified
	 * \param value the new value for the attribute
	 *
	 * \code
	 *   playlist.SetAttribute(IPOD_PLAYLIST_HIDDEN,1);
	 * \endcode
	 */
	void SetAttribute(int tag, uint32_t value);
	
	/** \brief Return the number of track items in this playlist
	 *
	 * \return the number of track items in the playlist
	 */
	unsigned long TrackItemCount(void);
	
	/** \brief Return an object encapsulating a track item
	 *
	 * \param index the index of the track item to be retrieved
	 * \return an object encapsulating a track item
	 */
	IPodTrackItem TrackItemByIndex(unsigned long index);
private:
	IPodPlaylist(ipod_playlist_t p);
	ipod_playlist_t playlist;
};

/** \brief A class representing a track item in a playlist
 */
class IPodTrackItem {
	friend class IPodPlaylist;
public:
	/** \brief Constructor, creates a new, empty track item in the playlist
	 */

	IPodTrackItem(IPodPlaylist &playlist);
	/** \brief Destructor, does not delete the track item
	 */
	~IPodTrackItem();
	
	/** \brief Removes the track item from the playlist
	 */
	void Remove(void);

	/** \brief Return a numerical attribute for the track item
	 *
	 * \param tag an identifier for the attribute to be retrieved
	 * \return the current value for the attribute
	 * \code
	 *  cout << "Track ID is " << trackItem.GetAttribute(IPOD_TRACK_ITEM_TRACK_ID) << endl;
	 * \endcode
	 */
	uint32_t GetAttribute(int tag);
	
	/** \brief Set the value of an attribute for the track item
	 *
	 * \param tag an identifier for the attribute to be modified
	 * \param value the new value for the attribute
	 *
	 * \code
	 *   trackItem.SetAttribute(IPOD_TRACK_ITEM_TRACK_ID,42);
	 * \endcode
	 */
	void SetAttribute(int tag, uint32_t value);
private:
	IPodTrackItem(ipod_track_item_t ti);
	ipod_track_item_t track_item;	
};

/** \brief A class representing an EQ Preset on the iPod
 */
class IPodEQPreset {
	friend class IPod;
public:
	/** \brief Constructor, creates a new, empty EQ Preset on the iPod
	 */
	IPodEQPreset(IPod &ipod);
	
	/** \brief Destructor, does not delete the EQ Preset
	 */
	~IPodEQPreset();
	
	/** \brief Removes the EQ Preset from the iPod
	 */
	void Remove(void);
	
	/** \brief Retrieves a text attribute from the EQ Preset
	 *
	 * \param tag an identifier for the string to be retrieved, only IPOD_TITLE currently supported
	 * \return the text of the string in the current encoding
	 * \code
	 *   cout << "Preset name is " << preset.GetText(IPOD_TITLE) << endl;
	 * \endcode
	 */
	std::string GetText(int tag);
	
	/** \brief Sets a text attribute for the EQ Preset
	 *
	 * \param tag an identifier for the string to be modified or added, only IPOD_TITLE currently supported
	 * \param s the string to be assigned in the current encoding
	 *
	 * \code
	 *   std:string title = "Boom Box";
	 *   preset.SetText(IPOD_TITLE,title);
	 * \endcode
	 */
	void SetText(int tag,std::string s);
	
	/** \brief Indicates whether the EQ Preset currently has a particular string
	 *
	 * \param tag an identifier for the string being queried, true only for IPOD_TITLE
	 * \return a boolean indicating whether or not the string item exists in the preset
	 */
	bool HasText(int tag);
	
	/** \brief Return a numerical attribute for the EQ Preset
	 *
	 * \param tag an identifier for the attribute to be retrieved
	 * \return the current value for the attribute
	 * \code
	 *  cout << "Preamp is " << preset.GetAttribute(IPOD_EQ_PRESET_PREAMP) << endl;
	 * \endcode
	 */
	int32_t GetAttribute(int tag);
	
	/** \brief Set the value of an attribute for the EQ Preset
	 *
	 * \param tag an identifier for the attribute to be modified
	 * \param value the new value for the attribute
	 *
	 * \code
	 *   preset.SetAttribute(IPOD_EQ_PRESET,100);
	 * \endcode
	 */
	void SetAttribute(int tag, int32_t value);
	
private:
	IPodEQPreset(ipod_eq_preset_t p);
	ipod_eq_preset_t preset;
};

#endif
