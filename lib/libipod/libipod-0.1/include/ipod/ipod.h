/*
 * ipod.h
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

#ifndef __IPOD_H__
#define __IPOD_H__

#include <ipod/ipod_file_utils.h>

#ifdef __cplusplus
extern "C" {
#endif

/** \file ipod.h
 *  \brief Mid-level C interface to the iPod.
 */

typedef void *ipod_t; /*!< \brief an iPod */
typedef void *ipod_track_t; /*!< \brief a track on an iPod */
typedef void *ipod_playlist_t; /*!< \brief a playlist on an iPod */
typedef void *ipod_track_item_t; /*!< \brief a track reference in a playlist on an iPod */
typedef void *ipod_eq_preset_t; /*!< \brief an equalizer preset on the iPod */


/** \brief Return a count and array of paths to mounted iPods
 *
 * This function scans the /mnt directory looking for mounted iPods and returns
 * an array of strings which are absolute paths to each mount point
 *
 * \param path_array a pointer to a pointer in which to store an array of strings
 * \return the number of mounted iPods
 *
 * The caller is reponsible for freeing the array and its elements
 */
extern int ipod_discover(char ***path_array);

/** \brief Read the databases for the iPod at the given mount point
 *
 * \param path an absolute path to the iPod's mount point
 * \return a reference to the iPod that is used in subsequent calls
 */
extern ipod_t ipod_new(const char *path);

/** \brief Write the database if required
 *
 * \param ipod the iPod to be flushed
 */
extern void ipod_flush(ipod_t ipod);

/** \brief Flush the databases and close the iPod
 *
 * \param ipod the iPod to be freed
 */
extern void ipod_free(ipod_t ipod);

/** \brief Return the version of the database on the iPod
 *
 * \param ipod the iPod
 * \return the version number of the database
 */
extern uint32_t ipod_version(ipod_t ipod);

/** \brief Report the total and available disk space on the iPod
 *
 * \param ipod the iPod
 * \param total a pointer to a 64-bit integer which will contain the total storage in bytes
 * \param free a pointer to a 64-bit integer which will contain the available space in bytes
 */
extern void ipod_disk_usage(ipod_t ipod, uint64_t *total, uint64_t *free);

//-----------------------------------------------------------------
//
// Tracks
//
//-----------------------------------------------------------------

/** \brief Return the number of audio tracks on the iod
 *
 * \param ipod the iPod
 * \return the number of audio tracks on the iPod
 */
extern unsigned int ipod_track_count(ipod_t ipod);

/** \brief get the audio track for the given index
 *
 * \param ipod the iPod
 * \param index the index of the audio track to be returned
 * \return the audio track
 */
extern ipod_track_t ipod_track_get_by_index(ipod_t ipod, unsigned int index);

/** \brief get the audio track with the given unique track ID
 *
 * \param ipod the iPod
 * \param track_id the track ID of the audio track to be returned
 * \return the audio track
 */
extern ipod_track_t ipod_track_get_by_track_id(ipod_t ipod, uint32_t track_id);

/** \brief free the audio track structure
 *
 * This method just frees the wrapper structure - the track itself in not removed
 * from the iPod database
 *
 * \param track the audio track structure to be freed
 */
extern void ipod_track_free(ipod_track_t track);

/** \brief Add a new, empty track structure to the iPod
 *
 * Subsequent calls should be made to add the various text and number attributes
 * to the track.
 *
 * \param ipod the iPod on which to add the track
 * \return a track structure
 */
extern ipod_track_t ipod_track_add(ipod_t ipod);

/** \brief Add a track from an mp3, m4a or wav audio file to the iPod
 *
 * This method will add a new track to the iPod and create the attribute
 * information based on the contents of the supplied audio file.  It will extract
 * ID3 tags and other metaiinformation as appropriate, and will analyse the file for
 * sample rate, bitrate, duration, etc.  It understands .mp3, .m4a, and .wav files.
 * For mp3 files, it will extract tags in ID3v1, ID3v1.1, ID3v2.2, ID3v2.3 and ID3v4
 * format, and handles text tags in ISO-8859-1, UTF-16-BOM, UTF-16BE and UTF-8
 *
 * \param ipod the iPod
 * \param filePath the path to an mp3, m4a or wav file
 * \return a track structure
 */
extern ipod_track_t ipod_track_add_from(ipod_t ipod, const char *filePath);

/** \brief Remove a track from the iPod
 *
 * The track will be removed from all playlists, and the corresponding
 * audio file will be removed from the iPod's storage
 *
 * \param track the track to be removed
 */
extern void ipod_track_remove(ipod_track_t track);

/** \brief Get an attribute text string from the track
 *
 * \param track the track from which to fetch the attribute
 * \param tag the identifier for the attribute to be retrieved
 * \param s (optional) a string allocated on the heap in which to store the resulting text.
 *          If the parameter is NULL, then a new string is allocated on the heap, otherwise
 *          the string is reallocated to the size of the attribute.
 * \return a string on the heap encoded in UTF-8
 *
 * \code
 *  char *title = ipod_string_new();
 *  title = ipod_track_get_text(track,IPOD_TITLE,title);
 *  printf("The title is %s\n",title);
 *  ipod_string_free(title);
 * \endcode
 */
extern char *ipod_track_get_text(ipod_track_t track,int tag,char *s);

/** \brief Set an attribute text string for the track
 *
 * \param track the track for which to set the attribute
 * \param tag the identifier for the attribute to be set
 * \param s the text encoded in UTF-8 to be assigned to the attribute
 *
 * \code
 * ipod_track_set_text(track,IPOD_TITLE,"Dead Puppies");
 * \endcode
 */
extern void ipod_track_set_text(ipod_track_t track,int tag, const char *s);

/** \brief Determine if a track has a particular text attribute
 *
 * \param track the track for which to test the attribute
 * \param tag the identifier for the attribute to be tested
 * \return 0 if the attribute is missing, 1 otherwise
 */
extern int ipod_track_has_text(ipod_track_t track, int tag);

/** \brief Get a numerical attribute of a track
 *
 * \param track the track from which to fetch the attribute
 * \param tag the identifier for the attribute to be retrieved
 * \return the current value of the attribute
 */
extern uint32_t ipod_track_get_attribute(ipod_track_t track, int tag);

/** \brief Set a numerical attribute of a track
 *
 * \param track the track for which to set the attribute
 * \param tag the identifier for the attribute to be set
 * \param value the new value for the attribute
 */
extern void ipod_track_set_attribute(ipod_track_t track, int tag, uint32_t value);

/** \brief Upload an audio file corresponding to the track
 *
 * \param track the track to be associated with the file
 * \param filePath the path to the audio file to be uploaded
 * \param callback a function to be called during the upload to report progress information
 * \param userData a pointer to data to be sent as a parameter for the callback
 */
extern void ipod_track_upload(ipod_track_t track,const char *filePath,ipod_file_transfer_func callback,void *userData);

/** \brief Download an audio file corresponding to the track
 *
 * \param track the track associated with the file
 * \param filePath the path to the destination to which the track will be downloaded
 * \param callback a function to be called during the diwnload to report progress information
 * \param userData a pointer to data to be sent as a parameter for the callback
 */
extern void ipod_track_download(ipod_track_t track,const char *filePath,ipod_file_transfer_func callback,void *userData);

//-----------------------------------------------------------------
//
// Playlists
//
//-----------------------------------------------------------------

/** \brief Return the number of playlists on the iPod
 *
 * \param ipod the iPod
 * \return the number of playlists on the iPod
 */
extern unsigned int ipod_playlist_count(ipod_t ipod);

/** \brief get the playlist for the given index
 *
 * \param ipod the iPod
 * \param index the index of the playlist to be returned
 * \return the playlist
 */
extern ipod_playlist_t ipod_playlist_get_by_index(ipod_t ipod, unsigned int index);

/** \brief free the playlist structure
 *
 * This method just frees the wrapper structure - the playlist itself in not removed
 * from the iPod database
 *
 * \param playlist the playlist structure to be freed
 */
extern void ipod_playlist_free(ipod_playlist_t playlist);

/** \brief Add a new, empty playlist structure to the iPod
 *
 * Subsequent calls should be made to add the various text and number attributes
 * to the playlist.
 *
 * \param ipod the iPod on which to add the playlist
 * \return a playlist structure
 */
extern ipod_playlist_t ipod_playlist_add(ipod_t ipod);

/** \brief Remove a playlist from the iPod
 *
 * \param playlist the playlist to be removed
 */
extern void ipod_playlist_remove(ipod_playlist_t playlist);

/** \brief Get an attribute text string from the playlist
 *
 * \param playlist the playlist from which to fetch the attribute
 * \param tag the identifier for the attribute to be retrieved (IPOD_TITLE is the only tag currently supported)
 * \param s (optional) a string allocated on the heap in which to store the resulting text.
 *          If the parameter is NULL, then a new string is allocated on the heap, otherwise
 *          the string is reallocated to the size of the attribute.
 * \return a string on the heap encoded in UTF-8
 *
 * \code
 *  char *title = ipod_string_new();
 *  title = ipod_playlist_get_text(playlist,IPOD_TITLE,title);
 *  printf("The playlist title is %s\n",title);
 *  ipod_string_free(title);
 * \endcode
 */
extern char *ipod_playlist_get_text(ipod_playlist_t playlist,int tag,char *s);

/** \brief Set an attribute text string for the playlist
 *
 * \param playlist the playlist for which to set the attribute
 * \param tag the identifier for the attribute to be set (IPOD_TITLE is the only tag currently supported
 * \param s the text encoded in UTF-8 to be assigned to the attribute
 *
 * \code
 * ipod_playlist_set_text(playlist,IPOD_TITLE,"Favorites");
 * \endcode
 */
extern void ipod_playlist_set_text(ipod_playlist_t playlist,int tag,const char *s);

/** \brief Determine if a playlist has a particular text attribute
 *
 * \param playlist the playlist for which to test the attribute
 * \param tag the identifier for the attribute to be tested (IPOD_TITLE si the only tag currently supported)
 * \return 0 if the attribute is missing, 1 otherwise
 */
extern int ipod_playlist_has_text(ipod_playlist_t playlist, int tag);

/** \brief Get a numerical attribute of a playlist
 *
 * \param playlist the playlist from which to fetch the attribute
 * \param tag the identifier for the attribute to be retrieved
 * \return the current value of the attribute
 */
extern uint32_t ipod_playlist_get_attribute(ipod_playlist_t playlist, int tag);

/** \brief Set a numerical attribute of a playlist
 *
 * \param playlist the playlist for which to set the attribute
 * \param tag the identifier for the attribute to be set
 * \param value the new value for the attribute
 */
extern void ipod_playlist_set_attribute(ipod_playlist_t playlist, int tag, uint32_t value);

//-----------------------------------------------------------------
//
// Track Items (references to Tracks in Playlists)
//
//-----------------------------------------------------------------

/** \brief Return the number of track items in the playlist
 *
 * \param playlist the playlist
 * \return the number of track items in the playlist
 */
extern unsigned int ipod_track_item_count(ipod_playlist_t playlist);

/** \brief get the track item for the given index
 *
 * \param playlist the playlist
 * \param index the index of the track item to be returned
 * \return the track item
 */
extern ipod_track_item_t ipod_track_item_get_by_index(ipod_playlist_t playlist, unsigned int index);

/** \brief free the track item structure
 *
 * This method just frees the wrapper structure - the track item itself in not removed
 * from the playlist
 *
 * \param trackItem the track item structure to be freed
 */
extern void ipod_track_item_free(ipod_track_item_t trackItem);

/** \brief Add a new, empty track item structure to the iPod
 *
 * Subsequent calls should be made to add the various number attributes
 * to the track item.
 *
 * \param playlist the playlist to which to add the track item
 * \return a track item structure
 */
extern ipod_track_item_t ipod_track_item_add(ipod_playlist_t playlist);

/** \brief Remove a track item from a playlist
 *
 * \param trackItem the track item to be removed
 */
extern void ipod_track_item_remove(ipod_track_item_t trackItem);

/** \brief Get a numerical attribute of a track item
 *
 * \param trackItem the track item from which to fetch the attribute
 * \param tag the identifier for the attribute to be retrieved
 * \return the current value of the attribute
 */
extern uint32_t ipod_track_item_get_attribute(ipod_track_item_t trackItem, int tag);

/** \brief Set a numerical attribute of a track item
 *
 * \param trackItem the track item for which to set the attribute
 * \param tag the identifier for the attribute to be set
 * \param value the new value for the attribute
 */
extern void ipod_track_item_set_attribute(ipod_track_item_t trackItem, int tag, uint32_t value);

//-----------------------------------------------------------------
//
// EQ Presets
//
//-----------------------------------------------------------------

/** \brief Return the number of EQ presets on the iPod
 *
 * \param ipod the iPod
 * \return the number of EQ presets on the iPod
 */
extern unsigned int ipod_eq_preset_count(ipod_t ipod);

/** \brief get the EQ preset for the given index
 *
 * \param ipod the iPod
 * \param index the index of the EQ preset to be returned
 * \return the EQ preset
 */
extern ipod_eq_preset_t ipod_eq_preset_get_by_index(ipod_t ipod, unsigned int index);

/** \brief free the EQ preset structure
 *
 * This method just frees the wrapper structure - the EQ preset itself in not removed
 * from the iPod
 *
 * \param preset the EQ preset structure to be freed
 */
extern void ipod_eq_preset_free(ipod_eq_preset_t preset);

/** \brief Add a new, empty EQ preset structure to the iPod
 *
 * Subsequent calls should be made to add the various text and number attributes
 * to the EQ preset.
 *
 * \param ipod the iPod on which to add the EQ preset
 * \return an EQ preset structure
 */
extern ipod_eq_preset_t ipod_eq_preset_add(ipod_t ipod);

/** \brief Remove an EQ preset from the iPod
 *
 * \param preset the EQ preset to be removed
 */
extern void ipod_eq_preset_remove(ipod_eq_preset_t preset);

/** \brief Get an attribute text string from the EQ preset
 *
 * \param preset the EQ preset from which to fetch the attribute
 * \param tag the identifier for the attribute to be retrieved (IPOD_TITLE is the only tag currently supported)
 * \param s (optional) a string allocated on the heap in which to store the resulting text.
 *          If the parameter is NULL, then a new string is allocated on the heap, otherwise
 *          the string is reallocated to the size of the attribute.
 * \return a string on the heap encoded in UTF-8
 *
 * \code
 *  char *title = ipod_string_new();
 *  title = ipod_eq_preset_get_text(preset,IPOD_TITLE,title);
 *  printf("The preset name is %s\n",title);
 *  ipod_string_free(title);
 * \endcode
 */
extern char *ipod_eq_preset_get_text(ipod_eq_preset_t preset,int tag,char *s);

/** \brief Set an attribute text string for the EQ preset
 *
 * \param preset the EQ preset for which to set the attribute
 * \param tag the identifier for the attribute to be set (IPOD_TITLE is the only tag currently supported
 * \param s the text encoded in UTF-8 to be assigned to the attribute
 *
 * \code
 * ipod_eq_preset_set_text(preset,IPOD_TITLE,"Boombox");
 * \endcode
 */
extern void ipod_eq_preset_set_text(ipod_eq_preset_t preset,int tag,const char *s);

/** \brief Determine if an EQ preset has a particular text attribute
 *
 * \param preset the EQ preset for which to test the attribute
 * \param tag the identifier for the attribute to be tested (IPOD_TITLE si the only tag currently supported)
 * \return 0 if the attribute is missing, 1 otherwise
 */
extern int ipod_eq_preset_has_text(ipod_eq_preset_t preset, int tag);

/** \brief Get a numerical attribute of an EQ preset
 *
 * \param preset the EQ preset from which to fetch the attribute
 * \param tag the identifier for the attribute to be retrieved
 * \return the current value of the attribute
 */
extern int32_t ipod_eq_preset_get_attribute(ipod_eq_preset_t preset, int tag);

/** \brief Set a numerical attribute of an EQ preset
 *
 * \param preset the EQ preset for which to set the attribute
 * \param tag the identifier for the attribute to be set
 * \param value the new value for the attribute
 */
extern void ipod_eq_preset_set_attribute(ipod_eq_preset_t preset, int tag, int32_t value);

//
//
//-----------------------------------------------------------------
//
// Miscellaneous
//
//-----------------------------------------------------------------

/** \brief Prints out various internal statistics for debugging
 */
extern void ipod_report(void);

#ifdef __cplusplus
};
#endif

#endif
