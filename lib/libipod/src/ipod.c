/*
 * ipod.c
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

#include <ipod/ipod.h>
#include <ipod/ipod_error.h>
#include <ipod/ipod_memory.h>
#include <ipod/ipod_string.h>
#include <ipod/ipod_io_file.h>
#include <ipod/ipod_constants.h>
#include <ipod/ipod_file_utils.h>
#include "ipod_private.h"
#include "ipod_atom_mhbd.h"
#include "ipod_atom_mhsd.h"
#include "ipod_atom_mhlt.h"
#include "ipod_atom_mhit.h"
#include "ipod_atom_mhlp.h"
#include "ipod_atom_mhyp.h"
#include "ipod_atom_mhip.h"
#include "ipod_atom_mhod.h"
#include "ipod_atom_mqed.h"
#include "ipod_atom_pqed.h"
#include <sys/stat.h>
#include <sys/statfs.h>
#include <dirent.h>
#include <time.h>

#define IPOD_DB_PATH "/iPod_Control/iTunes/iTunesDB"
#define IPOD_SD_PATH "/iPod_Control/iTunes/iTunesSD"
#define IPOD_EQ_PATH "/iPod_Control/iTunes/iTunesEQPresets"

//
// Discover any initialized iPods attached to this system and return an
// array of strings containing absolute paths to the roots of
// devices.
//
// this code is for Linux - replace for other platforms.
//
int ipod_discover(char ***path_array)
{
	char **paths;
	int path_count = 0;
	DIR *mnt;
	paths = (char **)ipod_memory_alloc(0);
	mnt = opendir("/mnt");
	if (mnt) {
		for (;;) {
			struct dirent *dir = readdir(mnt);
			if (dir) {
				if (strcmp(dir->d_name,".") && strcmp(dir->d_name,"..") &&
						strncmp(dir->d_name,"floppy",6) && strncmp(dir->d_name,"cdrom",5)) {
					char *db_name;
					char *path_name = ipod_string_new_from("/mnt/");
					path_name = ipod_string_append(path_name,dir->d_name);
					db_name = ipod_string_new_from(path_name);
					db_name = ipod_string_append(db_name,IPOD_DB_PATH);
					if (ipod_file_exists(db_name)) {
						path_count++;
						paths = (char **)ipod_memory_realloc(paths,path_count*sizeof(char *));
						paths[path_count-1] = path_name;
					} else {
						ipod_string_free(path_name);
					}
					ipod_string_free(db_name);
				} else {
				}
			} else {
				break;
			}
		}
		closedir(mnt);
	} else {
		ipod_error("ipod_discover(): Cannot open /mnt directory\n");
	}
	*path_array = paths;
	return path_count;
}

ipod_t ipod_new(const char *path) {
	ipod_p p;
	char *basePath,*dbPath,*sdPath,*eqPath;
	FILE *f;
	ipod_io io;

	if (!path) return NULL;
	basePath = ipod_string_new_from(path);
	dbPath = ipod_string_append(ipod_string_new_from(basePath),IPOD_DB_PATH);
	sdPath = ipod_string_append(ipod_string_new_from(basePath),IPOD_SD_PATH);
	eqPath = ipod_string_append(ipod_string_new_from(basePath),IPOD_EQ_PATH);
	p = (ipod_p)ipod_memory_alloc(sizeof(ipod_private_struct));
	p->basePath = basePath;
	p->dbPath = dbPath;
	p->sdPath = sdPath;
	p->eqPath = eqPath;
	p->db = NULL;
	p->eq = NULL;
	f = fopen(dbPath,"rb");
	if (!f) {
		ipod_error("ipod_new(): Can't find ipod database at %s, creating\n",dbPath);
		p->db = ipod_atom_new_mhbd();
		ipod_atom_init(p->db,IPOD_VERSION5_0);
		p->db_dirty = 1;
	} else {
		io = ipod_io_file_new(f);
		p->db = ipod_atom_read_next(io,IPOD_VERSION_ANY);
		fclose(f);
		ipod_io_file_free(io);
		p->db_dirty = 0;
	}
	f = fopen(eqPath,"rb");
	if (!f) {
		ipod_error("ipod_new(): Can't find eq presets database at %s, creating\n",eqPath);
		p->eq = ipod_atom_new_mqed();
		ipod_atom_init(p->eq,IPOD_VERSION5_0);
		p->eq_dirty = 1;
	} else {
		io = ipod_io_file_new(f);
		p->eq = ipod_atom_read_next(io,IPOD_VERSION_ANY);
		fclose(f);
		ipod_io_file_free(io);
		p->eq_dirty = 0;
	}
	return (ipod_t)p;
}

static void ipod_check_tracks(ipod_t ipod);
static void ipod_write_shuffle_db(ipod_atom root,ipod_io io);

//
// write the database if required
//
void ipod_flush(ipod_t ipod)
{
	ipod_p p = (ipod_p)ipod;
	if (p && p->basePath) {
		if (p->db && p->basePath && p->dbPath) {
			ipod_check_tracks(ipod);
			ipod_atom_prepare_to_write(p->db,p->db,IPOD_VERSION_ANY);
			if (p->db_dirty) {
				FILE *f = fopen(p->dbPath,"wb");
				if (f) {
					ipod_io io = ipod_io_file_new(f);
					ipod_atom_write(p->db,io,IPOD_VERSION_ANY);
					ipod_io_file_free(io);
					fclose(f);
				}
				if (ipod_file_exists(p->sdPath)) { // XXX DSM probably ought to detect shuffle another way
					f = fopen(p->sdPath,"wb");
					if (f) {
						ipod_io io = ipod_io_file_new(f);
						ipod_write_shuffle_db(p->db,io);
						ipod_io_file_free(io);
						fclose(f);
					}
				}
			}
			p->db_dirty = 0;
		}
	}
}

//
// flush the database and close the iPod
//
void ipod_free(ipod_t ipod)
{
	ipod_p p = (ipod_p)ipod;
	
	ipod_flush(ipod);
	if (p) {
		if (p->basePath) {
			ipod_string_free(p->basePath);
			p->basePath = NULL;
		}
		if (p->dbPath) {
			ipod_string_free(p->dbPath);
			p->dbPath = NULL;
		}
		if (p->eqPath) {
			ipod_string_free(p->eqPath);
			p->eqPath = NULL;
		}
		if (p->db) {
			ipod_atom_free(p->db);
			p->db = NULL;
		}
		if (p->eq) {
			ipod_atom_free(p->eq);
			p->eq = NULL;
		}
		ipod_memory_free(p);
	}
}

uint32_t ipod_version(ipod_t ipod)
{
	ipod_p p = (ipod_p)ipod;
	return ipod_atom_mhbd_get_version(p->db);
}

//
// report the total and available disk space on the iPod
//
void ipod_disk_usage(ipod_t ipod, uint64_t *total, uint64_t *free)
{
	ipod_p p = (ipod_p)ipod;
	*total = 0;
	*free = 0;
	if (p && p->basePath) {
		struct statfs s;
		if (!statfs(p->basePath,&s)) {
			//ipod_error("ipod_disk_usage(): size %ldK free %ldK\n",s.f_blocks<<2,s.f_bfree<<2);
			*total = ((uint64_t)s.f_blocks)<<12;
			*free = ((uint64_t)s.f_bfree)<<12;
		} else {
			ipod_error("ipod_disk_usage(): cannot stat ipod at %s\n",p->basePath);
		}
	} else {
		ipod_error("ipod_disk_usage(): invalid ipod (0x%lx)\n",ipod);
	}
}


//-----------------------------------------------------------------
//
// Tracks
//
//-----------------------------------------------------------------

//
// dig down the atom tree to get the list of tracks (mhit atoms)
//
static ipod_atom_list ipod_tracks(ipod_atom root)
{
	if (root) {
		ipod_atom mhsd, mhlt;
		ipod_atom_list mhits;
		mhsd = ipod_atom_mhbd_tracks(root);
		mhlt = ipod_atom_mhsd_tracks(mhsd);
		return ipod_atom_mhlt_tracks(mhlt);
	}
}

//
// dig down the atom tree to get the list of playlists (mhyp atoms)
//
static ipod_atom_list ipod_playlists(ipod_atom root)
{
	if (root) {
		ipod_atom mhsd, mhlp;
		ipod_atom_list mhyps;
		mhsd = ipod_atom_mhbd_playlists(root);
		mhlp = ipod_atom_mhsd_playlists(mhsd);
		return ipod_atom_mhlp_playlists(mhlp);
	}
}

//
// return the number of tracks on the ipod
//
unsigned int ipod_track_count(ipod_t ipod)
{
	ipod_p p = (ipod_p)ipod;
	if (p && p->db)
		return ipod_atom_list_length(ipod_tracks(p->db));
	else
		ipod_error("ipod_track_count(): Invalid ipod %lx\n",ipod);
	return 0;
}


//
// get the n'th track
//
ipod_track_t ipod_track_get_by_index(ipod_t ipod, unsigned int index)
{
	ipod_p p = (ipod_p)ipod;
	if (p && p->db) {
		ipod_atom_list tracks = ipod_tracks(p->db);
		if (tracks) {
			ipod_track_p t = (ipod_track_p)ipod_memory_alloc(sizeof(ipod_track_private_struct));
			t->ipod = p;
			t->track = ipod_atom_list_get(tracks,index);
			return (ipod_track_t)t;
		}
	}
	return NULL;
}

//
// get the track by track ID
//
ipod_track_t ipod_track_get_by_track_id(ipod_t ipod, uint32_t track_id)
{
	ipod_p p = (ipod_p)ipod;
	if (p && p->db) {
		ipod_atom_list tracks = ipod_tracks(p->db);
		if (tracks) {
			unsigned int i;
			for (i=0;i<ipod_atom_list_length(tracks);i++) {
				ipod_atom mhit_atom = ipod_atom_list_get(tracks,i);
				if (mhit_atom) {
					ipod_atom_mhit mhit = (ipod_atom_mhit)mhit_atom->data;
					if (mhit->trackID==track_id) {
						ipod_track_p t = (ipod_track_p)ipod_memory_alloc(sizeof(ipod_track_private_struct));
						t->ipod = p;
						t->track = mhit_atom;
						return (ipod_track_t)t;
					}
				}
			}
		}
	}
	return NULL;
}

//
// free this structure (does not delete the track)
//
void ipod_track_free(ipod_track_t track)
{
	if (track)
		ipod_memory_free(track);
}

//
// compute a unique track ID
//
static uint32_t ipod_unique_track_id(ipod_atom_list tracks)
{
	uint32_t track_id = 1000; // arbitrary
	unsigned int i;

	for (i=0;i<ipod_atom_list_length(tracks);i++) {
		uint32_t a_track_id;
		ipod_atom track = ipod_atom_list_get(tracks,i);
		a_track_id = ipod_atom_mhit_get_attribute(track,IPOD_TRACK_ID);
		if (a_track_id>=track_id)
			track_id = a_track_id+2;
	}
	return track_id;
}

//
// count the number of hash directories in the iPod_Control:Music directory
//
static unsigned int ipod_music_folders_count(ipod_t ipod)
{
	ipod_p p = (ipod_p)ipod;
	unsigned int count = 0;
	char *musicPath = 0,*dirPath;
	dirPath = ipod_string_new();
	musicPath = ipod_string_new_from(p->basePath);
	musicPath = ipod_string_append(musicPath,"/iPod_Control/Music/");
	for (;;) {
		char dirName[] = "F00";
		dirPath = ipod_string_set(dirPath,musicPath);
		sprintf(dirName,"F%02d",count);
		dirPath = ipod_string_append(dirPath,dirName);
		if (!ipod_directory_exists(dirPath))
			break;
		count++;
	}
	ipod_string_free(dirPath);
	ipod_string_free(musicPath);
	return count;
}

//
// remove any tracks for whom files do not exist
//
// We should probably also remove any files in iPod_Control:Music
// that don't have corresponding entries in the database - iTunes
// seems to do this.
//
static void ipod_check_tracks(ipod_t ipod)
{
	unsigned int i;
	char *location = ipod_string_new();
	for (i=0;i<ipod_track_count(ipod);i++) {
		ipod_track_t track = ipod_track_get_by_index(ipod,i);
		location = ipod_track_get_text(track,IPOD_FULL_PATH,location);
		if (!ipod_file_exists(location)) {
			ipod_track_p t = (ipod_track_p)track;
			ipod_error("ipod_check_tracks(): Removing track for missing file %s\n",location);
			ipod_track_remove(track);
			ipod_atom_free(t->track);
			i--;
		}
		ipod_track_free(track);
	}
	ipod_string_free(location);
}

//
// create a unique random 4-letter name for the track
//
// NOTE: this is done because there's a rather low limit on the total
// length of a track name in the database.  Most other programs try to manufacture
// something based on the upload file name - however, on top of the length limitation, there
// are other restrictions on characters.  Like iTunes, we punt and leave the problem up
// to the hosting application to create a meaningful host track file name based on the
// meta information from the track.  This means that a downloaded track name may not
// match the name of the uploaded track.
//
static char *ipod_unique_track_location(ipod_atom_list tracks,ipod_t ipod,const char *extension)
{
	ipod_p p = (ipod_p)ipod;
	char *musicPath = 0;
	char *fullName;
	int dirCount = ipod_music_folders_count(ipod);
	fullName = ipod_string_new();
	musicPath = ipod_string_new_from(p->basePath);
	musicPath = ipod_string_append(musicPath,"/iPod_Control/Music/");
	srandom(time(NULL));
	for (;;) {
		int i,dirNum;
		char name[] = "XXXX";
		char dirName[] = "F00";
		
		dirNum = random() % dirCount;
		for (i=0;i<4;i++)
			name[i] = 'A'+(random() % 26);
		fullName = ipod_string_set(fullName,musicPath);
		sprintf(dirName,"F%02d",dirNum);
		fullName = ipod_string_append(fullName,dirName);
		fullName = ipod_string_append(fullName,"/");
		fullName = ipod_string_append(fullName,name);
		fullName = ipod_string_append(fullName,extension);
		if (!ipod_file_exists(fullName)) {
			fullName = ipod_string_set(fullName,":iPod_Control:Music:");
			fullName = ipod_string_append(fullName,dirName);
			fullName = ipod_string_append(fullName,":");
			fullName = ipod_string_append(fullName,name);
			fullName = ipod_string_append(fullName,extension);
			ipod_string_free(musicPath);
			return fullName;
		}
	}	
}

//
// add a new, empty track to an iPod
//
ipod_track_t ipod_track_add(ipod_t ipod)
{
	ipod_p p = (ipod_p)ipod;
	if (p && p->db) {
		ipod_atom_list tracks = ipod_tracks(p->db);
		if (tracks) {
			ipod_atom mhit_atom = ipod_atom_new_mhit();
			if (mhit_atom) {
				unsigned long track_id;
				char *location;
				ipod_track_p t;
				time_t tm;
				tm = time(NULL);
				ipod_atom_init(mhit_atom,IPOD_VERSION_ANY);
				t = (ipod_track_p)ipod_memory_alloc(sizeof(ipod_track_private_struct));
				t->ipod = p;
				t->track = mhit_atom;
				track_id = ipod_unique_track_id(tracks);
				ipod_atom_mhit_set_attribute(mhit_atom,IPOD_TRACK_ID,track_id);
				ipod_atom_mhit_set_attribute(mhit_atom,IPOD_TRACK_ADDED_TIME_NATIVE,tm);
				ipod_atom_mhit_set_attribute(mhit_atom,IPOD_TRACK_LAST_MODIFICATION_TIME_NATIVE,tm);
				ipod_atom_mhit_set_attribute(mhit_atom,IPOD_TRACK_DBIDHI,track_id);
				ipod_atom_mhit_set_attribute(mhit_atom,IPOD_TRACK_DBIDLO,tm);
				ipod_atom_list_append(tracks,mhit_atom);
				p->db_dirty = 1;
				return (ipod_track_t)t;
			}
		}
	}
	return NULL;
}

//
// remove a track from the iPod - it will be removed from all playlists
// and the associated music file deleted
//
void ipod_track_remove(ipod_track_t track)
{
	ipod_track_p t = (ipod_track_p)track;
	if (t && t->ipod && t->track) {
		ipod_p p = t->ipod;
		if (p) {
			int index;
			ipod_atom_list tracks = ipod_tracks(p->db);
			index = ipod_atom_list_index(tracks,t->track);
			if (index>=0) {
				char *fullPath;
				ipod_atom_list_remove(tracks,t->track);
				// XXX DSM TODO remove from playlists
				fullPath = ipod_track_get_text(track,IPOD_FULL_PATH,NULL);
				ipod_delete_file(fullPath);
				ipod_string_free(fullPath);
				p->db_dirty = 1;
			} else {
				ipod_error("ipod_track_remove(): Can't find track %lx on ipod %lx\n",track,p);
			}
		} else {
			ipod_error("ipod_track_remove(): Bad ipod %lx for track %lx\n",p,track);
		}
	} else {
		ipod_error("ipod_track_remove(): Bad track %lx",track);
	}
}

//
// get a text string encoded in UTF-8 from the track
//
char *ipod_track_get_text(ipod_track_t track,int tag,char *s)
{
	ipod_track_p t = (ipod_track_p)track;
	if (t && t->ipod && t->track) {
		switch (tag) {
			case IPOD_FULL_PATH: {
				char *partialPath = ipod_string_new();
				s = ipod_string_set(s,t->ipod->basePath);
				partialPath = ipod_track_get_text(track,IPOD_LOCATION,partialPath);
				ipod_string_replace_char(partialPath,':','/');
				s = ipod_string_append(s,partialPath);
				ipod_string_free(partialPath);
				return s;
				}
			default:
				return ipod_atom_mhit_get_text_utf8(t->track,tag,s);
		}
	} else {
		ipod_error("ipod_track_get_text(): Bad track %lx\n",track);
	}
	return s;
}

//
// set a text string encoded in UTF-8 from the track
//
void ipod_track_set_text(ipod_track_t track,int tag,const char *s)
{
	ipod_track_p t = (ipod_track_p)track;
	if (t && t->ipod && t->track) {
		switch (tag) {
			case IPOD_FULL_PATH:
				ipod_error("ipod_track_set_text(): Tag %d is read-only\n",tag);
				break;
			default:
				ipod_atom_mhit_set_text_utf8(t->track,tag,s);
		}
		t->ipod->db_dirty = 1;
	} else {
		ipod_error("ipod_track_set_text(): Bad track %lx\n",track);
	}
}

//
// determine is a track has an existing text item
//
int ipod_track_has_text(ipod_track_t track, int tag)
{
	ipod_track_p t = (ipod_track_p)track;
	if (t && t->ipod && t->track)
		return ipod_atom_mhit_has_text(t->track,tag);
	return 0;
}

//
// get an attribute of a track
//
uint32_t ipod_track_get_attribute(ipod_track_t track, int tag)
{
	ipod_track_p t = (ipod_track_p)track;
	if (t && t->ipod && t->track) {
		return ipod_atom_mhit_get_attribute(t->track,tag);
	} else {
		ipod_error("ipod_track_get_attribute(): Bad track %lx\n",track);
	}
	return 0;
}

//
// set an attribute of a track
//
void ipod_track_set_attribute(ipod_track_t track, int tag, uint32_t value)
{
	ipod_track_p t = (ipod_track_p)track;
	if (t && t->ipod && t->track) {
		ipod_atom_mhit_set_attribute(t->track,tag,value);
		t->ipod->db_dirty = 1;
	} else {
		ipod_error("ipod_track_set_attribute(): Bad track %lx\n",track);
	}
}


//
// upload a track to the iPod
//
void ipod_track_upload(ipod_track_t track,const char *filePath,ipod_file_transfer_func callback,void *userData)
{
	if (track) {
		char *ipod_path;
		if (!ipod_track_has_text(track,IPOD_LOCATION)) {
			ipod_track_p t = (ipod_track_p)track;
			ipod_p p = (ipod_p)t->ipod;
			ipod_atom_list tracks = ipod_tracks(p->db);
			const char *extension;
			char *location;
			extension = ipod_extension_of(filePath,".mp3");
			location = ipod_unique_track_location(tracks,p,extension);
			if (location && strlen(location)>0) {
				ipod_atom_mhit_set_text_utf8(t->track,IPOD_LOCATION,location);
			}
		}
		ipod_path = ipod_track_get_text(track,IPOD_FULL_PATH,NULL);
		//ipod_error("ipod_track_upload(): Uploading %s to %s\n",filePath,ipod_path);
		ipod_copy_file(filePath,ipod_path,callback,userData);
		ipod_string_free(ipod_path);
	}
}

//
// download a track from the iPod
//
void ipod_track_download(ipod_track_t track,const char *filePath,ipod_file_transfer_func callback,void *userData)
{
	if (track) {
		char *ipod_path = ipod_track_get_text(track,IPOD_FULL_PATH,NULL);
		//ipod_error("ipod_track_download(): Downloading %s to %s\n",ipod_path,filePath);
		ipod_copy_file(ipod_path,filePath,callback,userData);
		ipod_string_free(ipod_path);
	}
}

//-----------------------------------------------------------------
//
// Playlists
//
//-----------------------------------------------------------------

//
// return the number of playlists on the ipod
//
unsigned int ipod_playlist_count(ipod_t ipod)
{
	ipod_p p = (ipod_p)ipod;
	if (p && p->db)
		return ipod_atom_list_length(ipod_playlists(p->db));
	else
		ipod_error("ipod_playlist_count(): Invalid ipod_t (%lx)\n",ipod);
	return 0;
}

//
// get the n'th playlist
//
ipod_playlist_t ipod_playlist_get_by_index(ipod_t ipod, unsigned int index)
{
	ipod_p p = (ipod_p)ipod;
	if (p && p->db) {
		ipod_atom_list playlists = ipod_playlists(p->db);
		if (playlists) {
			ipod_playlist_p t = (ipod_playlist_p)ipod_memory_alloc(sizeof(ipod_playlist_private_struct));
			t->ipod = p;
			t->playlist = ipod_atom_list_get(playlists,index);
			return (ipod_playlist_t)t;
		}
	}
	return NULL;
}

//
// free this structure (does not delete the playlist)
//
void ipod_playlist_free(ipod_playlist_t playlist)
{
	if (playlist)
		ipod_memory_free(playlist);
}

//
// compute a unique playlist ID
//
// It should be enough to just have a unique low-order long
//
static uint32_t ipod_unique_playlist_id(ipod_atom_list playlists)
{
	uint32_t playlist_id = 10; // arbitrary
	unsigned int i;

	for (i=0;i<ipod_atom_list_length(playlists);i++) {
		uint32_t a_playlist_id;
		ipod_atom playlist = ipod_atom_list_get(playlists,i);
		a_playlist_id = ipod_atom_mhyp_get_attribute(playlist,IPOD_PLAYLIST_PLAYLIST_ID_LO);
		if (a_playlist_id>=playlist_id)
			playlist_id = a_playlist_id+2;
	}
	return playlist_id;
}

//
// add a new, empty playlist to an iPod
//
ipod_playlist_t ipod_playlist_add(ipod_t ipod)
{
	ipod_p p = (ipod_p)ipod;
	if (p && p->db) {
		ipod_atom_list playlists = ipod_playlists(p->db);
		if (playlists) {
			ipod_atom mhyp_atom = ipod_atom_new_mhyp();
			if (mhyp_atom) {
				ipod_playlist_p t;
				ipod_atom_init(mhyp_atom,IPOD_VERSION_ANY);
				t = (ipod_playlist_p)ipod_memory_alloc(sizeof(ipod_playlist_private_struct));
				t->ipod = p;
				t->playlist = mhyp_atom;
				ipod_atom_mhyp_set_attribute(mhyp_atom,IPOD_PLAYLIST_PLAYLIST_ID_LO,ipod_unique_playlist_id(playlists));
				ipod_atom_mhyp_set_attribute(mhyp_atom,IPOD_PLAYLIST_TIMESTAMP_NATIVE,time(NULL));
				ipod_atom_list_append(playlists,mhyp_atom);
				p->db_dirty = 1;
				return (ipod_playlist_t)t;
			}
		}
	}
	return NULL;
}

//
// remove a playlist from the iPod
//
void ipod_playlist_remove(ipod_playlist_t playlist)
{
	ipod_playlist_p t = (ipod_playlist_p)playlist;
	if (t && t->ipod && t->playlist) {
		ipod_p p = t->ipod;
		if (p) {
			int index;
			ipod_atom_list playlists;
			playlists = ipod_playlists(p->db);
			index = ipod_atom_list_index(playlists,t->playlist);
			if (index>=0) {
				ipod_atom_list_remove(playlists,t->playlist);
				ipod_atom_free(t->playlist);
				//ipod_playlist_free(playlist);
				p->db_dirty = 1;
			} else {
				ipod_error("ipod_playlist_remove(): Can't find playlist %lx on ipod %lx\n",playlist,p);
			}
		} else {
			ipod_error("ipod_playlist_remove(): Bad ipod %lx for playlist %lx\n",p,playlist);
		}
	} else {
		ipod_error("ipod_playlist_remove(): Bad playlist %lx",playlist);
	}
}


//
// get a text string encoded in UTF-8 from the playlist
//
char *ipod_playlist_get_text(ipod_playlist_t playlist,int tag,char *s)
{
	ipod_playlist_p t = (ipod_playlist_p)playlist;
	if (t && t->ipod && t->playlist) {
		return ipod_atom_mhyp_get_text_utf8(t->playlist,tag,s);
	} else {
		ipod_error("ipod_playlist_get_text(): Bad playlist %lx\n",playlist);
	}
	return s;
}

//
// set a text string encoded in UTF-8 from the playlist
//
void ipod_playlist_set_text(ipod_playlist_t playlist,int tag,const char *s)
{
	ipod_playlist_p t = (ipod_playlist_p)playlist;
	if (t && t->ipod && t->playlist) {
		ipod_atom_mhyp_set_text_utf8(t->playlist,tag,s);
		t->ipod->db_dirty = 1;
	} else {
		ipod_error("ipod_playlist_set_text(): Bad playlist %lx\n",playlist);
	}
}

//
// determine if a playlist has an existing text item
//
int ipod_playlist_has_text(ipod_playlist_t playlist, int tag)
{
	ipod_playlist_p t = (ipod_playlist_p)playlist;
	if (t && t->ipod && t->playlist)
		return ipod_atom_mhyp_has_text(t->playlist,tag);
	return 0;
}

//
// get an attribute of a playlist
//
uint32_t ipod_playlist_get_attribute(ipod_playlist_t playlist, int tag)
{
	ipod_playlist_p t = (ipod_playlist_p)playlist;
	if (t && t->ipod && t->playlist) {
		return ipod_atom_mhyp_get_attribute(t->playlist,tag);
	} else {
		ipod_error("ipod_playlist_get_attribute(): Bad playlist %lx\n",playlist);
	}
	return 0;
}

//
// set an attribute of a playlist
//
void ipod_playlist_set_attribute(ipod_playlist_t playlist, int tag, uint32_t value)
{
	ipod_playlist_p t = (ipod_playlist_p)playlist;
	if (t && t->ipod && t->playlist) {
		ipod_atom_mhyp_set_attribute(t->playlist,tag,value);
		t->ipod->db_dirty = 1;
	} else {
		ipod_error("ipod_playlist_set_attribute(): Bad playlist %lx\n",playlist);
	}
}

//-----------------------------------------------------------------
//
// Track Items
//
//-----------------------------------------------------------------

//
// get a count of tracks in a playlist
//
unsigned int ipod_track_item_count(ipod_playlist_t playlist)
{
	ipod_playlist_p t = (ipod_playlist_p)playlist;
	if (t && t->ipod && t->playlist) {
		return ipod_atom_mhyp_track_item_count(t->playlist);
	} else {
		ipod_error("ipod_playlist_track_count(): Bad playlist %lx",playlist);
	}
	return 0;
}


//
// get the n'th track item in the playlist
//
ipod_track_item_t ipod_track_item_get_by_index(ipod_playlist_t playlist, unsigned int index)
{
	ipod_playlist_p t = (ipod_playlist_p)playlist;
	if (t && t->ipod && t->playlist) {
		ipod_atom track_item = ipod_atom_mhyp_get_track_item_by_index(t->playlist,index);
		if (track_item) {
			ipod_track_item_p ti = (ipod_track_item_p)ipod_memory_alloc(sizeof(ipod_playlist_private_struct));
			ti->track_item = track_item;
			ti->playlist = t;
			ti->ipod = t->ipod;
			return (ipod_track_item_t)ti;
		} else {
			ipod_error("ipod_track_item_get_by_index(): Cannot find track item for index %d\n",index);
		}
	} else {
		ipod_error("ipod_track_item_get_by_index(): Bad playlist %lx",playlist);
	}
	return NULL;
}

//
// free this structure (does not delete the track item)
//
void ipod_track_item_free(ipod_track_item_t trackItem)
{
	if (trackItem)
		ipod_memory_free(trackItem);

}

//
// add a new, empty track item to a playlist
//
ipod_track_item_t ipod_track_item_add(ipod_playlist_t playlist)
{
	ipod_playlist_p t = (ipod_playlist_p)playlist;
	if (t && t->ipod && t->playlist) {
		ipod_atom track_item = ipod_atom_mhyp_new_track_item(t->playlist);
		if (track_item) {
			ipod_track_item_p ti = (ipod_track_item_p)ipod_memory_alloc(sizeof(ipod_playlist_private_struct));
			ti->track_item = track_item;
			ti->playlist = t;
			ti->ipod = t->ipod;
			ipod_atom_mhip_set_attribute(track_item,IPOD_TRACK_ITEM_TIMESTAMP_NATIVE,time(NULL));
			t->ipod->db_dirty = 1;
			return (ipod_track_item_t)ti;
		} else {
			ipod_error("ipod_track_item_add(): Cannot create track item\n");
		}
	} else {
		ipod_error("ipod_track_item_add(): Bad playlist %lx",playlist);
	}
}

//
// remove a track item from the playlist
//
void ipod_track_item_remove(ipod_track_item_t trackItem)
{
	ipod_track_item_p t = (ipod_track_item_p)trackItem;
	if (t && t->ipod && t->playlist && t->track_item) {
		ipod_atom_mhyp_remove_track_item(t->playlist->playlist,t->track_item);
		ipod_atom_free(t->track_item);
		//ipod_track_item_free(t);
		t->ipod->db_dirty = 1;
	} else {
		ipod_error("ipod_track_item_remove(): Bad track item %lx",trackItem);
	}
}

//
// get an attribute of a track item
//
uint32_t ipod_track_item_get_attribute(ipod_track_item_t trackItem, int tag)
{
	ipod_track_item_p t = (ipod_track_item_p)trackItem;
	if (t && t->ipod && t->playlist && t->track_item) {
		return ipod_atom_mhip_get_attribute(t->track_item,tag);
	} else {
		ipod_error("ipod_track_item_get_attribute(): Bad track item %lx\n",trackItem);
	}
	return 0;
}

//
// set an attribute of a track item
//
void ipod_track_item_set_attribute(ipod_track_item_t trackItem, int tag, uint32_t value)
{
	ipod_track_item_p t = (ipod_track_item_p)trackItem;
	if (t && t->ipod && t->playlist && t->track_item) {
		ipod_atom_mhip_set_attribute(t->track_item,tag,value);
		t->ipod->db_dirty = 1;
	} else {
		ipod_error("ipod_track_item_set_attribute(): Bad track item %lx\n",trackItem);
	}
}

//-----------------------------------------------------------------
//
// EQ Presets
//
//-----------------------------------------------------------------

//
// return the number of presets on the ipod
//
unsigned int ipod_eq_preset_count(ipod_t ipod)
{
	ipod_p p = (ipod_p)ipod;
	if (p && p->eq)
		return ipod_atom_mqed_preset_count(p->eq);
	else
		ipod_error("ipod_eq_preset_count(): Invalid ipod_t (%lx)\n",ipod);
	return 0;
}

//
// get the n'th preset
//
ipod_eq_preset_t ipod_eq_preset_get_by_index(ipod_t ipod, unsigned int index)
{
	ipod_p p = (ipod_p)ipod;
	if (p && p->eq) {
		ipod_eq_preset_p t = (ipod_eq_preset_p)ipod_memory_alloc(sizeof(ipod_eq_preset_private_struct));
		t->ipod = p;
		t->preset = ipod_atom_mqed_get_preset_by_index(p->eq,index);
		return (ipod_eq_preset_t)t;
	}
	return NULL;
}

//
// free this structure (does not delete the preset)
//
void ipod_eq_preset_free(ipod_eq_preset_t preset)
{
	if (preset)
		ipod_memory_free(preset);
}

//
// add a new, empty preset to an iPod
//
ipod_eq_preset_t ipod_eq_preset_add(ipod_t ipod)
{
	ipod_p p = (ipod_p)ipod;
	if (p && p->eq) {
		ipod_eq_preset_p t;
		ipod_atom pqed_atom = ipod_atom_mqed_new_preset(p->eq);
		t = (ipod_eq_preset_p)ipod_memory_alloc(sizeof(ipod_eq_preset_private_struct));
		t->ipod = p;
		t->preset = pqed_atom;
		p->eq_dirty = 1;
		return (ipod_eq_preset_t)t;
	}
	return NULL;
}

//
// remove a preset from the iPod
//
void ipod_eq_preset_remove(ipod_eq_preset_t preset)
{
	ipod_eq_preset_p t = (ipod_eq_preset_p)preset;
	if (t && t->ipod && t->preset) {
		ipod_atom_mqed_remove_preset(t->ipod->eq,preset);
	} else {
		ipod_error("ipod_eq_preset_remove(): Bad preset %lx",preset);
	}
}

//
// get a text string encoded in UTF-8 from the preset
//
char *ipod_eq_preset_get_text(ipod_eq_preset_t preset,int tag,char *s)
{
	ipod_eq_preset_p t = (ipod_eq_preset_p)preset;
	if (t && t->ipod && t->preset) {
		return ipod_atom_pqed_get_text_utf8(t->preset,tag,s);
	} else {
		ipod_error("ipod_eq_preset_get_text(): Bad preset %lx\n",preset);
	}
	return s;
}

//
// set a text string encoded in UTF-8 from the preset
//
void ipod_eq_preset_set_text(ipod_eq_preset_t preset,int tag,const char *s)
{
	ipod_eq_preset_p t = (ipod_eq_preset_p)preset;
	if (t && t->ipod && t->preset) {
		ipod_atom_pqed_set_text_utf8(t->preset,tag,s);
		t->ipod->db_dirty = 1;
	} else {
		ipod_error("ipod_eq_preset_set_text(): Bad preset %lx\n",preset);
	}
}

//
// determine if a preset has an existing text item
//
int ipod_eq_preset_has_text(ipod_eq_preset_t preset, int tag)
{
	ipod_eq_preset_p t = (ipod_eq_preset_p)preset;
	if (t && t->ipod && t->preset)
		return ipod_atom_pqed_has_text(t->preset,tag);
	return 0;
}

//
// get an attribute of a preset
//
int32_t ipod_eq_preset_get_attribute(ipod_eq_preset_t preset, int tag)
{
	ipod_eq_preset_p t = (ipod_eq_preset_p)preset;
	if (t && t->ipod && t->preset) {
		return ipod_atom_pqed_get_attribute(t->preset,tag);
	} else {
		ipod_error("ipod_eq_preset_get_attribute(): Bad preset %lx\n",preset);
	}
	return 0;
}

//
// set an attribute of a preset
//
void ipod_eq_preset_set_attribute(ipod_eq_preset_t preset, int tag, int32_t value)
{
	ipod_eq_preset_p t = (ipod_eq_preset_p)preset;
	if (t && t->ipod && t->preset) {
		ipod_atom_pqed_set_attribute(t->preset,tag,value);
		t->ipod->db_dirty = 1;
	} else {
		ipod_error("ipod_eq_preset_set_attribute(): Bad preset %lx\n",preset);
	}
}

//
// This routine writes out an iPod Shuffle database
//
// Shuffles are unique in that since they don't have a UI, they don't require
// the primary database for their operation, and instead use a much simpler database.
// It's basically a shuffled list of UNIX-style file paths.  One thing that's a little
// odd is the use of 3-byte values, presumably to save space, then pad the filepaths
// out to 522 bytes.
//
void ipod_write_shuffle_db(ipod_atom root,ipod_io io)
{
	unsigned int i;
	ipod_atom_list tracks;
	tracks = ipod_atom_list_shallow_copy(ipod_tracks(root));
	ipod_atom_list_shuffle(tracks);
	ipod_io_putul3(io,ipod_atom_list_length(tracks));
	ipod_io_putul3(io,0x010600); // whatever!
	ipod_io_putul3(io,0x12); // version??
	ipod_io_putul3(io,0);
	ipod_io_putul3(io,0);
	ipod_io_putul3(io,0);
	for (i=0;i<ipod_atom_list_length(tracks);i++) {
		char *path;
		const char *extension;
		size_t u16len;
		int j;
		char *u16string;
		size_t dataWritten;
		ipod_atom track = ipod_atom_list_get(tracks,i);
		path = ipod_string_new();
		path = ipod_atom_mhit_get_text_utf8(track,IPOD_LOCATION,path);
		ipod_string_replace_char(path,':','/'); // use UNIX-style path
		extension = ipod_extension_of(path,".mp3");
		ipod_io_putul3(io,0x22e); // fixed total length of block?
		ipod_io_putul3(io,0x5aa501); // unk1 - some sort of magic bytes?
		ipod_io_putul3(io,ipod_atom_mhit_get_attribute(track,IPOD_TRACK_START_TIME));
		ipod_io_putul3(io,0); // unk2
		ipod_io_putul3(io,0); // unk3
		ipod_io_putul3(io,ipod_atom_mhit_get_attribute(track,IPOD_TRACK_END_TIME));
		ipod_io_putul3(io,0); // unk4
		ipod_io_putul3(io,0); // unk5
		ipod_io_putul3(io,100); // volume XXX DSM use value from track?
		if (!strcmp(extension,".wav"))
			ipod_io_putul3(io,3);
		else if (!strcmp(extension,".m4a") || !strcmp(extension,".aac"))
			ipod_io_putul3(io,2);
		else
			ipod_io_putul3(io,1);
		ipod_io_putul3(io,0x200); // unk6 - length of filename in bytes (name is always padded to 512)
		u16string = ipod_string_utf16_from_utf8(path,&u16len);
		ipod_io_write(io,u16string,u16len*2,&dataWritten);
		for (j=0;j<522-u16len*2;j++)
			ipod_io_putb(io,0);
		ipod_io_putul3(io,1); // play during shuffle
		ipod_io_putul3(io,0); // don't bookmark (used by podcasts)
		ipod_io_putul3(io,0); // unk7
		ipod_memory_free(u16string);
		ipod_string_free(path);
	}
}

void ipod_report(void)
{
	ipod_memory_report();
	ipod_string_report();
	ipod_atom_report();
}
