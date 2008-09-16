/*
 * ipod_cpp.cpp
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

#include <ipod/ipod_cpp.h>
#include <ipod/ipod_string.h>
#include <ipod/ipod_memory.h>

//
// IPod
//
IPod::IPod(std::string path)
{
	ipod = ipod_new(path.c_str());
}

IPod::~IPod() {
	ipod_free(ipod);
}

void IPod::Flush(void)
{
	ipod_flush(ipod);
}

unsigned long IPod::Version(void)
{
	return ipod_version(ipod);
}

void IPod::DiskUsage(uint64_t *total, uint64_t *free)
{
	ipod_disk_usage(ipod,total,free);
}

unsigned long IPod::TrackCount(void)
{
	return ipod_track_count(ipod);
}

IPodTrack IPod::TrackByIndex(unsigned long index)
{
	return IPodTrack(ipod_track_get_by_index(ipod,index));
}

IPodTrack IPod::TrackByTrackID(uint32_t trackID)
{
	return IPodTrack(ipod_track_get_by_track_id(ipod,trackID));
}

unsigned long IPod::PlaylistCount(void)
{
	return ipod_playlist_count(ipod);
}

IPodPlaylist IPod::PlaylistByIndex(unsigned long index)
{
	return IPodPlaylist(ipod_playlist_get_by_index(ipod,index));
}

unsigned long IPod::EQPresetCount(void)
{
	return ipod_eq_preset_count(ipod);
}

IPodEQPreset IPod::EQPresetByIndex(unsigned long index)
{
	return IPodEQPreset(ipod_eq_preset_get_by_index(ipod,index));
}

int IPod::Discover(std::string **paths)
{
	char **path_array;
	int count = ipod_discover(&path_array);
	*paths = new std::string[count];
	for (int i=0;i<count;i++) {
		*paths[i] = path_array[i];
		ipod_string_free(path_array[i]);
	}
	ipod_memory_free(path_array);
	return count;
}

IPod::Encoding IPod::StringEncoding(void)
{
	return IPod::g_encoding;
}

void IPod::SetStringEncoding(IPod::Encoding encoding)
{
	IPod::g_encoding = encoding;
}

IPod::Encoding IPod::g_encoding = IPod::IPOD_ENCODING_UTF_8;
//
// IPodTrack
//
IPodTrack::IPodTrack(IPod &ipod)
{
	track = ipod_track_add(ipod.ipod);
}

IPodTrack::IPodTrack(IPod &ipod,std::string filePath)
{
	track = ipod_track_add_from(ipod.ipod,filePath.c_str());
}

IPodTrack::~IPodTrack()
{
	ipod_track_free(track);
}

void IPodTrack::Remove(void)
{
	ipod_track_remove(track);
}

std::string IPodTrack::GetText(int tag)
{
	if (IPod::g_encoding==IPod::IPOD_ENCODING_ISO_8859_1) {
		char *s = ipod_track_get_text(track,tag,NULL); // is utf-8
		char *ss = ipod_string_iso8859_from_utf8(s); // is iso-8859
		std::string sss = ss;
		ipod_string_free(s);
		ipod_string_free(ss);
		return sss;
	} else {
		char *s = ipod_track_get_text(track,tag,NULL); // is utf-8
		std::string sss = s;
		ipod_string_free(s);
		return sss;
	}
}

void IPodTrack::SetText(int tag, std::string s)
{
	if (IPod::g_encoding==IPod::IPOD_ENCODING_ISO_8859_1) {
		char *ss = ipod_string_utf8_from_iso8859((char *)s.c_str());
		ipod_track_set_text(track,tag,ss);
		ipod_string_free(ss);
	} else
		ipod_track_set_text(track,tag,(char *)s.c_str());
}

bool IPodTrack::HasText(int tag)
{
	return ipod_track_has_text(track,tag);
}

uint32_t IPodTrack::GetAttribute(int tag)
{
	return ipod_track_get_attribute(track,tag);
}

void IPodTrack::SetAttribute(int tag, uint32_t value)
{
	ipod_track_set_attribute(track,tag,value);
}

void IPodTrack::Upload(char *filePath, ipod_file_transfer_func callback, void *userData)
{
	ipod_track_upload(track,filePath,callback,userData);
}

void IPodTrack::Download(char *filePath, ipod_file_transfer_func callback, void *userData)
{
	ipod_track_download(track,filePath,callback,userData);
}

IPodTrack::IPodTrack(ipod_track_t t) {
	track = t;
}

//
// IPodPlaylist
//
IPodPlaylist::IPodPlaylist(IPod &ipod)
{
	playlist = ipod_playlist_add(ipod.ipod);
}

IPodPlaylist::~IPodPlaylist()
{
	ipod_playlist_free(playlist);
}

void IPodPlaylist::Remove(void)
{
	ipod_playlist_remove(playlist);
}

std::string IPodPlaylist::GetText(int tag)
{
	if (IPod::g_encoding==IPod::IPOD_ENCODING_ISO_8859_1) {
		char *s = ipod_playlist_get_text(playlist,tag,NULL); // is utf-8
		char *ss = ipod_string_iso8859_from_utf8(s); // is iso-8859
		std::string sss = ss;
		ipod_string_free(s);
		ipod_string_free(ss);
		return sss;
	} else {
		char *s = ipod_playlist_get_text(playlist,tag,NULL); // is utf-8
		std::string sss = s;
		ipod_string_free(s);
		return sss;
	}
}

void IPodPlaylist::SetText(int tag, std::string s)
{
	if (IPod::g_encoding==IPod::IPOD_ENCODING_ISO_8859_1) {
		char *ss = ipod_string_utf8_from_iso8859((char *)s.c_str());
		ipod_playlist_set_text(playlist,tag,ss);
		ipod_string_free(ss);
	} else
		ipod_playlist_set_text(playlist,tag,(char *)s.c_str());
}

bool IPodPlaylist::HasText(int tag)
{
	return ipod_playlist_has_text(playlist,tag);
}

uint32_t IPodPlaylist::GetAttribute(int tag)
{
	return ipod_playlist_get_attribute(playlist,tag);
}

void IPodPlaylist::SetAttribute(int tag, uint32_t value)
{
	ipod_track_set_attribute(playlist,tag,value);
}
 
unsigned long IPodPlaylist::TrackItemCount(void)
{
	return ipod_track_item_count(playlist);
}

IPodTrackItem IPodPlaylist::TrackItemByIndex(unsigned long index)
{
	return IPodTrackItem(ipod_track_item_get_by_index(playlist,index));
}

IPodPlaylist::IPodPlaylist(ipod_playlist_t p)
{
	playlist = p;
}

//
// IPodTrackItem
//
IPodTrackItem::IPodTrackItem(IPodPlaylist &playlist)
{
	track_item = ipod_track_item_add(playlist.playlist);
}

IPodTrackItem::~IPodTrackItem()
{
	ipod_track_item_free(track_item);
}

void IPodTrackItem::Remove(void)
{
	ipod_track_item_remove(track_item);
}

uint32_t IPodTrackItem::GetAttribute(int tag)
{
	return ipod_track_item_get_attribute(track_item,tag);
}

void IPodTrackItem::SetAttribute(int tag, uint32_t value)
{
	ipod_track_item_set_attribute(track_item,tag,value);
}

IPodTrackItem::IPodTrackItem(ipod_track_item_t ti)
{
	track_item = ti;
}

//
// IPodEQPreset
//
IPodEQPreset::IPodEQPreset(IPod &ipod)
{
	preset = ipod_eq_preset_add(ipod.ipod);
}

IPodEQPreset::~IPodEQPreset()
{
	ipod_eq_preset_free(preset);
}

void IPodEQPreset::Remove(void)
{
	ipod_eq_preset_remove(preset);
}

std::string IPodEQPreset::GetText(int tag)
{
	if (IPod::g_encoding==IPod::IPOD_ENCODING_ISO_8859_1) {
		char *s = ipod_eq_preset_get_text(preset,tag,NULL); // is utf-8
		char *ss = ipod_string_iso8859_from_utf8(s); // is iso-8859
		std::string sss = ss;
		ipod_string_free(s);
		ipod_string_free(ss);
		return sss;
	} else {
		char *s = ipod_eq_preset_get_text(preset,tag,NULL); // is utf-8
		std::string sss = s;
		ipod_string_free(s);
		return sss;
	}
}

void IPodEQPreset::SetText(int tag, std::string s)
{
	if (IPod::g_encoding==IPod::IPOD_ENCODING_ISO_8859_1) {
		char *ss = ipod_string_utf8_from_iso8859((char *)s.c_str());
		ipod_eq_preset_set_text(preset,tag,ss);
		ipod_string_free(ss);
	} else
		ipod_eq_preset_set_text(preset,tag,(char *)s.c_str());
}

bool IPodEQPreset::HasText(int tag)
{
	return ipod_eq_preset_has_text(preset,tag);
}

int32_t IPodEQPreset::GetAttribute(int tag)
{
	return ipod_eq_preset_get_attribute(preset,tag);
}

void IPodEQPreset::SetAttribute(int tag, int32_t value)
{
	ipod_track_set_attribute(preset,tag,value);
}

IPodEQPreset::IPodEQPreset(ipod_eq_preset_t p)
{
	preset = p;
}

