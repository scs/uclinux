/*
 * dumptracks__cpp.cpp
 *
 * Duane Maxwell 20051111
 *
 */

#include "ipod/ipod_cpp.h"
#include "ipod/ipod_constants.h"
#include <iostream>

using namespace std;

int main(int argc,char **argv) {
	string *ipod_paths;
	
	int ipod_count = IPod::Discover(&ipod_paths);
	for (int ipod_index=0;ipod_index<ipod_count;ipod_index++) {
		string path = ipod_paths[ipod_index];
		IPod ipod(path);
		cout << "iPod at " << path << " (" << ipod.TrackCount() << " tracks, " << ipod.PlaylistCount() << " playlists)" << endl;
		for (unsigned long i=0;i<ipod.TrackCount();i++) {
			IPodTrack track = ipod.TrackByIndex(i);
			string title = track.GetText(IPOD_TITLE);
			string artist = track.GetText(IPOD_ARTIST);
			uint32_t trackID = track.GetAttribute(IPOD_TRACK_ID);
			cout << "  Index " << i << " TrackID " << trackID << ": '" << title << "' " << artist << endl;
		}
		for (unsigned long i=0;i<ipod.PlaylistCount();i++) {
			IPodPlaylist playlist = ipod.PlaylistByIndex(i);
			string name = playlist.GetText(IPOD_TITLE);
			cout << endl << "Playlist " << i << ": '" << name << "' (" << playlist.TrackItemCount() << " tracks)" << endl;
			for (unsigned long j=0;j<playlist.TrackItemCount();j++) {
				IPodTrackItem item = playlist.TrackItemByIndex(j);
				uint32_t trackID = item.GetAttribute(IPOD_TRACK_ITEM_TRACK_ID);
				IPodTrack track = ipod.TrackByTrackID(trackID);
				string title = track.GetText(IPOD_TITLE);
				cout << "  Index " << j << " TrackID " << trackID << ": '" << title << "'" << endl;
			}
		}
	}
}
