/*
 * dumptracks.c
 *
 * Duane Maxwell 20051111
 *
 */

#include <stdio.h>
#include <ipod/ipod.h>
#include <ipod/ipod_io_file.h>
#include <ipod/ipod_constants.h>
#include <ipod/ipod_string.h>

void dumpTracks(char *path) {
	ipod_t ipod;
	unsigned long numTracks,numPlaylists,i,j;
	
	ipod = ipod_new(path);
	numTracks = ipod_track_count(ipod);
	numPlaylists = ipod_playlist_count(ipod);
	printf("iPod at %s (%d tracks,%d playlists)\n",path,numTracks,numPlaylists);
	for (i=0;i<numTracks;i++) {
		ipod_track_t track = ipod_track_get_by_index(ipod,i);
		if (track) {
			uint32_t trackID;
			char *s = ipod_string_new();
			trackID = ipod_track_get_attribute(track,IPOD_TRACK_ID);
			printf("  Index %d TrackID %d: \"%s\" ",i,trackID,(s = ipod_track_get_text(track,IPOD_TITLE,s)));
			printf("%s\n",(s = ipod_track_get_text(track,IPOD_ARTIST,s)));
			ipod_string_free(s);
			ipod_track_free(track);
		} else {
			printf("Can't find track %d\n",i);
		}
	}
	for (i=0;i<numPlaylists;i++) {
		ipod_playlist_t playlist;
		char *s = NULL;
		playlist = ipod_playlist_get_by_index(ipod,i);
		if (playlist) {
			numTracks = ipod_track_item_count(playlist);
			printf("\nPlaylist %d: '%s' (%d tracks)\n",i,(s=ipod_playlist_get_text(playlist,IPOD_TITLE,s)),numTracks);
			ipod_string_free(s);
			for (j=0;j<numTracks;j++) {
				unsigned long trackID;
				ipod_track_t track;
				char *s = NULL;
				ipod_track_item_t item = ipod_track_item_get_by_index(playlist,j);
				trackID = ipod_track_item_get_attribute(item,IPOD_TRACK_ITEM_TRACK_ID);
				track = ipod_track_get_by_track_id(ipod,trackID);
				printf("  Index %d TrackID %d: \"%s\"\n",j,trackID,(s = ipod_track_get_text(track,IPOD_TITLE,s)));
				ipod_string_free(s);
				ipod_track_free(track);
				ipod_track_item_free(item);
			}
			ipod_playlist_free(playlist);
		} else {
			fprintf(stderr,"Can't find playlist %d\n",i);
		}	
	}
	ipod_free(ipod);
	printf("\n");
}

int main(int argc, char **argv) {
	char **paths;
	int i,count;
	count = ipod_discover(&paths);
	printf("Found %d ipods\n",count);
	for (i=0;i<count;i++) {
		dumpTracks(paths[i]);
	}
}
