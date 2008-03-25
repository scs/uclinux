#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/param.h>
#include <dirent.h>
#include "dirtraverse.h"

#include "debug.h"

#define TRUE  1
#define FALSE 0

//
// Read all files in a directory. Continue recusively down in directories.
//
int visit_dir(char *path, visit_cb cb, void *userdata)
{
	struct stat statbuf;
	DIR *dir;
	struct dirent *dirent;
	char t[MAXPATHLEN];
	int len;
	int ret = 1;

	dir = opendir(path);
	if(dir == NULL) {
		return -1;
	}
	dirent = readdir(dir);
	while(dirent != NULL) {
		if(strcmp(".", dirent->d_name) == 0) {
		}
		else if(strcmp("..", dirent->d_name) == 0) {
		}
		else {
			snprintf(t, MAXPATHLEN, "%s/%s", path, dirent->d_name);
			if(lstat(t, &statbuf) < 0) {
				return -1;
			}
			else if(S_ISREG(statbuf.st_mode)) {
				ret = cb(VISIT_FILE, t, "", userdata);
				if( ret  < 0)
					goto out;
			}			
			else if(S_ISDIR(statbuf.st_mode)) {
				ret = cb(VISIT_GOING_DEEPER, dirent->d_name, path, userdata);
				if( ret < 0)
					goto out;
				len = strlen(path);
				sprintf(path, "%s%s/", path, dirent->d_name);
				ret = visit_dir(t, cb, userdata);
				if(ret < 0)
					goto out;
				ret = cb(VISIT_GOING_UP, "", "", userdata);
				if(ret < 0)
					goto out;
				path[len] = '\0';
			}
			else {
				// This was probably a symlink. Just skip
			}
		}
		dirent = readdir(dir);
	}

out:
	return ret;
}

//
//
//
int visit_all_files(char *name, visit_cb cb, void *userdata)
{
	struct stat statbuf;
	int ret;
	char path[MAXPATHLEN];

	if(stat(name, &statbuf) < 0) {
		DEBUG(0, "Error stating %s\n", name);
		ret = -1;
		goto out;
	}

	if(S_ISREG(statbuf.st_mode)) {
		/* A single file. Just visit it, then we are done. */
		ret = cb(VISIT_FILE, name, "", userdata);
	}
	else if(S_ISDIR(statbuf.st_mode)) {
		/* A directory! Enter it */
		snprintf(path, MAXPATHLEN, "%s", name);

		/* Don't notify app if going "down" to "." */
		if(strcmp(name, ".") == 0)
			ret = 1;
		else
			ret = cb(VISIT_GOING_DEEPER, name, "", userdata);

		if(ret < 0)
			goto out;
		ret = visit_dir(path, cb, userdata);
		if(ret < 0)
			goto out;
		ret = cb(VISIT_GOING_UP, "", "", userdata);
		if(ret < 0)
			goto out;
	}
	else {
		/* Not file, not dir, don't know what to do */
		ret = -1;
	}

out:
	return ret;
}

#if 0
int visit(int action, char *name, char *path, void *userdata)
{
	switch(action) {
	case VISIT_FILE:
		printf("Visiting %s\n", filename);
		break;

	case VISIT_GOING_DEEPER:
		printf("Going deeper %s\n", filename);
		break;

	case VISIT_GOING_UP:
		printf("Going up\n");
		break;
	default:
		printf("going %d\n", action);
	}
	return 1;
}


//
//
//
int main(int argc, char *argv[])
{
//	visit_all_files("Makefile", visit);
//	visit_all_files("/usr/local/apache/", visit);
	visit_all_files("testdir", visit);
	return 0;
}
#endif
