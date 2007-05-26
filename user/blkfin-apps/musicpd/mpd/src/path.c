/* the Music Player Daemon (MPD)
 * (c)2003-2004 by Warren Dukes (shank@mercury.chem.pitt.edu)
 * This project's homepage is: http://www.musicpd.org
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "path.h"
#include "log.h"
#include "charConv.h"
#include "conf.h"
#include "utf8.h"
#include "mpm.h"

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#ifdef HAVE_LOCALE
#ifdef HAVE_LANGINFO_CODESET
#include <locale.h>
#include <langinfo.h>
#endif
#endif

char * musicDir;
char * playlistDir;

char * fsCharset = NULL;

char * pathConvCharset(char * to, char * from, char * str) {
	if(setCharSetConversion(to,from)==0)
		return convStrDup(str);
	return NULL;
}

char * fsCharsetToUtf8(char * str) {
	char *tmp = pathConvCharset("UTF-8",fsCharset,str);

	if(tmp && !validUtf8String(tmp)) {
		free(tmp);
		return NULL;
	} else {
		char *ret = mpm_maxpath_str();
		strncpy(ret,tmp,MAXPATHLEN);
		free(tmp);
		return ret;
	}
}

char * utf8ToFsCharset(char * str) {
	char *tmp = pathConvCharset(fsCharset,"UTF-8",str);

//		printf("In charset= %s  \r\n",tmp);
	if (!tmp)
		{
//			printf("str in if= %s  \r\n",str);
			return str;	
		}
	else {
		char *ret = mpm_maxpath_str();
		strncpy(ret,tmp,MAXPATHLEN);
		free(tmp);
//		printf("ret in else= %s  \r\n",ret);
		
		return ret;
	}
}

void setFsCharset(char * charset) {
	int error = 0;

	if(fsCharset) free(fsCharset);

	fsCharset = strdup(charset);

	DEBUG("setFsCharset: fs charset is: %s\n",fsCharset);
	
	if(setCharSetConversion("UTF-8",fsCharset)!=0) {
		WARNING("fs charset conversion problem: "
			"not able to convert from \"%s\" to \"%s\"\n",
			fsCharset,"UTF-8");
		error = 1;
	}
	if(setCharSetConversion(fsCharset,"UTF-8")!=0) {
		WARNING("fs charset conversion problem: "
			"not able to convert from \"%s\" to \"%s\"\n",
			"UTF-8",fsCharset);
		error = 1;
	}
	
	if(error) {
		free(fsCharset);
		WARNING("setting fs charset to ISO-8859-1!\n");
		fsCharset = strdup("ISO-8859-1");
	}
}

char * getFsCharset() {
	return fsCharset;
}

void initPaths(char * playlistDirArg, char * musicDirArg) {
	char * charset = NULL;
#ifdef HAVE_LOCALE
#ifdef HAVE_LANGINFO_CODESET
	char * originalLocale;
#endif
#endif
        struct stat st;

        playlistDir = prependCwdToPathDup(playlistDirArg);
        if((stat(playlistDir,&st))<0) {
                ERROR("problem stat'ing \"%s\": %s\n", playlistDirArg, strerror(errno));
                exit(EXIT_FAILURE);
        }
        if(!S_ISDIR(st.st_mode)) {
                ERROR("\"%s\" is not a directory: %s\n", playlistDirArg, strerror(errno));
                exit(EXIT_FAILURE);
        }

        musicDir = prependCwdToPathDup(musicDirArg);
        if((stat(musicDir,&st))<0) {
                ERROR("problem stat'ing \"%s\"\n",musicDirArg);
                exit(EXIT_FAILURE);
        }
        if(!S_ISDIR(st.st_mode)) {
                ERROR("\"%s\" is not a directory\n",musicDirArg);
                exit(EXIT_FAILURE);
        }

	if(getConf()[CONF_FS_CHARSET]) {
		charset = strdup(getConf()[CONF_FS_CHARSET]);
	}
#ifdef HAVE_LOCALE
#ifdef HAVE_LANGINFO_CODESET
	else if((originalLocale = setlocale(LC_CTYPE,NULL))) {
		char * temp;
		char * currentLocale;
		originalLocale = strdup(originalLocale);

		if(!(currentLocale = setlocale(LC_CTYPE,""))) {
			WARNING("problems setting current locale with "
					"setlocale()\n");
		}
		else {
			if(strcmp(currentLocale,"C")==0 ||
					strcmp(currentLocale,"POSIX")==0) 
			{
				WARNING("current locale is \"%s\"\n",
						currentLocale);
			}
			else if((temp = nl_langinfo(CODESET))) {
				charset = strdup(temp);
			}
			else WARNING("problems getting charset for locale\n");
			if(!setlocale(LC_CTYPE,originalLocale)) {
				WARNING("problems resetting locale with setlocale()\n");
			}
		}

		free(originalLocale);
	}
	else WARNING("problems getting locale with setlocale()\n");
#endif
#endif

	if(charset) {
		setFsCharset(charset);
		free(charset);
	}
	else {
		WARNING("setting filesystem charset to ISO-8859-1\n");
		setFsCharset("ISO-8859-1");
	}
}

void finishPaths() {
	free(fsCharset);
	fsCharset = NULL;
}

char * rmp2amp(char * relativePath) {
	char *absolutePath = mpm_maxpath_str();

	memset(absolutePath,0,MAXPATHLEN+1);

	strncpy(absolutePath,musicDir,MAXPATHLEN);
	strncat(absolutePath,relativePath,MAXPATHLEN-strlen(musicDir));

//		printf("absolutePath in rmp2amp  = %d  \r\n",absolutePath);
	return absolutePath;
}

char * rpp2app(char * relativePath) {
	char *absolutePath = mpm_maxpath_str();

	memset(absolutePath,0,MAXPATHLEN+1);

	strncpy(absolutePath,playlistDir,MAXPATHLEN);
	strncat(absolutePath,relativePath,MAXPATHLEN-strlen(musicDir));

	return absolutePath;
}

char * parentPath(char * path) {
	char *c, *parentPath = mpm_maxpath_str();

	memset(parentPath,0,MAXPATHLEN+1);
	strncpy(parentPath,path,MAXPATHLEN);
	
	c = strrchr(parentPath,'/');
	if (c == NULL)
		parentPath[0] = '\0';
	else {
		while ((parentPath <= c) && *(--c) == '/') /* nothing */;
		c[1] = '\0';
	}
	
	return parentPath;
}

char * sanitizePathDup(char * path) {
	int len = strlen(path)+1;
	char * ret = malloc(len);
	char * cp = ret;

	memset(ret,0,len);

	len = 0;

	/* eliminate more than one '/' in a row, like "///" */
	while(*path) {
		while(*path=='/') path++;
		if(*path=='.') {
			/* we dont want to have hidden directoires, or '.' or
			   ".." in our path */
			free(ret);
			return NULL;
		}
		while(*path && *path!='/') {
			*(cp++) = *(path++);
			len++;
		}
		if(*path=='/') {
			*(cp++) = *(path++);
			len++;
		}
	}

	if(len && ret[len-1]=='/') {
		len--;
		ret[len] = '\0';
	}

	DEBUG("sanitized: %s\n", ret);

	return realloc(ret,len+1);
}

char * prependCwdToPathDup(char * path) {
        int len = MAXPATHLEN+1;
        char * ret = malloc(len);

        memset(ret,0,len);

        len = 0;

        if(path[0]=='/') {
                strncpy(ret,path,MAXPATHLEN);
                len = strlen(ret);
        }
        else {
                getcwd(ret,MAXPATHLEN);
                len = strlen(ret);
                if(ret[len-1]!='/') {
                        strncat(ret,"/",MAXPATHLEN-len);
                        len = strlen(ret);
                }
                strncat(ret,path,MAXPATHLEN-len);
                len = strlen(ret);
        }
        if(ret[len-1]!='/') {
                strncat(ret,"/",MAXPATHLEN-len);
                len = strlen(ret);
        }

        return realloc(ret,len+1);
}

