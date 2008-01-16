/*============================================================ */
/* */
/*	fileio.c - Unix file access functions */
/* */
/*============================================================ */

/*
 * Modified For OpenVMS By:  Robert Alan Byer.
 *                           byer@mail.ourservers.net
 *                           January 15, 2004
 */
#if defined(__DECC) && defined(VMS)
#  define PATH_LEADER
#else
#  define PATH_LEADER "."
#endif

#include <stdarg.h>
#include "xmame.h"
#include "osdutils.h"
#include "unzip.h"
#ifdef MESS
#include "image.h"
#endif

#ifdef _POSIX_VERSION
#define OFF_T off_t
#define FSEEK fseeko
#define FTELL ftello
#else
#define OFF_T long
#define FSEEK fseek
#define FTELL ftell
#endif

#define VERBOSE				0

#define MAX_OPEN_FILES		16
#define FILE_BUFFER_SIZE	256


/*============================================================ */
/*	EXTERNALS */
/*============================================================ */

extern char *rompath_extra;

/* from datafile.c */
extern const char *db_filename;

/* from cheat.c */
extern char *cheatfile;



/*============================================================ */
/*	TYPE DEFINITIONS */
/*============================================================ */

typedef struct _pathdata pathdata;

struct _pathdata
{
	const char *rawpath;
	const char **path;
	int pathcount;
};

struct _osd_file
{
	FILE		*fileptr;
	OFF_T		filepos;
	OFF_T		end;
	OFF_T		offset;
	OFF_T		bufferbase;
	size_t		bufferbytes;
	unsigned char	buffer[FILE_BUFFER_SIZE];
};

static pathdata pathlist[FILETYPE_end];
static osd_file openfile[MAX_OPEN_FILES];



/*============================================================ */
/*	GLOBAL VARIABLES */
/*============================================================ */

char *playbackname;
char *recordname;

FILE *stdout_file;
FILE *stderr_file;



/*============================================================ */
/*	LOCAL VARIABLES */
/*============================================================ */

#ifndef MESS

static int errorlog;

static int init_errorlog(struct rc_option *option, const char *arg, int priority)
{
	/* provide errorlog from here on */
	if (errorlog)
	{
		options.logfile = mame_fopen(NULL, "error.log", FILETYPE_DEBUGLOG, TRUE);
		if (!options.logfile)
		{
			perror("unable to open log file\n");
			exit(1);
		}
	}
	option->priority = priority;
	return 0;
}

#endif // !MESS



/*============================================================ */
/*	FILE PATH OPTIONS */
/*============================================================ */

struct rc_option fileio_opts[] =
{
	/* name, shortname, type, dest, deflt, min, max, func, help */
	{ "File I/O-related", NULL, rc_seperator, NULL, NULL, 0, 0, NULL, NULL },
#ifndef MESS
	{ "rompath", "rp", rc_string, (char *)&pathlist[FILETYPE_ROM].rawpath, XMAMEROOT"/roms", 0, 0, NULL, "Search path for rom files" },
#else
	{ "biospath", "bp", rc_string, (char *)&pathlist[FILETYPE_ROM].rawpath, XMAMEROOT"/bios", 0, 0, NULL, "Search path for BIOS sets" },
	{ "softwarepath", "swp", rc_string, (char *)&pathlist[FILETYPE_IMAGE].rawpath, XMAMEROOT"/software", 0, 0, NULL,  "Search path for software" },
	{ "hash_directory", "hash", rc_string, (char *)&pathlist[FILETYPE_HASH].rawpath, XMAMEROOT"/hash", 0, 0, NULL, "Directory containing hash files" },
#endif
	{ "samplepath", "sp", rc_string, (char *)&pathlist[FILETYPE_SAMPLE].rawpath, XMAMEROOT"/samples", 0, 0, NULL, "Search path for sample files" },
	{ "inipath", NULL, rc_string, (char *)&pathlist[FILETYPE_INI].rawpath, XMAMEROOT"/ini", 0, 0, NULL, "Search path for ini files" },
	{ "cfg_directory", NULL, rc_string, (char *)&pathlist[FILETYPE_CONFIG].rawpath, "$HOME/"PATH_LEADER NAME"/cfg", 0, 0, NULL, "Directory to save configurations" },
	{ "nvram_directory", NULL, rc_string, (char *)&pathlist[FILETYPE_NVRAM].rawpath, "$HOME/"PATH_LEADER NAME"/nvram", 0, 0, NULL, "Directory to save nvram contents" },
	{ "memcard_directory", NULL, rc_string, (char *)&pathlist[FILETYPE_MEMCARD].rawpath, "$HOME/"PATH_LEADER NAME"/memcard", 0, 0, NULL, "Directory to save memory card contents" },
	{ "input_directory", NULL, rc_string, (char *)&pathlist[FILETYPE_INPUTLOG].rawpath, "$HOME/"PATH_LEADER NAME"/inp", 0, 0, NULL, "Directory to save input device logs" },
	{ "hiscore_directory", NULL, rc_string, (char *)&pathlist[FILETYPE_HIGHSCORE].rawpath, "$HOME/"PATH_LEADER NAME"/hi", 0, 0, NULL, "Directory to save hiscores" },
	{ "state_directory", NULL, rc_string, (char *)&pathlist[FILETYPE_STATE].rawpath, "$HOME/"PATH_LEADER NAME"/sta", 0, 0, NULL, "Directory to save states" },
	{ "artwork_directory", NULL, rc_string, (char *)&pathlist[FILETYPE_ARTWORK].rawpath, XMAMEROOT"/artwork", 0, 0, NULL, "Directory for Artwork (Overlays etc.)" },
	{ "snapshot_directory", NULL, rc_string, (char *)&pathlist[FILETYPE_SCREENSHOT].rawpath, XMAMEROOT"/snap", 0, 0, NULL, "Directory for screenshots (.png format)" },
	{ "diff_directory", NULL, rc_string, (char *)&pathlist[FILETYPE_IMAGE_DIFF].rawpath, "$HOME/"PATH_LEADER NAME"/diff", 0, 0, NULL, "Directory for hard drive image difference files" },
	{ "ctrlr_directory", NULL, rc_string, (char *)&pathlist[FILETYPE_CTRLR].rawpath, XMAMEROOT"/ctrlr", 0, 0, NULL, "Directory to save controller definitions" },
	{ "comment_directory", NULL, rc_string, (char *)&pathlist[FILETYPE_COMMENT].rawpath, XMAMEROOT"/comments", 0, 0, NULL, "Directory to save comment files" },
	{ "cheat_file", NULL, rc_string, &cheatfile, XMAMEROOT"/cheat.dat", 0, 0, NULL, "Cheat filename" },
	{ "hiscore_file", NULL, rc_string, &db_filename, XMAMEROOT"/hiscore.dat", 0, 0, NULL, NULL },
	{ "record", "rec", rc_string, &recordname, NULL, 0, 0, NULL, "Set a file to record keypresses into" },
	{ "playback", "pb", rc_string, &playbackname, NULL, 0, 0, NULL, "Set a file to playback keypresses from" },
	{ "stdout-file", "out", rc_file, &stdout_file, NULL, 1,	0, NULL, "Set a file to redirect stdout to" },
	{ "stderr-file", "err",	rc_file, &stderr_file, NULL, 1, 0, NULL, "Set a file to redirect stderr to" },
#ifndef MESS
	{ "log", "L", rc_bool, &errorlog, "0", 0, 0, init_errorlog, "Generate error.log" },
#endif
	{ NULL,	NULL, rc_end, NULL, NULL, 0, 0,	NULL, NULL }
};



/*============================================================ */
/*	is_pathsep */
/*============================================================ */

INLINE int is_pathsep(char c)
{
	return (c == '/' || c == '\\');
}



/*============================================================ */
/*	find_reverse_path_sep */
/*============================================================ */

static char *find_reverse_path_sep(char *name)
{
	char *p = name + strlen(name) - 1;
	while (p >= name && !is_pathsep(*p))
		p--;
	return (p >= name) ? p : NULL;
}



/*============================================================ */
/*	create_path */
/*============================================================ */

static int create_path(char *path, int has_filename)
{
	char *sep = find_reverse_path_sep(path);

	/* if there's still a separator, and it's not the root, nuke it and recurse */
	if (sep && sep > path && !is_pathsep(sep[-1]))
	{
		*sep = 0;
		if (!create_path(path, 0))
			return 0;
		*sep = '/';
	}

	/* if we have a filename, we're done */
	if (has_filename)
		return 1;

	/* create the path */
	return check_and_create_dir(path) ? FALSE : TRUE;
}



/*============================================================ */
/*	is_variablechar */
/*============================================================ */

INLINE int is_variablechar(char c)
{
	return (isalnum(c) || c == '_' || c == '-');
}



/*============================================================ */
/*	parse_variable */
/*============================================================ */

static const char *parse_variable(const char **start, const char *end)
{
	const char *src = *start, *var;
	char variable[1024];
	char *dest = variable;

	/* copy until we hit the end or until we hit a non-variable character */
	for (src = *start; src < end && is_variablechar(*src); src++)
		*dest++ = *src;

	/* an empty variable means "$" and should not be expanded */
	if (src == *start)
		return "$";

	/* NULL terminate and return a pointer to the end */
	*dest = 0;
	*start = src;

	/* return the actual variable value */
	var = getenv(variable);
	return (var) ? var : "";
}



/*============================================================ */
/*	copy_and_expand_variables */
/*============================================================ */

static char *copy_and_expand_variables(const char *path, int len)
{
	char *dst, *result;
	const char *src;
	int length = 0;
	int backslash;

	/* first determine the length of the expanded string */
	backslash = 0;
	for (src = path; src < path + len; src++)
	{
		if (!backslash && *src == '\\' && src + 1 < path + len)
		{
			backslash = 1;
			continue;
		}
		if (!backslash && *src == '$')
		{
			src++;
			length += strlen(parse_variable(&src, path + len));
			src--;
		}
		else
			length++;
		backslash = 0;
	}

	/* allocate a string of the appropriate length */
	result = malloc(length + 1);
	assert_always(result != NULL, "Out of memory in variable expansion!");

	/* now actually generate the string */
	backslash = 0;
	for (src = path, dst = result; src < path + len; src++)
	{
		if (!backslash && *src == '\\' && src + 1 < path + len)
		{
			backslash = 1;
			continue;
		}
		if (!backslash && *src == '$')
		{
			src++;
			dst += sprintf(dst, "%s", parse_variable(&src, path + len));
			src--;
		}
		else
			*dst++ = *src;
		backslash = 0;
	}

	/* NULL terminate and return */
	*dst = 0;
	return result;
}



/*============================================================ */
/*	expand_pathlist */
/*============================================================ */

static void expand_pathlist(pathdata *list)
{
	const char *rawpath = (list->rawpath) ? list->rawpath : "";
	const char *token;

#if VERBOSE
	printf("Expanding: %s\n", rawpath);
#endif

	/* free any existing paths */
	if (list->pathcount != 0)
	{
		int pathindex;

		for (pathindex = 0; pathindex < list->pathcount; pathindex++)
			free((void *)list->path[pathindex]);
		free((void *)list->path);
	}

	/* by default, start with an empty list */
	list->path = NULL;
	list->pathcount = 0;

	/* look for separators */
	token = strchr(rawpath, ':');
	if (!token)
		token = rawpath + strlen(rawpath);

	/* loop until done */
	while (1)
	{
		/* allocate space for the new pointer */
		list->path = realloc((void *)list->path, (list->pathcount + 1) * sizeof(char *));
		assert_always(list->path != NULL, "Out of memory!");

		/* copy the path in */
		list->path[list->pathcount++] = copy_and_expand_variables(rawpath, token - rawpath);
#if VERBOSE
		printf("  %s\n", list->path[list->pathcount - 1]);
#endif

		/* if this was the end, break */
		if (*token == 0)
			break;
		rawpath = token + 1;

		/* find the next separator */
		token = strchr(rawpath, ':');
		if (!token)
			token = rawpath + strlen(rawpath);
	}

	/* when finished, reset the path info, so that future INI parsing 
	 * will cause us to get called again */
	free((void *)list->rawpath);
	list->rawpath = NULL;
	return;
}



/*============================================================ */
/*	free_pathlists */
/*============================================================ */

void free_pathlists(void)
{
	int i;

	for (i = 0; i < FILETYPE_end; i++)
	{
		pathdata *list = &pathlist[i];

		/* free any existing paths */
		if (list->pathcount != 0)
		{
			int pathindex;

			for (pathindex = 0; pathindex < list->pathcount; pathindex++)
				free((void *)list->path[pathindex]);
			free((void *)list->path);
		}

		/* by default, start with an empty list */
		list->path = NULL;
		list->pathcount = 0;
	}
}



/*============================================================ */
/*	get_path_for_filetype */
/*============================================================ */

static const char *get_path_for_filetype(int filetype, int pathindex, int *count)
{
	pathdata *list;

	/* handle aliasing of some paths */
	switch (filetype)
	{
#ifndef MESS
		case FILETYPE_IMAGE:
			list = &pathlist[FILETYPE_ROM];
			break;
#endif

		default:
			list = &pathlist[filetype];
			break;
	}

	/* if we don't have expanded paths, expand them now */
	if (list->pathcount == 0 || list->rawpath)
	{
		/* special hack for ROMs */
		if (list == &pathlist[FILETYPE_ROM] && rompath_extra)
		{
			/* this may leak a little memory, but it's a hack anyway! :-P */
			const char *rawpath = (list->rawpath) ? list->rawpath : "";
			char *newpath = malloc(strlen(rompath_extra) + strlen(rawpath) + 2);
			sprintf(newpath, "%s:%s", rompath_extra, rawpath);
			free((void *)list->rawpath);
			list->rawpath = newpath;
		}

		/* decompose the path */
		expand_pathlist(list);
	}

	/* set the count */
	if (count)
		*count = list->pathcount;

	/* return a valid path always */
	return (pathindex < list->pathcount) ? list->path[pathindex] : "";
}



/*============================================================ */
/*	compose_path */
/*============================================================ */

static void compose_path(char *output, size_t outputlen, int pathtype, int pathindex, const char *filename)
{
	const char *basepath = get_path_for_filetype(pathtype, pathindex, NULL);
	char *p;

#ifdef MESS
	if (osd_is_absolute_path(filename))
		basepath = NULL;
#endif

	/* compose the full path */
	*output = 0;
	if (basepath)
		strncat(output, basepath, outputlen - strlen(output) - 1);
	if (*output && !is_pathsep(output[strlen(output) - 1]))
		strncat(output, "/", outputlen - strlen(output) - 1);
	strncat(output, filename, outputlen - strlen(output) - 1);

	/* convert backslashes to forward slashes */
	for (p = output; *p; p++)
		if (*p == '\\')
			*p = '/';
}



/*============================================================ */
/*  get_last_fileerror */
/*============================================================ */

static osd_file_error get_last_fileerror(void)
{
	osd_file_error error;

	switch (errno)
	{
		case ENOMEM:
			error = FILEERR_OUT_OF_MEMORY;
			break;

		case ENOENT:
		case ENOTDIR:
			error = FILEERR_NOT_FOUND;
			break;

		case EACCES:
		case EAGAIN:
		case EFAULT:
		case EISDIR:
		case EROFS:
			error = FILEERR_ACCESS_DENIED;
			break;

		default:
			error = FILEERR_FAILURE;
			break;
	}
	return error;
}


/*============================================================ */
/*	osd_get_path_count */
/*============================================================ */

int osd_get_path_count(int pathtype)
{
	int count;

	/* get the count and return it */
	get_path_for_filetype(pathtype, 0, &count);
	return count;
}



/*============================================================ */
/*	osd_get_path_info */
/*============================================================ */

int osd_get_path_info(int pathtype, int pathindex, const char *filename)
{
	struct stat buf;
	char fullpath[1024];

	/* compose the full path */
	compose_path(fullpath, sizeof(fullpath), pathtype, pathindex, filename);

	/* get the file attributes */
	if (stat(fullpath, &buf))
		return PATH_NOT_FOUND;
#ifdef BSD43
	else if (S_IFDIR & buf.st_mode)
#else
	else if (S_ISDIR(buf.st_mode))
#endif
		return PATH_IS_DIRECTORY;
	else
		return PATH_IS_FILE;
}



/*============================================================ */
/*	osd_fopen */
/*============================================================ */

osd_file *osd_fopen(int pathtype, int pathindex, const char *filename,
		const char *mode, osd_file_error *error)
{
	char fullpath[1024];
	osd_file *file;
	int i;

	/* find an empty file pointer */
	for (i = 0; i < MAX_OPEN_FILES; i++)
		if (openfile[i].fileptr == NULL)
			break;
	if (i == MAX_OPEN_FILES)
		goto error;

	/* zap the file record */
	file = &openfile[i];
	memset(file, 0, sizeof(*file));

	/* compose the full path */
	compose_path(fullpath, sizeof(fullpath), pathtype, pathindex, filename);

	/* attempt to open the file */
	file->fileptr = fopen(fullpath, mode);
	if (file->fileptr == NULL)
	{
		/* if it's read-only, or if the path exists, then that's final */
		if (!(strchr(mode, 'w')) || errno != EACCES)
			goto error;

		/* create the path and try again */
		create_path(fullpath, TRUE);
		file->fileptr = fopen(fullpath, mode);

		/* if that doesn't work, we give up */
		if (file->fileptr == NULL)
			goto error;
	}

	/* get the file size */
	FSEEK(file->fileptr, 0, SEEK_END);
	file->end = FTELL(file->fileptr);
	rewind(file->fileptr);
	*error = FILEERR_SUCCESS;
	return file;

error:
	*error = get_last_fileerror();
	return NULL;
}



/*============================================================ */
/*	osd_fseek */
/*============================================================ */

int osd_fseek(osd_file *file, INT64 offset, int whence)
{
	/* convert the whence into method */
	switch (whence)
	{
		default:
		case SEEK_SET:
			file->offset = offset;
			break;
		case SEEK_CUR:
			file->offset += offset;
			break;
		case SEEK_END:
			file->offset = file->end + offset;
			break;
	}
	return 0;
}



/*============================================================ */
/*	osd_ftell */
/*============================================================ */

UINT64 osd_ftell(osd_file *file)
{
	return file->offset;
}



/*============================================================ */
/*	osd_feof */
/*============================================================ */

int osd_feof(osd_file *file)
{
	return (file->offset >= file->end);
}



/*============================================================ */
/*	osd_fread */
/*============================================================ */

UINT32 osd_fread(osd_file *file, void *buffer, UINT32 length)
{
	UINT32 bytes_left = length;
	int bytes_to_copy;
	int result;
	size_t read;

	/* handle data from within the buffer */
	if (file->offset >= file->bufferbase && file->offset < file->bufferbase + file->bufferbytes)
	{
		/* copy as much as we can */
		bytes_to_copy = file->bufferbase + file->bufferbytes - file->offset;
		if (bytes_to_copy > length)
			bytes_to_copy = length;
		memcpy(buffer, &file->buffer[file->offset - file->bufferbase], bytes_to_copy);

		/* account for it */
		bytes_left -= bytes_to_copy;
		file->offset += bytes_to_copy;
		buffer = (unsigned char *)buffer + bytes_to_copy;

		/* if that's it, we're done */
		if (bytes_left == 0)
			return length;
	}

	/* attempt to seek to the current location if we're not there already */
	if (file->offset != file->filepos)
	{
		result = FSEEK(file->fileptr, file->offset, SEEK_SET);
		if (result && errno)
		{
			file->filepos = ~(OFF_T)0;
			return length - bytes_left;
		}
		file->filepos = file->offset;
	}

	/* if we have a small read remaining, do it to the buffer and copy out the results */
	if (length < FILE_BUFFER_SIZE/2)
	{
		/* read as much of the buffer as we can */
		file->bufferbase = file->offset;
		file->bufferbytes = 0;
		file->bufferbytes = fread(file->buffer, sizeof(unsigned char), FILE_BUFFER_SIZE, file->fileptr);
		file->filepos += file->bufferbytes;

		/* copy it out */
		bytes_to_copy = bytes_left;
		if (bytes_to_copy > file->bufferbytes)
			bytes_to_copy = file->bufferbytes;
		memcpy(buffer, file->buffer, bytes_to_copy);

		/* adjust pointers and return */
		file->offset += bytes_to_copy;
		bytes_left -= bytes_to_copy;
		return length - bytes_left;
	}

	/* otherwise, just read directly to the buffer */
	else
	{
		/* do the read */
		read = fread(buffer, sizeof(unsigned char), bytes_left, file->fileptr);
		file->filepos += read;

		/* adjust the pointers and return */
		file->offset += read;
		bytes_left -= read;
		return length - bytes_left;
	}
}



/*============================================================ */
/*	osd_fwrite */
/*============================================================ */

UINT32 osd_fwrite(osd_file *file, const void *buffer, UINT32 length)
{
	int result;
	size_t written;

	/* invalidate any buffered data */
	file->bufferbytes = 0;

	/* attempt to seek to the current location */
	result = FSEEK(file->fileptr, file->offset, SEEK_SET);
	if (result && errno)
		return 0;

	/* do the write */
	written = fwrite(buffer, sizeof(unsigned char), length, file->fileptr);
	file->filepos += written;

	/* adjust the pointers */
	file->offset += written;
	if (file->offset > file->end)
		file->end = file->offset;
	return written;
}



/*============================================================ */
/*	osd_fclose */
/*============================================================ */

void osd_fclose(osd_file *file)
{
	/* close the handle and clear it out */
	if (file->fileptr)
		fclose(file->fileptr);
	file->fileptr = NULL;
}



/*============================================================ */
/*	osd_create_directory */
/*============================================================ */

int osd_create_directory(int pathtype, int pathindex, const char *dirname)
{
	char fullpath[1024];

	/* compose the full path */
	compose_path(fullpath, sizeof(fullpath), pathtype, pathindex, dirname);

	return create_path(fullpath, FALSE);
}
