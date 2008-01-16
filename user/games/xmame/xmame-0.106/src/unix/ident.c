#include "xmame.h"
#include "audit.h"
#include "unzip.h"
#include "driver.h"
#include "hash.h"
#include "jedparse.h"
#include <dirent.h>

#ifdef BSD43 /* old style directory handling */
#include <sys/types.h>
#include <sys/dir.h>
#define dirent direct
#endif

unsigned int crc32 (unsigned int crc, const unsigned char *buf, unsigned int len);
void romident(const char* name);

#define KNOWN_START 0
#define KNOWN_ALL   1
#define KNOWN_NONE  2
#define KNOWN_SOME  3

static int silentident = 0;
static int knownstatus = KNOWN_START;
static int ident = 0;
static int identfiles = 0;
static int identmatches = 0;
static int identnonroms = 0;

enum { IDENT_IDENT = 1, IDENT_ISKNOWN };

struct rc_option frontend_ident_opts[] =
{
   /* name, shortname, type, dest, deflt, min, max, func, help */
   { "Rom Identification Related", NULL,	rc_seperator,	NULL,
     NULL,		0,			0,		NULL,
     NULL },
   { "ident",		"id",			rc_set_int,	&ident,
     NULL,		IDENT_IDENT,		0,		NULL,
     "Identify unknown romdump, or unknown romdumps in dir/zip" },
   { "isknown",		"ik",			rc_set_int,	&ident,
     NULL,		IDENT_ISKNOWN,		0,		NULL,
     "Check if romdump or romdumps in dir/zip are known"} ,
   { NULL,		NULL,			rc_end,		NULL,
     NULL,		0,			0,		NULL,
     NULL }
};


/*-------------------------------------------------
    match_roms - scan for a matching ROM by hash
-------------------------------------------------*/

static void match_roms(const game_driver *driver, const char *hash, int length, int *found)
{
	const rom_entry *region, *rom;

	/* iterate over regions and files within the region */
	for (region = rom_first_region(driver); region; region = rom_next_region(region))
		for (rom = rom_first_file(region); rom; rom = rom_next_file(rom))
			if (hash_data_is_equal(hash, ROM_GETHASHDATA(rom), 0))
			{
				int baddump = hash_data_has_info(ROM_GETHASHDATA(rom), HASH_INFO_BAD_DUMP);

				if (!silentident)
				{
					if (*found != 0)
						fprintf(stdout_file, "             ");
					fprintf(stdout_file, "= %s%-12s  %s\n", baddump ? "(BAD) " : "", ROM_GETNAME(rom), driver->description);
				}
				(*found)++;
			}
}


/*-------------------------------------------------
    identify_data - identify a buffer full of
    data; if it comes from a .JED file, parse the
    fusemap into raw data first
-------------------------------------------------*/

void identify_data(const char *name, const UINT8 *data, int length)
{
	int namelen = strlen(name);
	char hash[HASH_BUF_SIZE];
	UINT8 *tempjed = NULL;
	int found = 0;
	jed_data jed;
	int i;

	/* if this is a '.jed' file, process it into raw bits first */
	if (namelen > 4 && name[namelen - 4] == '.' &&
		tolower(name[namelen - 3]) == 'j' &&
		tolower(name[namelen - 2]) == 'e' &&
		tolower(name[namelen - 1]) == 'd' &&
		jed_parse(data, length, &jed) == JEDERR_NONE)
	{
		/* now determine the new data length and allocate temporary memory for it */
		length = jedbin_output(&jed, NULL, 0);
		tempjed = malloc(length);
		if (!tempjed)
			return;

		/* create a binary output of the JED data and use that instead */
		jedbin_output(&jed, tempjed, length);
		data = tempjed;
	}

	/* compute the hash of the data */
	hash_data_clear(hash);
	hash_compute(hash, data, length, HASH_SHA1 | HASH_CRC);

	/* remove directory portion of the name */
	for (i = namelen - 1; i > 0; i--)
		if (name[i] == '/' || name[i] == '\\')
		{
			i++;
			break;
		}

	/* output the name */
	identfiles++;
	if (!silentident)
		fprintf(stdout_file, "%s ", &name[i]);

	/* see if we can find a match in the ROMs */
	for (i = 0; drivers[i]; i++)
		match_roms(drivers[i], hash, length, &found);

	/* if we didn't find it, try to guess what it might be */
	if (found == 0)
	{
		/* if not a power of 2, assume it is a non-ROM file */
		if ((length & (length - 1)) != 0)
		{
			if (!silentident)
				fprintf(stdout_file, "NOT A ROM\n");
			identnonroms++;
		}

		/* otherwise, it's just not a match */
		else
		{
			if (!silentident)
				fprintf(stdout_file, "NO MATCH\n");
			if (knownstatus == KNOWN_START)
				knownstatus = KNOWN_NONE;
			else if (knownstatus == KNOWN_ALL)
				knownstatus = KNOWN_SOME;
		}
	}

	/* if we did find it, count it as a match */
	else
	{
		identmatches++;
		if (knownstatus == KNOWN_START)
			knownstatus = KNOWN_ALL;
		else if (knownstatus == KNOWN_NONE)
			knownstatus = KNOWN_SOME;
	}

	/* free any temporary JED data */
	if (tempjed)
		free(tempjed);
}


/*-------------------------------------------------
    identify_file - identify a file; if it is a
    ZIP file, scan it and identify all enclosed
    files
-------------------------------------------------*/

void identify_file(const char *name)
{
	int namelen = strlen(name);
	int length;
	FILE *f;

	/* if the file has a 3-character extension, check it */
	if (namelen > 4 && name[namelen - 4] == '.' &&
		tolower(name[namelen - 3]) == 'z' &&
		tolower(name[namelen - 2]) == 'i' &&
		tolower(name[namelen - 1]) == 'p')
	{
		/* first attempt to examine it as a valid ZIP file */
		zip_file *zip = openzip(FILETYPE_RAW, 0, name);
		if (zip != NULL)
		{
			zip_entry *entry;

			/* loop over entries in the ZIP, skipping empty files and directories */
			for (entry = readzip(zip); entry; entry = readzip(zip))
				if (entry->uncompressed_size != 0)
				{
					UINT8 *data = (UINT8 *)malloc(entry->uncompressed_size);
					if (data != NULL)
					{
						readuncompresszip(zip, entry, (char *)data);
						identify_data(entry->name, data, entry->uncompressed_size);
						free(data);
					}
				}

			/* close up and exit early */
			closezip(zip);
			return;
		}
	}

	/* open the file directly */
	f = fopen(name, "rb");
	if (f)
	{
		/* determine the length of the file */
		fseek(f, 0, SEEK_END);
		length = ftell(f);
		fseek(f, 0, SEEK_SET);

		/* skip empty files */
		if (length != 0)
		{
			UINT8 *data = (UINT8 *)malloc(length);
			if (data != NULL)
			{
				fread(data, 1, length, f);
				identify_data(name, data, length);
				free(data);
			}
		}
		fclose(f);
	}
}


/*-------------------------------------------------
    identify_dir - scan a directory and identify
    all the files in it
-------------------------------------------------*/

void identify_dir(const char* dirname)
{
	DIR *dir;
	struct dirent *ent;

	dir = opendir(dirname);
	if (!dir)
		return;

	ent = readdir(dir);
	while (ent)
	{
		/* Skip special files */
		if (ent->d_name[0] != '.')
		{
			char* buf = (char*)malloc(strlen(dirname) + 1 + strlen(ent->d_name) + 1);
			sprintf(buf, "%s/%s", dirname, ent->d_name);
			identify_file(buf);
			free(buf);
		}

		ent = readdir(dir);
	}
	closedir(dir);
}

void romident(const char* name)
{
	struct stat s;

	if (stat(name, &s) != 0)
	{
		fprintf(stdout_file, "%s: %s\n", name, strerror(errno));
		return;
	}

#ifdef BSD43
	if (S_IFDIR & s.st_mode)
#else
	if (S_ISDIR(s.st_mode))
#endif
		identify_dir(name);
	else
		identify_file(name);
}

int frontend_ident(const char *gamename)
{
	if (!ident)
		return 1234;

	if (!gamename)
	{
		fprintf(stderr_file, "-ident / -isknown requires a game- or filename as second argument\n");
		return OSD_NOT_OK;
	}

	if (ident == IDENT_ISKNOWN)
		silentident = 1;

	romident(gamename);

	if (ident == IDENT_ISKNOWN)
	{
		switch (knownstatus)
		{
			case KNOWN_START: fprintf(stdout_file, "ERROR     %s\n",gamename); break;
			case KNOWN_ALL:   fprintf(stdout_file, "KNOWN     %s\n",gamename); break;
			case KNOWN_NONE:  fprintf(stdout_file, "UNKNOWN   %s\n",gamename); break;
			case KNOWN_SOME:  fprintf(stdout_file, "PARTKNOWN %s\n",gamename); break;
		}
	}
	return OSD_OK;
}
