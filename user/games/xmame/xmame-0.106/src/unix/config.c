/*
 * X-mame config-file and commandline parsing
 * We don't use stderr_file resp stdout_file in here since we don't know if 
 * it's valid yet.
 */

#define __CONFIG_C_
#include <time.h>
#include "xmame.h"
#include "fileio.h"
#include "driver.h"
#include "audit.h"
#include "sysdep/sysdep_dsp.h"
#include "sysdep/sysdep_mixer.h"
#include "sysdep/misc.h"

/* be sure that device names are nullified */
extern void XInput_trackballs_reset();

/* from ... */
extern char *cheatfile;
extern char *db_filename;

extern char *playbackname;
extern char *recordname;

/* some local vars */
static int showconfig = 0;
static int showmanusage = 0;
static int showversion = 0;
static int showusage  = 0;
static int validate = 0;
static int loadconfig = 1;
static char *language = NULL;
static char *gamename = NULL;
static char *statename = NULL;
char *rompath_extra = NULL;
#ifndef MESS
static char *defaultgamename;
#else
static const char *mess_opts;
#endif

static int got_gamename;

static int config_handle_arg(char *arg);
#ifdef MAME_DEBUG
static int config_handle_debug_size(struct rc_option *option, const char *arg,
		int priority);
#endif
void show_usage(void);

#ifdef MESS
static int specify_ram(struct rc_option *option, const char *arg, int priority);
static void add_mess_device_options(struct rc_struct *rc, const game_driver *gamedrv);
#endif

/* OpenVMS doesn't support paths with a leading '.' character. */
#if defined(__DECC) && defined(VMS)
#  define PATH_LEADER
#else
#  define PATH_LEADER "."
#endif

/* struct definitions */
static struct rc_option opts1[] = {
   /* name, shortname, type, dest, deflt, min, max, func, help */
	{ NULL, NULL, rc_link, video_opts, NULL, 0, 0, NULL, NULL },
	{ NULL, NULL, rc_link, input_opts, NULL, 0, 0, NULL, NULL },
	{ NULL, NULL, rc_link, sound_opts, NULL, 0, 0, NULL, NULL },
	{ NULL, NULL, rc_end, NULL, NULL, 0, 0, NULL, NULL }
};

static struct rc_option opts2[] = {
   /* name, shortname, type, dest, deflt, min, max, func, help */
	{ NULL, NULL, rc_link, network_opts, NULL, 0, 0, NULL, NULL },
	{ NULL, NULL, rc_link, fileio_opts, NULL, 0, 0, NULL, NULL },
#ifdef MESS
	/* FIXME - these option->names should NOT be hardcoded! */
	{ "MESS specific options", NULL, rc_seperator, NULL, NULL, 0, 0, NULL, NULL },
	{ "ramsize", "ram", rc_string, &mess_opts, NULL, 0, 0, specify_ram, "Specifies size of RAM (if supported by driver)" },
#else
	{ "MAME Related", NULL, rc_seperator, NULL, NULL, 0, 0, NULL, NULL },
	{ "defaultgame", "def", rc_string, &defaultgamename, "robby", 0, 0, NULL, "Set the default game started when no game is given on the command line (only useful in the config files)" },
#endif
	{ "language", "lang", rc_string, &language, "english", 0, 0, NULL, "Select the language for the menus and osd" },
	{ "cheat", "c", rc_bool, &options.cheat, "0", 0, 0, NULL, "Enable/disable cheat subsystem" },
	{ "skip_gameinfo", NULL, rc_bool, &options.skip_gameinfo, "0", 0, 0, NULL, "Skip displaying the game info screen" },
#ifdef MESS
	{ "skip_warnings", NULL, rc_bool, &options.skip_warnings, "0", 0, 0, NULL, "Skip displaying the warnings screen" },
#endif
	{ "validate", "valid", rc_bool, &validate, "0", 0, 0, NULL, "Validate all game drivers" },
	{ "bios", NULL, rc_string, &options.bios, "default", 0, 14, NULL, "Change system bios" },
	{ "state", NULL, rc_string, &statename, NULL, 0, 0, NULL, "state to load" },
	{ "autosave", NULL, rc_bool, &options.auto_save, "0", 0, 0, NULL, "Enable automatic restore at startup and save at exit" },
#ifdef MAME_DEBUG
	{ "debug", "d", rc_bool, &options.mame_debug, NULL, 0, 0, NULL, "Enable/disable debugger" },
	{ "debug-size", "ds", rc_use_function, NULL, "640x480", 0, 0, config_handle_debug_size, "Specify the resolution/window size to use for the debugger (window) in the form of XRESxYRES (minimum size = 640x480)" },
#endif
	{ NULL, NULL, rc_link, frontend_list_opts, NULL, 0, 0, NULL, NULL },
	{ NULL, NULL, rc_link, frontend_ident_opts, NULL, 0, 0, NULL, NULL },
	{ "General Options", NULL, rc_seperator, NULL, NULL, 0, 0, NULL, NULL },
	{ "loadconfig", "lcf", rc_bool, &loadconfig, "1", 0, 0, NULL, "Load (don't load) configfiles" },
	{ "showconfig", "sc", rc_set_int, &showconfig, NULL, 1, 0, NULL, "Display running parameters in rc style" },
	{ "manhelp", "mh", rc_set_int, &showmanusage, NULL, 1, 0, NULL, "Print commandline help in man format, useful for manpage creation" },
	{ "version", "V", rc_set_int, &showversion, NULL, 1, 0, NULL, "Display version" },
	{ "help", "?", rc_set_int, &showusage, NULL, 1, 0, NULL, "Show this help" },
	{ NULL, NULL, rc_end, NULL, NULL, 0, 0, NULL, NULL }
};

/*
 * Penalty string compare, the result _should_ be a measure on
 * how "close" two strings ressemble each other.
 * The implementation is way too simple, but it sort of suits the
 * purpose.
 * This used to be called fuzzy matching, but there's no randomness
 * involved and it is in fact a penalty method.
 */

int penalty_compare (const char *s, const char *l)
{
	int gaps = 0;
	int match = 0;
	int last = 1;

	for (; *s && *l; l++)
	{
		if (*s == *l)
			match = 1;
		else if (*s >= 'a' && *s <= 'z' && (*s - 'a') == (*l - 'A'))
			match = 1;
		else if (*s >= 'A' && *s <= 'Z' && (*s - 'A') == (*l - 'a'))
			match = 1;
		else
			match = 0;

		if (match)
			s++;

		if (match != last)
		{
			last = match;
			if (!match)
				gaps++;
		}
	}

	/* penalty if short string does not completely fit in */
	for (; *s; s++)
		gaps++;

	return gaps;
}

/*
 * We compare the game name given on the CLI against the long and
 * the short game names supported
 */
void show_approx_matches(void)
{
	struct { int penalty; int index; } topten[10];
	int i,j;
	int penalty; /* best fuzz factor so far */

	for (i = 0; i < 10; i++)
	{
		topten[i].penalty = 9999;
		topten[i].index = -1;
	}

	for (i = 0; (drivers[i] != 0); i++)
	{
		int tmp;

		if ((drivers[i]->flags & NOT_A_DRIVER) != 0)
			continue;

		penalty = penalty_compare (gamename, drivers[i]->description);
		tmp = penalty_compare (gamename, drivers[i]->name);
		if (tmp < penalty) penalty = tmp;

		/* eventually insert into table of approximate matches */
		for (j = 0; j < 10; j++)
		{
			if (penalty >= topten[j].penalty) break;
			if (j > 0)
			{
				topten[j-1].penalty = topten[j].penalty;
				topten[j-1].index = topten[j].index;
			}
			topten[j].index = i;
			topten[j].penalty = penalty;
		}
	}

	for (i = 9; i >= 0; i--)
	{
		if (topten[i].index != -1)
			fprintf (stderr, "%-10s%s\n", drivers[topten[i].index]->name, drivers[topten[i].index]->description);
	}
}

#ifndef MESS
/* for verify roms which is used for the random game selection */
static int config_printf(const char *fmt, ...)
{
	return 0;
}
#endif

static int config_handle_arg(char *arg)
{
	int i;

	/* notice: for MESS game means system */
	if (got_gamename)
	{
		fprintf(stderr, "error: duplicate gamename: %s\n", arg);
		return -1;
	}

	rompath_extra = osd_dirname(arg);

	if (rompath_extra && !strlen(rompath_extra))
	{
		free(rompath_extra);
		rompath_extra = NULL;
	}

	gamename = arg;

	/* do we have a driver for this? */
	for (i = 0; drivers[i]; i++)
	{
		if (mame_stricmp(gamename, drivers[i]->name) == 0)
		{
			game_index = i;
			break;
		}
	}

#ifdef MESS
	if (game_index >= 0)
		add_mess_device_options(rc, drivers[game_index]);
#endif /* MESS */

	got_gamename = 1;
	return 0;
}

#ifdef MAME_DEBUG
static int config_handle_debug_size(struct rc_option *option, const char *arg,
		int priority)
{
	int width, height;

	if (sscanf(arg, "%dx%d", &width, &height) == 2)
	{
		if((width >= 640) && (height >= 480))
		{
			options.debug_width  = width;
			options.debug_height = height;
			return 0;
		}
	}
	fprintf(stderr,
			"error: invalid debugger size or too small (minimum size = 640x480): \"%s\".\n",
			arg);
	return -1;
}
#endif /* MAME_DEBUG */

#ifdef MESS
int xmess_printf_output(const char *fmt, va_list arg)
{
	return vfprintf(stderr_file, fmt, arg);
}
#endif /* MESS */

/*
 * get configuration from configfile and env.
 */
int xmame_config_init(int argc, char *argv[])
{
	char buffer[BUF_SIZE];
	unsigned char lsb_test[2] = {0, 1};
	int i;

	memset(&options,0,sizeof(options));

	/* Let's see if the endianess of this arch is correct; otherwise,
	   YELL about it and bail out. */
#ifdef LSB_FIRST
	if(*((unsigned short*)lsb_test) != 0x0100)
#else	
	if(*((unsigned short*)lsb_test) != 0x0001)
#endif
	{
		fprintf(stderr, "error: compiled byte ordering doesn't match machine byte ordering.\n"
#ifdef LSB_FIRST
				"compiled for LSB first, are you sure you chose the right cpu in makefile.unix?\n");
#else
				"compiled for MSB first, are you sure you chose the right cpu in makefile.unix?\n");
#endif
		return OSD_NOT_OK;
	}

	/* some settings which are static for xmame and thus aren't controlled 
	   by options */
	options.gui_host = 1;
	cheatfile = NULL;
	db_filename = NULL;

	/* create the rc object */
	if (!(rc = rc_create()))
		return OSD_NOT_OK;

	if(rc_register(rc, opts1))
		return OSD_NOT_OK;

	if(sysdep_dsp_init(rc, NULL))
		return OSD_NOT_OK;

	if(sysdep_mixer_init(rc, NULL))
		return OSD_NOT_OK;

	if(rc_register(rc, opts2))
		return OSD_NOT_OK;

	/* get the homedir */
	if(!(home_dir = get_home_dir()))
		return OSD_NOT_OK;

	/* check that the required dirs exist, and create them if necessary */
	snprintf(buffer, BUF_SIZE, "%s/"PATH_LEADER"%s", home_dir, NAME);
	if (check_and_create_dir(buffer))
		return OSD_NOT_OK;

	snprintf(buffer, BUF_SIZE, "%s/"PATH_LEADER"%s/%s", home_dir, NAME, "cfg");
	if (check_and_create_dir(buffer))
		return OSD_NOT_OK;

	snprintf(buffer, BUF_SIZE, "%s/"PATH_LEADER"%s/%s", home_dir, NAME, "mem");
	if (check_and_create_dir(buffer))
		return OSD_NOT_OK;

	snprintf(buffer, BUF_SIZE, "%s/"PATH_LEADER"%s/%s", home_dir, NAME, "sta");
	if (check_and_create_dir(buffer))
		return OSD_NOT_OK;

	snprintf(buffer, BUF_SIZE, "%s/"PATH_LEADER"%s/%s", home_dir, NAME, "nvram");
	if (check_and_create_dir(buffer))
		return OSD_NOT_OK;

	snprintf(buffer, BUF_SIZE, "%s/"PATH_LEADER"%s/%s", home_dir, NAME, "diff");
	if (check_and_create_dir(buffer))
		return OSD_NOT_OK;

	snprintf(buffer, BUF_SIZE, "%s/"PATH_LEADER"%s/%s", home_dir, NAME, "rc");
	if (check_and_create_dir(buffer))
		return OSD_NOT_OK;

	snprintf(buffer, BUF_SIZE, "%s/"PATH_LEADER"%s/%s", home_dir, NAME, "hi");
	if (check_and_create_dir(buffer))
		return OSD_NOT_OK;

	snprintf(buffer, BUF_SIZE, "%s/"PATH_LEADER"%s/%s", home_dir, NAME, "inp");
	if (check_and_create_dir(buffer))
		return OSD_NOT_OK;

	/* parse the commandline */
	got_gamename = 0;
	if (rc_parse_commandline(rc, argc, argv, 2, config_handle_arg))
		return OSD_NOT_OK;

	if (validate)
	{
		extern int mame_validitychecks(int game);
		cpuintrf_init();
		sndintrf_init();
		exit(mame_validitychecks(-1));
	}

	if (showmanusage)
	{
		rc_print_man_options(rc, stdout);
		return OSD_OK;
	}

	if (showversion)
	{
		fprintf(stdout, "%s\n", title);
		return OSD_OK;
	}

	if (showusage)
	{
		show_usage();
		return OSD_OK;
	}

	/* parse the various configfiles, starting with the one with the
	   lowest priority */
	if(loadconfig)
	{
		snprintf(buffer, BUF_SIZE, "%s/%src", SYSCONFDIR, NAME);
		if(rc_load(rc, buffer, 1, 1))
			return OSD_NOT_OK;
		snprintf(buffer, BUF_SIZE, "%s/"PATH_LEADER"%s/%src", home_dir, NAME, NAME);
		if(rc_load(rc, buffer, 1, 1))
			return OSD_NOT_OK;
		snprintf(buffer, BUF_SIZE, "%s/%s-%src", SYSCONFDIR, NAME, DISPLAY_METHOD);
		if(rc_load(rc, buffer, 1, 1))
			return OSD_NOT_OK;
		snprintf(buffer, BUF_SIZE, "%s/"PATH_LEADER"%s/%s-%src", home_dir, NAME, NAME,
				DISPLAY_METHOD);
		if(rc_load(rc, buffer, 1, 1))
			return OSD_NOT_OK;
	}

	/* setup stderr_file and stdout_file */
	if (!stderr_file)
		stderr_file = stderr;
	if (!stdout_file)
		stdout_file = stdout;

	if (showconfig)
	{
		rc_write(rc, stdout_file, NAME" running parameters");
		return OSD_OK;
	}

	/* handle frontend options */
	if ((i = frontend_list(gamename)) != 1234)
		return i;

	if ((i = frontend_ident(gamename)) != 1234)
		return i;

	if (playbackname)
	{
		options.playback = mame_fopen(playbackname, 0, FILETYPE_INPUTLOG, 0);
		if (!options.playback)
			fatalerror("failed to open %s for playback\n", playbackname);
	}

	/* check for game name embedded in .inp header */
	if (options.playback)
	{
		inp_header inp_header;

		/* read playback header */
		mame_fread(options.playback, &inp_header, sizeof(inp_header));

		if (!isalnum(inp_header.name[0])) /* If first byte is not alpha-numeric */
			mame_fseek(options.playback, 0, SEEK_SET); /* old .inp file - no header */
		else
		{
			for (i = 0; (drivers[i] != 0); i++) /* find game and play it */
			{
				if (strcmp(drivers[i]->name, inp_header.name) == 0)
				{
					game_index = i;
					gamename = (char *)drivers[i]->name;
					printf("Playing back previously recorded game %s (%s) [press return]\n",
							drivers[game_index]->name,drivers[game_index]->description);
					getchar();
					break;
				}
			}
		}
	}

	/* handle the game selection */
	game_index = -1;

	if (!gamename)
#ifdef MESS
	{
		show_usage();
		return OSD_NOT_OK;
	}
#else
	gamename = defaultgamename;

	/* random game? */
	if (strcasecmp(gamename, "random") == 0)
	{
		for (i=0; drivers[i]; i++) ; /* count available drivers */

		srand(time(NULL));

		for(;;)
		{
			game_index = (float)rand()*i/RAND_MAX;

			fprintf(stdout_file, "Random game selected: %s (%s)\n  verifying roms... ",drivers[game_index]->name,drivers[game_index]->description);
			if(audit_verify_roms (game_index, (verify_printf_proc)config_printf) == CORRECT)
			{
				fprintf(stdout_file, "OK\n");
				break;
			}
			else
				fprintf(stdout_file, "FAILED\n");
		}
	}
	else
#endif
		/* do we have a driver for this? */
#ifdef MESS
		for (i = 0; drivers[i]; i++)
		{
			if (strcasecmp(gamename,drivers[i]->name) == 0)
			{
				game_index = i;
				break;
			}
		}
#else
	{
		char *begin = strrchr(gamename, '/'), *end;
		int len;

		if (begin == 0)
			begin = gamename;
		else
			begin++;

		end = strchr(begin, '.');
		if (end == 0)
			len = strlen(begin);
		else
			len = end - begin;            

		for (i = 0; drivers[i]; i++)
		{
			if (strncasecmp(begin, drivers[i]->name, len) == 0 
					&& len == strlen(drivers[i]->name))
			{
				begin = strrchr(gamename,'/');
				if (begin)
				{
					*begin='\0'; /* dynamic allocation and copying will be better */
					rompath_extra = malloc(strlen(gamename) + 1);
					strcpy(rompath_extra, gamename);
				}
				game_index = i;
				break;
			}
		}
	}
#endif

	/* we give up. print a few approximate matches */
	if (game_index == -1)
	{
		fprintf(stderr_file, "\n\"%s\" approximately matches the following\n"
				"supported " GAMESNOUN " (best match first):\n\n", gamename);
		show_approx_matches();
		exit(1);
	}

	/* now that we've got the gamename parse the game specific configfile */
	if (loadconfig)
	{
		snprintf(buffer, BUF_SIZE, "%s/rc/%src", SYSCONFDIR,
				drivers[game_index]->name);
		if(rc_load(rc, buffer, 1, 1))
			return OSD_NOT_OK;
		snprintf(buffer, BUF_SIZE, "%s/"PATH_LEADER"%s/rc/%src", home_dir, NAME,
				drivers[game_index]->name);
		if(rc_load(rc, buffer, 1, 1))
			return OSD_NOT_OK;
	}

	if (recordname)
	{
		options.record = mame_fopen(recordname, 0, FILETYPE_INPUTLOG, 1);
		if (!options.record)
			fatalerror("failed to open %s for recording\n", recordname);
	}

	if (options.record)
	{
		inp_header inp_header;

		memset(&inp_header, '\0', sizeof(inp_header));
		strncpy(inp_header.name, drivers[game_index]->name, sizeof(inp_header.name) - 1);
		mame_fwrite(options.record, &inp_header, sizeof(inp_header));
	}

	if (statename)
		options.savegame = statename;

	if (language)
		options.language_file = mame_fopen(0, language, FILETYPE_LANGUAGE,0);

	/* setup ui orientation */
	options.ui_orientation = drivers[game_index]->flags & ORIENTATION_MASK;

	if (options.ui_orientation & ORIENTATION_SWAP_XY)
	{
		/* if only one of the components is inverted, switch them */
		if ((options.ui_orientation & ROT180) == ORIENTATION_FLIP_X ||
				(options.ui_orientation & ROT180) == ORIENTATION_FLIP_Y)
			options.ui_orientation ^= ROT180;
	}

	return 1234;
}

void xmame_config_exit(void)
{
	gamename = NULL;

	if(rc)
	{
		sysdep_mixer_exit();
		sysdep_dsp_exit();
		rc_destroy(rc);
		rc = NULL;
	}

	free(home_dir);
	home_dir = NULL;

	/* close open files */
	if (options.logfile)
	{
		mame_fclose(options.logfile);
		options.logfile = NULL;
	}

	if (options.playback)
	{
		mame_fclose(options.playback);
		options.playback = NULL;
	}

	if (options.record)
	{
		mame_fclose(options.record);
		options.record = NULL;
	}

	if (options.language_file)
	{
		mame_fclose(options.language_file);
		options.language_file = NULL;
	}
}

/* 
 * show help and exit
 */
void show_usage(void) 
{
	/* header */
	fprintf(stdout, 
#ifdef MESS
			"Usage: xmess <system> [game] [options]\n"
#else
			"Usage: xmame [game] [options]\n"
#endif 
			"Options:\n");

	/* actual help message */
	rc_print_help(rc, stdout);

	/* footer */
	fprintf(stdout, "\nFiles:\n\n");
	fprintf(stdout, "Config Files are parsed in the following order:\n");
	fprint_columns(stdout, SYSCONFDIR"/"NAME"rc",
			"Global configuration config file");
	fprint_columns(stdout, "${HOME}/."NAME"/"NAME"rc",
			"User configuration config file");
	fprint_columns(stdout, SYSCONFDIR"/"NAME"-"DISPLAY_METHOD"rc",
			"Global per display method config file");
	fprint_columns(stdout, "${HOME}/."NAME"/"NAME"-"DISPLAY_METHOD"rc",
			"User per display method config file");
	fprint_columns(stdout, SYSCONFDIR"/rc/<game>rc",
			"Global per game config file");
	fprint_columns(stdout, "${HOME}/."NAME"/rc/<game>rc",
			"User per game config file");
	/*  fprintf(stdout, "\nEnvironment variables:\n\n");
	    fprint_columns(stdout, "ROMPATH", "Rom search path"); */
	fprintf(stdout, "\n"
#ifdef MESS
			"M.E.S.S. - Multi-Emulator Super System\n"
			"Copyright (C) 1998-2006 by the MESS team\n"
#else
			"M.A.M.E. - Multiple Arcade Machine Emulator\n"
			"Copyright (C) 1997-2006 by Nicola Salmoria and the MAME Team\n"
#endif
			"%s port maintained by Lawrence Gold\n", NAME);
}

#ifdef MESS

static int specify_ram(struct rc_option *option, const char *arg, int priority)
{
	UINT32 specified_ram = 0;

	if (strcmp(arg, "0"))
	{
		specified_ram = ram_parse_string(arg);
		if (specified_ram == 0)
		{
			fprintf(stderr, "Cannot recognize the RAM option %s; aborting\n", arg);
			return -1;
		}
	}
	options.ram = specified_ram;
	return 0;
}



/*============================================================ */
/*	Device options */
/*============================================================ */

struct device_rc_option
{
	/* options for the RC system */
	struct rc_option opts[2];

	/* device information */
	iodevice_t devtype;
	const char *tag;
	int index;

	/* mounted file */
	char *filename;
};

struct device_type_options
{
	int count;
	struct device_rc_option *opts[MAX_DEV_INSTANCES];
};

struct device_type_options *device_options;



static int add_device(struct rc_option *option, const char *arg, int priority)
{
	struct device_rc_option *dev_option = (struct device_rc_option *) option;

	/* the user specified a device type */
	options.image_files[options.image_count].device_type = dev_option->devtype;
	options.image_files[options.image_count].device_tag = dev_option->tag;
	options.image_files[options.image_count].device_index = dev_option->index;
	options.image_files[options.image_count].name = auto_strdup(arg);
	options.image_count++;

	return 0;
}



static void add_mess_device_options(struct rc_struct *rc, const game_driver *gamedrv)
{
	struct SystemConfigurationParamBlock cfg;
	device_getinfo_handler handlers[64];
	int count_overrides[sizeof(handlers) / sizeof(handlers[0])];
	device_class devclass;
	iodevice_t devtype;
	int dev_count, dev, id, count;
	struct device_rc_option *dev_option;
	struct rc_option *opts;
	const char *dev_name;
	const char *dev_short_name;
	const char *dev_tag;

	/* retrieve getinfo handlers */
	memset(&cfg, 0, sizeof(cfg));
	memset(handlers, 0, sizeof(handlers));
	cfg.device_slotcount = sizeof(handlers) / sizeof(handlers[0]);
	cfg.device_handlers = handlers;
	cfg.device_countoverrides = count_overrides;
	if (gamedrv->sysconfig_ctor)
		gamedrv->sysconfig_ctor(&cfg);

	/* count devides */
	for (dev_count = 0; handlers[dev_count]; dev_count++)
		;

	if (dev_count > 0)
	{
		/* add a separator */
		opts = auto_malloc(sizeof(*opts) * 2);
		memset(opts, 0, sizeof(*opts) * 2);
		opts[0].name = "MESS devices";
		opts[0].type = rc_seperator;
		opts[1].type = rc_end;
		rc_register(rc, opts);

		/* we need to save all options */
		device_options = auto_malloc(sizeof(*device_options) * dev_count);
		memset(device_options, 0, sizeof(*device_options) * dev_count);

		/* list all options */
		for (dev = 0; dev < dev_count; dev++)
		{
			devclass.gamedrv = gamedrv;
			devclass.get_info = handlers[dev];

			/* retrieve info about the device */
			devtype = (iodevice_t) (int) device_get_info_int(&devclass, DEVINFO_INT_TYPE);
			count = (int) device_get_info_int(&devclass, DEVINFO_INT_COUNT);
			dev_tag = device_get_info_string(&devclass, DEVINFO_STR_DEV_TAG);
			if (dev_tag)
				dev_tag = auto_strdup(dev_tag);

			device_options[dev].count = count;

			for (id = 0; id < count; id++)
			{
				/* retrieve info about the device instance */
				dev_name = device_instancename(&devclass, id);
				dev_short_name = device_briefinstancename(&devclass, id);

				/* dynamically allocate the option */
				dev_option = auto_malloc(sizeof(*dev_option));
				memset(dev_option, 0, sizeof(*dev_option));

				/* populate the options */
				dev_option->opts[0].name = auto_strdup(dev_name);
				dev_option->opts[0].shortname = auto_strdup(dev_short_name);
				dev_option->opts[0].type = rc_string;
				dev_option->opts[0].func = add_device;
				dev_option->opts[0].dest = &dev_option->filename;
				dev_option->opts[1].type = rc_end;
				dev_option->devtype = devtype;
				dev_option->tag = dev_tag;
				dev_option->index = id;

				/* register these options */
				device_options[dev].opts[id] = dev_option;
				rc_register(rc, dev_option->opts);
			}
		}
	}
}

void osd_begin_final_unloading(void)
{
}

#endif
