/****************************************************************************
 ** ircat.c *****************************************************************
 ****************************************************************************
 *
 * ircat - prints config strings to standard output, can be used to
 * provide remote control input to scripts
 *
 * The first agrument to the program is the program name, as it
 * appears in the prog entries in .lircrc.
 *
 * For example if .lircrc contains:
 *
 * begin
 * 	prog = myprog
 * 	button = tv_p+
 * 	config = next_file
 * end
 *
 * then
 *
 * $ ircat myprog
 *
 * will print "next_file" (followed by newline) every time the
 * button tv_p+ is pressed.
 *
 *
 * Copyright (C) 2002 Bjorn Bringert <bjorn@bringert.net>
 *
 * Based on irexec.c
 *
 */


#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <errno.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "lirc_client.h"

#define PROG_NAME "ircat"
#define PROG_VERSION PROG_NAME " " VERSION


void print_usage (char *prog_name)
{
	printf("Usage: %s [options] <prog>\n", prog_name);
	printf("\t -h --help\t\tdisplay usage summary\n");
	printf("\t -v --version\t\tdisplay version\n");
	printf("\t -c --config=<file>\tset config file\n");
}

int main(int argc, char *argv[])
{
	struct lirc_config *config;
	char *config_file = NULL;

	while (1) {
		int c;
		static struct option long_options[] = {
			{"config", required_argument, NULL, 'c'},
			{"help", no_argument, NULL, 'h'},
			{"version", no_argument, NULL, 'v'},
			{0, 0, 0, 0}
		};
		c = getopt_long(argc, argv, "chv", long_options, NULL);
		if (c == -1)
			break;
		switch (c) {
		case 'c':
			config_file = optarg;
			break;
		case 'h':
			print_usage(argv[0]);
			return EXIT_SUCCESS;
		case 'v':
			printf("%s\n", PROG_VERSION);
			return EXIT_SUCCESS;
		default:
			print_usage(argv[0]);
			return EXIT_FAILURE;
		}
	}

	if (optind != argc - 1) {
		print_usage(argv[0]);
		return EXIT_FAILURE;
	}

	if (lirc_init(argv[argc-1], 1) == -1) exit(EXIT_FAILURE);

	if (lirc_readconfig(config_file, &config, NULL) == 0) {
		char *code;
		char *c;
		int ret;

		while (lirc_nextcode(&code) == 0) {
			if (code == NULL) continue;
			while ((ret = lirc_code2char(config, code, &c)) == 0 &&
			      c != NULL) {
				printf("%s\n", c);
				fflush(stdout);
			}
			free(code);
			if (ret == -1) break;
		}
		lirc_freeconfig(config);
	}

	lirc_deinit();
	exit(EXIT_SUCCESS);
}
