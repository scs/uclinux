/*
 * Simple test case for the simple-gpio driver.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#define PROG "simple-gpio-test"

#define err(fmt, args...) \
	do { \
		fprintf(stderr, PROG ":%s:%i: error: " fmt "\n", __func__, __LINE__, ## args); \
		exit(2); \
	} while (0)
#define errp(fmt, args...) err(fmt ": %s", ## args, strerror(errno))

__attribute__((noreturn))
void usage(int exit_status)
{
	puts(
		"Usage: simple-gpio-test <gpio device>\n"
		"\n"
		"This will open the specified gpio device, set it to input\n"
		"mode, and then wait for it to go high.\n"
		"\n"
		"You should specify a gpio device that represents a button.\n"
		"\n"
		"Quick cheat sheet:\n"
		" BF533-STAMP:\n"
		"\tLED1 => GPIO2\tPB1 => GPIO5\n"
		"\tLED2 => GPIO3\tPB2 => GPIO6\n"
		"\tLED3 => GPIO4\tPB3 => GPIO8\n"
		" BF537-STAMP:\n"
		"\tLED1 => GPIO6\tPB1 => GPIO2\n"
		"\tLED2 => GPIO7\tPB2 => GPIO3\n"
		"\tLED3 => GPIO8\tPB3 => GPIO4\n"
		"\tLED4 => GPIO9\tPB4 => GPIO5\n"
		"\tLED5 => GPIO10\n"
		"\tLED6 => GPIO11\n"
	);
	exit(exit_status);
}

int main(int argc, char *argv[])
{
	char *button;
	FILE *fp;

	if (argc != 2)
		usage(1);
	if (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help"))
		usage(0);

	/* open the specified device */
	button = argv[1];
	fp = fopen(button, "r+");
	if (!fp)
		errp("unable to open specified device '%s'", button);

	/* set it to input mode */
	if (fwrite("I", 1, 1, fp) != 1)
		errp("unable to set to output mode");
	fsync(fileno(fp));

	/* now wait for user to press the button */
	puts("Going to sleep until the gpio goes high.");
	puts("(if this is a button, you should push it :p)");

	while (1) {
		char byte;
		if (fread(&byte, 1, 1, fp) != 1)
			errp("unable to read device");

		if (byte == '1')
			break;
	}

	puts("The gpio went high!  Time to bail!");

	fclose(fp);

	return 0;
}
