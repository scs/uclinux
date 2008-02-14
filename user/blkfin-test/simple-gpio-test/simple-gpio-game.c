/*
 * Simple test case for the simple-gpio driver.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>

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
		"Usage: simple-gpio-game <list of buttons> : <list of leds>\n"
		"       simple-gpio-game <board template>\n"
		"\n"
		"This will run blinky on the specified leds and then let you\n"
		"control the leds by the button pushes.\n"
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

char *bf537_stamp_buttons[] = { "/dev/gpio2", "/dev/gpio3", "/dev/gpio4", "/dev/gpio5" };
char *bf537_stamp_leds[] = { "/dev/gpio10", "/dev/gpio9", "/dev/gpio8", "/dev/gpio7" };

int main(int argc, char *argv[])
{
	int i;
	int num_buttons, num_leds, got_colon;
	char **buttons, **leds;
	int *buttons_fd, *leds_fd;
	bool using_template = false;

	if (argc < 2)
		usage(1);
	if (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help"))
		usage(0);

	setbuf(stdout, NULL);

	/* get the array of buttons and leds ... */
	if (argc == 2) {
		/* ... from a template */
		if (!strcasecmp(argv[1], "bf537-stamp")) {
			num_buttons = num_leds = 4;
			buttons = bf537_stamp_buttons;
			leds = bf537_stamp_leds;
		} else
			err("unknown board template '%s'", argv[1]);
		using_template = true;
	} else {
		/* ... from the command line */
		num_buttons = num_leds = 0;
		got_colon = 0;
		i = 1;
		while (i < argc && argv[i]) {
			if (got_colon) {
				++num_leds;
				printf("LED[%i] = %s\n", num_leds, argv[i]);
			} else {
				if (!strcmp(argv[i], ":")) {
					got_colon = 1;
				} else {
					++num_buttons;
					printf("Button[%i] = %s\n", num_buttons, argv[i]);
				}
			}
			++i;
		}

		if (num_buttons != num_leds)
			err("number of buttons (%i) != number of leds (%i)", num_buttons, num_leds);

		buttons = calloc(sizeof(*buttons), num_buttons);
		leds = calloc(sizeof(*leds), num_leds);
	}
	buttons_fd = calloc(sizeof(*buttons_fd), num_buttons);
	leds_fd = calloc(sizeof(*leds_fd), num_leds);

	/* open up all the specified buttons and set them to inputs */
	printf("Buttons[%i] = { ", num_buttons);
	for (i = 0; i < num_buttons; ++i) {
		if (!using_template)
			buttons[i] = argv[i + 1];
		printf("%s%s ", buttons[i], (i < num_buttons - 1 ? "," : ""));
		buttons_fd[i] = open(buttons[i], O_RDWR);
		if (buttons_fd[i] == -1)
			errp("unable to open button '%s'", buttons[i]);
		if (write(buttons_fd[i], "I", 1) != 1)
			errp("unable to set button '%s' to input", buttons[i]);
		fsync(buttons_fd[i]);
	}
	printf("}\n");

	/* open up all the specified leds and set them to outputs */
	printf("LEDs[%i] = { ", num_leds);
	for (i = 0; i < num_leds; ++i) {
		if (!using_template)
			leds[i] = argv[i + 1 + num_buttons + 1];
		printf("%s%s ", leds[i], (i < num_leds - 1 ? "," : ""));
		leds_fd[i] = open(leds[i], O_RDWR);
		if (leds_fd[i] == -1)
			errp("unable to open LED '%s'", leds[i]);
		if (write(leds_fd[i], "O0", 2) != 2)
			errp("unable to set led '%s' to output", leds[i]);
		fsync(leds_fd[i]);
	}
	printf("}\n");

	/* first do a blinky for a few seconds */
	printf("Running blinky ");
	time_t start = time(NULL);
	char state = '1';
	while (time(NULL) - start < 5) {
		for (i = 0; i < num_leds; ++i) {
			if (write(leds_fd[i], &state, 1) != 1)
				errp("unable to write '%c' to led '%s'", state, leds[i]);
			fsync(leds_fd[i]);
			usleep(100000);
		}
		printf(".");
		state = (state == '0' ? '1' : '0');
	}
	printf("\n");

	/* now make the leds match the buttons */
	puts("Now matching LEDs to the buttons (hit CTRL+C to exit) ...");
	while (1) {
		for (i = 0; i < num_buttons; ++i) {
			char byte;
			if (read(buttons_fd[i], &byte, 1) != 1)
				errp("unable to read button '%s'", buttons[i]);
			if (write(leds_fd[i], &byte, 1) != 1)
				errp("unable to write '%c' to led '%s'", byte, leds[i]);
		}
	}

	/* we could clean up here, but let's test the driver to make sure it does it */

	return 0;
}
