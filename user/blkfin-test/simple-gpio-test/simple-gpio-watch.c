/*
 * Open a whole bunch of gpios and watch for value changes
 */

#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define errp(fmt, args...) ({ printf("%s:%i: " fmt ": %p\n", __func__, __LINE__, ## args, strerror(errno)); exit(1); })

int main(int argc, char *argv[])
{
	char **gpios = NULL;
	int i, num;

	chdir("/dev");

	if (argc > 1) {
		--argc;
		++argv;
		for (i = 0; i < argc; ++i) {
			gpios = realloc(gpios, (i + 1) * sizeof(*gpios));
			asprintf(&(gpios[i]), "%s", argv[i]);
		}
	} else {
		DIR *d = opendir("/dev");
		struct dirent *f;

		if (!d)
			errp("opendir(/dev)");

		i = 0;
		while ((f = readdir(d)) != NULL) {
			if (strncmp(f->d_name, "gpio", 4))
				continue;
			gpios = realloc(gpios, (i + 1) * sizeof(*gpios));
			asprintf(&(gpios[i]), "%s", f->d_name);
			++i;
		}
		closedir(d);
	}
	num = i;

	puts("Watching:");
	for (i = 0; i < num; ++i)
		printf("%s ", gpios[i]);
	puts("");

	int *fds = calloc(num, sizeof(*fds));
	for (i = 0; i < num; ++i) {
		fds[i] = open(gpios[i], O_RDONLY);
		if (fds[i] == -1)
			printf("Skipping %s\n", gpios[i]);
	}

	char *bytes = calloc(num, sizeof(bytes));
	memset(bytes, '0', num);
	while (1) {
		char byte;
		for (i = 0; i < num; ++i) {
			if (fds[i] == -1)
				continue;
			read(fds[i], &byte, 1);
			if (byte != bytes[i])
				printf("%s: %c -> %c\n", gpios[i], bytes[i], byte);
			bytes[i] = byte;
		}
	}

	return 0;
}
