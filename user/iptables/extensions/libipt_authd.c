/* Shared library add-on to iptables for authd. */
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <iptables.h>

/* Our less than helpful help
 */
static void help(void) {
	printf("authd v%s takes no options\n\n", IPTABLES_VERSION);
}

/* Initialize ourselves.
 */
static void init(struct ipt_entry_match *m, unsigned int *nfcache) {
	*nfcache |= NFC_UNKNOWN;	// Disallow caching of our results
}

/* Parse command options.
 * Since we have no options we never consume any and thus always
 * return false.
 */
static int parse(int c, char **argv, int invert, unsigned int *flags,
		const struct ipt_entry *entry, unsigned int *nfcache,
		struct ipt_entry_match **match) {
	return 0;
}

/* Final checks.  Nothing to see here.  Move along.
 */
static void final_check(unsigned int flags) {
}

/* Globals that contain our information.
 * We take no options so that structure is empty.
 */
static struct option opts[] = { {0} };

/* All of our information and work functions live here.
 */
static struct iptables_match authd = {
    name:		"authd",
    version:		IPTABLES_VERSION,
    size:		IPT_ALIGN(0),
    userspacesize:	IPT_ALIGN(0),
    help:		&help,
    init:		&init,
    parse:		&parse,
    final_check:	&final_check,
    extra_opts:		opts
};

/* Our initialisation code.  Just register us as a target and that's it.
 * The kernel module and the user land authd process will take care of
 * everything.
 */
void _init(void) {
	register_match(&authd);
}
