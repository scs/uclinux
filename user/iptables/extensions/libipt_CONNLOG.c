/* Shared library add-on to iptables to add CONNLOG target support. */
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <iptables.h>

/* Function which prints out usage message. */
static void
help(void)
{
	printf(
"CONNLOG target v%s takes no options\n",
IPTABLES_VERSION);
}

static struct option opts[] = {
	{ 0 }
};

/* Initialize the target. */
static void
init(struct ipt_entry_target *t, unsigned int *nfcache)
{
}

/* Function which parses command options; returns true if it
   ate an option */
static int
parse(int c, char **argv, int invert, unsigned int *flags,
      const struct ipt_entry *entry,
      struct ipt_entry_target **target)
{
	return 0;
}

static void
final_check(unsigned int flags)
{
}

static struct iptables_target connlog_target = {
    .name          = "CONNLOG",
    .version       = IPTABLES_VERSION,
    .size          = IPT_ALIGN(0),
    .userspacesize = IPT_ALIGN(0),
    .help          = &help,
    .init          = &init,
    .parse         = &parse,
    .final_check   = &final_check,
    .extra_opts    = opts
};

void _init(void)
{
	register_target(&connlog_target);
}
