/* Shared library add-on to iptables to add LED support. */
#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include <getopt.h>
#include <iptables.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv4/ipt_LED.h>
#include <linux/ledman.h>

static struct option opts[] = {
	{ .name = "led",              .has_arg = 1, .flag = 0, .val = '1' },
	{ .name = "save",             .has_arg = 0, .flag = 0, .val = '2' },
	{ .name = "restore",          .has_arg = 0, .flag = 0, .val = '3' },
	{ .name = 0 }
};

/* Initialize the target. */
static void
init(struct ipt_entry_target *t, unsigned int *nfcache)
{
	struct ipt_led_info *ledinfo = (struct ipt_led_info *)t->data;

	ledinfo->led = LEDMAN_ALL;
	ledinfo->mode = IPT_LED_SET;

	/* Can't cache this */
	*nfcache |= NFC_UNKNOWN;
}

struct ipt_led_names {
	const char *name;
	u_int32_t led;
};

static struct ipt_led_names ipt_led_names[] = {
#include "libipt_LED_def.c"
    { }
};

static u_int32_t
parse_led(const char *name)
{
	unsigned int led = -1;
	unsigned int set = 0;

	if (string_to_number(name, 0, 7, &led) == -1) {
		unsigned int i = 0;

		for (i = 0; ipt_led_names[i].name; i++) {
			if (strcasecmp(name, ipt_led_names[i].name) == 0) {
				set++;
				led = ipt_led_names[i].led;
				break;
			}
			if (strncasecmp(name, ipt_led_names[i].name,
					strlen(name)) == 0) {
				if (set++)
					exit_error(PARAMETER_PROBLEM,
						   "led `%s' ambiguous", name);
				led = ipt_led_names[i].led;
			}
		}

		if (!set)
			exit_error(PARAMETER_PROBLEM,
				   "led `%s' unknown", name);
	}

	return led;
}

#define IPT_LED_OPT_LED    0x01
#define IPT_LED_OPT_MODE   0x02
#define IPT_LED_OPT_NO_LED 0x04

/* Function which parses command options; returns true if it
   ate an option */
static int
parse(int c, char **argv, int invert, unsigned int *flags,
      const struct ipt_entry *entry,
      struct ipt_entry_target **target)
{
	struct ipt_led_info *ledinfo = (struct ipt_led_info *)(*target)->data;

	switch (c) {
	case '1':
		if (*flags & IPT_LED_OPT_LED)
			exit_error(PARAMETER_PROBLEM,
				   "Can't specify --led twice");

		ledinfo->led = parse_led(optarg);
		*flags |= IPT_LED_OPT_LED;
		break;

	case '2':
		if (*flags & IPT_LED_OPT_MODE)
			exit_error(PARAMETER_PROBLEM,
				   "Can't specify --save twice");

		ledinfo->mode = IPT_LED_SAVE;
		*flags |= IPT_LED_OPT_MODE;
		break;

	case '3':
		if (*flags & IPT_LED_OPT_MODE)
			exit_error(PARAMETER_PROBLEM,
				   "Can't specify --restore twice");

		ledinfo->mode = IPT_LED_RESTORE;
		*flags |= IPT_LED_OPT_MODE | IPT_LED_OPT_NO_LED;
		break;

	default:
		return 0;
	}

	return 1;
}

static void
final_check(unsigned int flags)
{
	if ((flags & IPT_LED_OPT_NO_LED) && (flags & IPT_LED_OPT_LED))
		exit_error(PARAMETER_PROBLEM,
	           	   "LED target: Can't specify --led with --restore");

	if (!(flags & IPT_LED_OPT_NO_LED) && !(flags & IPT_LED_OPT_LED))
		exit_error(PARAMETER_PROBLEM,
		           "LED target: No --led specified");
}

/* Prints out the targinfo. */
static void
print(const struct ipt_ip *ip,
      const struct ipt_entry_target *target,
      int numeric)
{
	const struct ipt_led_info *ledinfo
		= (const struct ipt_led_info *)target->data;
	unsigned int i;

	printf("LED ");
	switch (ledinfo->mode) {
	case IPT_LED_SAVE:
		printf("save ");
		/* fallthrough */
	case IPT_LED_SET:
		for (i = 0; ipt_led_names[i].name; i++) {
			if (ledinfo->led == ipt_led_names[i].led) {
				printf("led %s ", ipt_led_names[i].name);
				break;
			}
		}
		if (!ipt_led_names[i].name)
			printf("UNKNOWN led %u ", ledinfo->led);
		break;
	case IPT_LED_RESTORE:
		printf("restore ");
		break;
	default:
		printf("ERROR: UNKNOWN LED MODE ");
		break;
	}
}

/* Saves the union ipt_targinfo in parsable form to stdout. */
static void
save(const struct ipt_ip *ip, const struct ipt_entry_target *target)
{
	const struct ipt_led_info *ledinfo
		= (const struct ipt_led_info *)target->data;
	unsigned int i;

	switch (ledinfo->mode) {
	case IPT_LED_SAVE:
		printf("--save ");
		/* fallthrough */
	case IPT_LED_SET:
		printf("--led ");
		for (i = 0; ipt_led_names[i].name; i++) {
			if (ledinfo->led == ipt_led_names[i].led) {
				printf("led %s ", ipt_led_names[i].name);
				break;
			}
		}
		if (!ipt_led_names[i].name)
			printf("%u ", ledinfo->led);
		break;
	case IPT_LED_RESTORE:
		printf("--restore ");
		break;
	default:
		printf("ERROR: UNKNOWN LED MODE ");
		break;
	}
}

/* Function which prints out usage message. */
static void
help(void)
{
	unsigned int i;

	printf(
"LED v%s options:\n"
"  --led LED                     LED to set\n"
"  --save                        Save the LED value in the connection\n"
"  --restore                     Use the saved LED value\n"
"\n", IPTABLES_VERSION);

	printf("LED names:\n");
	for (i = 0; ipt_led_names[i].name; i++)
		printf(" %s\n", ipt_led_names[i].name);
}

static
struct iptables_target led
= {
    .name          = "LED",
    .version       = IPTABLES_VERSION,
    .size          = IPT_ALIGN(sizeof(struct ipt_led_info)),
    .userspacesize = IPT_ALIGN(sizeof(struct ipt_led_info)),
    .help          = &help,
    .init          = &init,
    .parse         = &parse,
    .final_check   = &final_check,
    .print         = &print,
    .save          = &save,
    .extra_opts    = opts
};

void _init(void)
{
	register_target(&led);
}
