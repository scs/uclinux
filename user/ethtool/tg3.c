#include <stdio.h>
#include "ethtool-util.h"

#define TG3_MAGIC 0x669955aa

int
tg3_dump_eeprom(struct ethtool_drvinfo *info, struct ethtool_eeprom *ee)
{
	int i;

	if (ee->magic != TG3_MAGIC) {
		fprintf(stderr, "Magic number 0x%08x does not match 0x%08x\n",
			ee->magic, TG3_MAGIC);
		return -1;
	}

	fprintf(stdout, "Address   \tData\n");
	fprintf(stdout, "----------\t----\n");
	for (i = 0; i < ee->len; i++)
		fprintf(stdout, "0x%08x\t0x%02x\n", i + ee->offset, ee->data[i]);

	return 0;
}
