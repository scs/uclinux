#include "driver.h"

int rapidfire_enable;

int setrapidfire(int selected)
{
	return 1;
}

int osd_net_active(void)
{
	return 1;
}

void osd_net_sync(unsigned short input_port_values[MAX_INPUT_PORTS],
		unsigned short input_port_defaults[MAX_INPUT_PORTS])
{
}
