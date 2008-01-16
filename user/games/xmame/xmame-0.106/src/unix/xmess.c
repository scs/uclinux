/*
This file is a set of function calls and defs required for MESS.
It doesnt do much at the moment, but its here in case anyone
needs it ;-)
*/

#include "driver.h"
#include "xmame.h"
#include "xmess.h"
#include <ctype.h>
#include <sys/stat.h>
#include <unistd.h>

int osd_select_file(mess_image *img, char *filename)
{
	return 0;
}

void osd_image_load_status_changed(mess_image *img, int is_final_unload)
{
}
