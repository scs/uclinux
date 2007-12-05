/*
 * pcfdemo - demonstrate PCF font loading for Nano-X
 */
#include <stdio.h>
#include <stdlib.h>
#define MWINCLUDECOLORS
#include "nano-X.h"

GR_FONT_ID font = 0;
GR_WINDOW_ID main_wid;
GR_FONT_INFO finfo;

int max_width = 240;
int max_height = 320;

static void
draw_string(void)
{
	int x = 0;
	int y = 10;
	int ch = 0;
	GR_GC_ID gc = GrNewGC();

	GrSetGCFont(gc, font);

	GrSetGCForeground(gc, GR_RGB(255, 255, 255));
	GrSetGCBackground(gc, GR_RGB(0, 0, 0));

	printf("First char = 0x%x, last char = 0x%x\n", finfo.firstchar,
	       finfo.lastchar);
	printf("Max width = %d, max height = %d\n", finfo.maxwidth,
	       finfo.height);

	for (ch = finfo.firstchar; ch < finfo.lastchar; ch++) {
		printf("draw_string: 0x%x\n", ch);
		GrText(main_wid, gc, x, y, &ch, 1,
		       GR_TFTOP | GR_TFUC16);

		if (x + (finfo.maxwidth + 2) >= max_width) {
			x = 0;
			if ( (y + finfo.height) >= max_height) {
				y = 0;
				getchar();
			}
			else
				y += finfo.height;
		} else
			x += (finfo.maxwidth + 2);
			
	}

	GrDestroyGC(gc);
}

int
main(int argc, char **argv)
{
	int width, height;

	if (argc < 2) {
		printf("%s <font>\n", argv[0]);
		return (-1);
	}

	if (GrOpen() == -1) {
		printf("GrOpen() error\n");
		return (-1);
	}

	font = GrCreateFont(argv[1], 0, 0);
	if (!font)
		printf("Unable to load %s\n", argv[1]);

	GrGetFontInfo(font, &finfo);

	width = (max_width / (finfo.maxwidth + 2)) * (finfo.maxwidth + 2);
	height = (max_height / (finfo.height + 5)) * (finfo.height + 5);

	printf("window height: %d, window width: %d\n", height, width);

	main_wid = GrNewWindowEx(GR_WM_PROPS_APPWINDOW, "pcfdemo",
			GR_ROOT_WINDOW_ID, 0, 0, width, height, BLACK);
	GrSelectEvents(main_wid, GR_EVENT_MASK_EXPOSURE|GR_EVENT_MASK_CLOSE_REQ);
	GrMapWindow(main_wid);

	while (1) {
		GR_EVENT event;
		GrGetNextEvent(&event);

		if (event.type == GR_EVENT_TYPE_EXPOSURE)
			draw_string();

	        if(event.type == GR_EVENT_TYPE_CLOSE_REQ) {
			GrClose();
			exit(0);
	      }
	}
}
