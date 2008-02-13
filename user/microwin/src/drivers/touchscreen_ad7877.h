#ifndef TS_DEVICE
#define TS_DEVICE "AD7877"

/*Dynamic Mayor,Minor*/
#define TS_DEVICE_FILE "/dev/ts0"


struct ts_event {
	short pressure;
	short x;
	short y;
	short millisecs;
};

#endif
