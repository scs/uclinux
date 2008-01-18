#ifndef TS_DEVICE
#define TS_DEVICE "AD7877"

/*Major 13 Minor 128*/ 
#define TS_DEVICE_FILE "/dev/ts"


struct ts_event {
	short pressure;
	short x;
	short y;
	short millisecs;
};

#endif
