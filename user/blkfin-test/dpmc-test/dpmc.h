#define SLEEP_MODE		1
#define DEEP_SLEEP_MODE		2
#define ACTIVE_PLLDISABLED	3
#define FULLON_MODE		4
#define ACTIVE_PLLENABLED	5
#define HIBERNATE_MODE		6

#define IOCTL_FULL_ON_MODE	_IO('s', 0xA0)
#define IOCTL_ACTIVE_MODE	_IO('s', 0xA1)
#define IOCTL_SLEEP_MODE	_IO('s', 0xA2)
#define IOCTL_DEEP_SLEEP_MODE	_IO('s', 0xA3)
#define IOCTL_HIBERNATE_MODE	_IO('s', 0xA4)
#define IOCTL_CHANGE_FREQUENCY	_IOW('s', 0xA5, unsigned long)
#define IOCTL_CHANGE_VOLTAGE	_IOW('s', 0xA6, double)
#define IOCTL_SET_CCLK		_IOW('s', 0xA7, unsigned long)
#define IOCTL_SET_SCLK		_IOW('s', 0xA8, unsigned long)
#define IOCTL_GET_PLLSTATUS	_IOW('s', 0xA9, unsigned long)
#define IOCTL_GET_CORECLOCK	_IOW('s', 0xAA, unsigned long)
#define IOCTL_GET_SYSTEMCLOCK	_IOW('s', 0xAB, unsigned long)
#define IOCTL_GET_VCO		_IOW('s', 0xAC, unsigned long)

#define DPMC_MINOR		254

