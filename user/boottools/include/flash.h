#ifndef __FLASH_H__
#define __FLASH_H__

/* Command codes for the flash_command routine */
#define FLASH_SELECT    0       /* no command; just perform the mapping */
#define FLASH_RESET     1       /* reset to read mode */
#define FLASH_READ      1       /* reset to read mode, by any other name */
#define FLASH_AUTOSEL   2       /* autoselect (fake Vid on pin 9) */
#define FLASH_PROG      3       /* program a word */
#define FLASH_CERASE    4       /* chip erase */
#define FLASH_SERASE    5       /* sector erase */
#define FLASH_ESUSPEND  6       /* suspend sector erase */
#define FLASH_ERESUME   7       /* resume sector erase */
#define FLASH_UB        8       /* go into unlock bypass mode */
#define FLASH_UBPROG    9       /* program a word using unlock bypass */
#define FLASH_UBRESET   10      /* reset to read mode from unlock bypass mode */
#define FLASH_LASTCMD   10      /* used for parameter checking */

/* Return codes from flash_status */
#define STATUS_READY    0       /* ready for action */
#define STATUS_BUSY     1       /* operation in progress */
#define STATUS_ERSUSP   2       /* erase suspended */
#define STATUS_TIMEOUT  3       /* operation timed out */
#define STATUS_ERROR    4       /* unclassified but unhappy status */

/* AMD's manufacturer ID */
#define AMDPART   	0x01

/* A list of 4 AMD device ID's - add others as needed */
#define ID_AM29DL800T   0x224A
#define ID_AM29DL800B   0x22CB
#define ID_AM29LV800T   0x22DA
#define ID_AM29LV800B   0x225B
#define ID_AM29LV160B   0x2249
#define ID_AM29LV160T   0x22C4
#define ID_AM29LV400B   0x22BA

#define SECTOR_DIRTY   0x01
#define SECTOR_ERASED  0x02
#define SECTOR_PROTECT 0x04

#define PGM_ERASE_FIRST 0x0001
#define PGM_RESET_AFTER 0x0002
#define PGM_EXEC_AFTER  0x0004
#define PGM_HALT_AFTER  0x0008

/* an mnode points at 4k pages of data through an offset table. */
typedef struct _memnode {
  int len;
  int *offset;
} mnode_t;

/* device level FLASH functions */

int flash_status(volatile unsigned short *flashptr);

int flash_command(int command,
		  volatile unsigned short *flashptr,
		  int offset,
		  unsigned int data);

int flash_write(volatile unsigned short *flashptr,
		int offset,
		int nbytes,
		unsigned short *buf);

int flash_timeout(volatile unsigned short *flashptr,
		  int retry);

int flash_device_id(volatile unsigned short *flashptr);
int flash_mfg_id(volatile unsigned short *flashptr);
char * flash_device_string(volatile unsigned short *flashptr);

/* block oriented high level functions */

int flash_chattr_range(volatile unsigned short *flashptr,
		       int start,
		       int end,
		       char and,
		       char or);

int flash_erase_range(volatile unsigned short *flashptr,
		      int start,
		      int end);

int flash_write_range(volatile unsigned short *flashptr,
		      mnode_t *mnode,
		      int offset);

#define flash_chip_erase(X) ({ flash_command(FLASH_CERASE, (X), 0, 0); \
                               flash_timeout((X), 100000000); })
#define flash_sector_erase(X,Y) ({ flash_command(FLASH_SERASE, (X), (Y), 0); \
                                   flash_timeout(&(X)[Y], 3000000); })
#endif /* __FLASH_H__ */


