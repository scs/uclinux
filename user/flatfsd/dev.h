/****************************************************************************/

/*
 *	dev.h -- raw flat filesystem access functions.
 */

/****************************************************************************/
#ifndef FLATFS_DEV_H
#define FLATFS_DEV_H
/****************************************************************************/

int flat_dev_open(const char *flatfs, const char *mode);
int flat_dev_length(void);
int flat_dev_erase_length(void);
int flat_dev_erase(off_t offset, size_t len);
int flat_dev_write(off_t offset, const char *buf, size_t len);
off_t flat_dev_seek(off_t offset, int whence);
int flat_dev_read(char *buf, size_t len);
int flat_dev_close(int abort, off_t written);

/****************************************************************************/
#endif
