/* io.c  -  Virtual disk input/output */

/* Written 1993 by Werner Almesberger */

/*
 * Thu Feb 26 01:15:36 CET 1998: Martin Schulze <joey@infodrom.north.de>
 *	Fixed nasty bug that caused every file with a name like
 *	xxxxxxxx.xxx to be treated as bad name that needed to be fixed.
 */

/* FAT32, VFAT, Atari format support, and various fixes additions May 1998
 * by Roman Hodek <Roman.Hodek@informatik.uni-erlangen.de> */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/fd.h>

#include "dosfsck.h"
#include "common.h"
#include "io.h"


typedef struct _change {
    void *data;
    loff_t pos;
    int size;
    struct _change *next;
} CHANGE;


static CHANGE *changes,*last;
static int fd,did_change = 0;

unsigned device_no;

/* Use the _llseek system call directly, because there (once?) was a bug in
 * the glibc implementation of it. */
#include <linux/unistd.h>
#if defined __alpha || defined __ia64__ || defined __s390x__ || defined __x86_64__ || defined __ppc64__
/* On alpha, the syscall is simply lseek, because it's a 64 bit system. */
static loff_t llseek( int fd, loff_t offset, int whence )
{
    return lseek(fd, offset, whence);
}
#else
# ifndef __NR__llseek
# error _llseek system call not present
# endif
static _syscall5( int, _llseek, uint, fd, ulong, hi, ulong, lo,
		  loff_t *, res, uint, wh );

static loff_t llseek( int fd, loff_t offset, int whence )
{
    loff_t actual;

    if (_llseek(fd, offset>>32, offset&0xffffffff, &actual, whence) != 0)
	return (loff_t)-1;
    return actual;
}
#endif


void fs_open(char *path,int rw)
{
    struct stat stbuf;
    
    if ((fd = open(path,rw ? O_RDWR : O_RDONLY)) < 0)
	pdie("open %s",path);
    changes = last = NULL;
    did_change = 0;

    if (fstat(fd,&stbuf) < 0)
	pdie("fstat",path);
    device_no = S_ISBLK(stbuf.st_mode) ? (stbuf.st_rdev >> 8) & 0xff : 0;
}


void fs_read(loff_t pos,int size,void *data)
{
    CHANGE *walk;
    int got;

    if (llseek(fd,pos,0) != pos) pdie("Seek to %lld",pos);
    if ((got = read(fd,data,size)) < 0) pdie("Read %d bytes at %lld",size,pos);
    if (got != size) die("Got %d bytes instead of %d at %lld",got,size,pos);
    for (walk = changes; walk; walk = walk->next) {
	if (walk->pos < pos+size && walk->pos+walk->size > pos) {
	    if (walk->pos < pos)
		memcpy(data,(char *) walk->data+pos-walk->pos,min(size,
		  walk->size-pos+walk->pos));
	    else memcpy((char *) data+walk->pos-pos,walk->data,min(walk->size,
		  size+pos-walk->pos));
	}
    }
}


int fs_test(loff_t pos,int size)
{
    void *scratch;
    int okay;

    if (llseek(fd,pos,0) != pos) pdie("Seek to %lld",pos);
    scratch = alloc(size);
    okay = read(fd,scratch,size) == size;
    free(scratch);
    return okay;
}


void fs_write(loff_t pos,int size,void *data)
{
    CHANGE *new;
    int did;

    if (write_immed) {
	did_change = 1;
	if (llseek(fd,pos,0) != pos) pdie("Seek to %lld",pos);
	if ((did = write(fd,data,size)) == size) return;
	if (did < 0) pdie("Write %d bytes at %lld",size,pos);
	die("Wrote %d bytes instead of %d at %lld",did,size,pos);
    }
    new = alloc(sizeof(CHANGE));
    new->pos = pos;
    memcpy(new->data = alloc(new->size = size),data,size);
    new->next = NULL;
    if (last) last->next = new;
    else changes = new;
    last = new;
}


static void fs_flush(void)
{
    CHANGE *this;
    int size;

    while (changes) {
	this = changes;
	changes = changes->next;
	if (llseek(fd,this->pos,0) != this->pos)
	    fprintf(stderr,"Seek to %lld failed: %s\n  Did not write %d bytes.\n",
	      this->pos,strerror(errno),this->size);
	else if ((size = write(fd,this->data,this->size)) < 0)
		fprintf(stderr,"Writing %d bytes at %lld failed: %s\n",this->size,
		  this->pos,strerror(errno));
	    else if (size != this->size)
		    fprintf(stderr,"Wrote %d bytes instead of %d bytes at %lld."
		      "\n",size,this->size,this->pos);
	free(this->data);
	free(this);
    }
}


int fs_close(int write)
{
    CHANGE *next;
    int changed;

    changed = !!changes;
    if (write) fs_flush();
    else while (changes) {
	    next = changes->next;
	    free(changes->data);
	    free(changes);
	    changes = next;
	}
    if (close(fd) < 0) pdie("closing file system");
    return changed || did_change;
}


int fs_changed(void)
{
    return !!changes || did_change;
}

/* Local Variables: */
/* tab-width: 8     */
/* End:             */
