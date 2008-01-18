/*****************************************************************************/

/*
 *	flatfs3.c -- flat compressed FLASH file-system version 3.
 *
 *	Copyright (C) 1999-2006, Greg Ungerer (gerg@snapgear.com).
 *	Copyright (C) 2001-2002, SnapGear (www.snapgear.com)
 *	Copyright (C) 2005 CyberGuard Corporation (www.cyberguard.com)
 */

/*****************************************************************************/

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <fcntl.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>
#include <malloc.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <limits.h>
#include <assert.h>
#include <syslog.h>
#include <zlib.h>

#include "flatfs.h"
#include "dev.h"
#include "ops.h"
#include "flatfs1.h"
#include "flatfs3.h"

/*****************************************************************************/

/*
 * General work buffer size (these are often allocated on the stack).
 */
#define BUF_SIZE 1024

/*
 * zlib meta-data. Keep track of compression/decompression.
 */
#define OUTPUT_SIZE 1024
#define INPUT_SIZE 1024

struct flatzfs_s {
	off_t		offset;
	z_stream	strm;
	char		*output;
	size_t		output_size;
	char		*input;
	size_t		input_size;
	int		write;
	int		read_initialised;
};

struct flatzfs_s flatzfs;

/*
 *	Keep track of the current highest tstamp value, and which partition
 *	the last restore came from. Helps us when it comes time to save the
 *	fs again.
 */
int numvalid = -1;
unsigned int numstamp;

/*****************************************************************************/

int flatz_read_init(void)
{
	int res;
	if (!flatzfs.read_initialised) {
		res = inflateInit(&flatzfs.strm);

		if (res != Z_OK) {
			syslog(LOG_ERR, "Initialising decompression failed - %d\n", res);
			return res;
		}

		flatzfs.read_initialised = 1;
	}

	return Z_OK;
}

/*****************************************************************************/

static int flatz_open(const char *mode)
{
	int rc;

	bzero(&flatzfs, sizeof(flatzfs));
	
	if (*mode == 'w') {
		rc = deflateInit(&flatzfs.strm, Z_DEFAULT_COMPRESSION);
		if (rc != 0)
			return ERROR_CODE();

		flatzfs.write = 1;
		flatzfs.output_size = OUTPUT_SIZE;
		flatzfs.output = (char *)malloc(flatzfs.output_size);

		flatzfs.strm.next_out = flatzfs.output;
		flatzfs.strm.avail_out = flatzfs.output_size;

	} else {
		flatzfs.write = 0;
		flatzfs.input_size = INPUT_SIZE;
		flatzfs.input = (char *)malloc(flatzfs.input_size);
	}

	return 0;
}

/*****************************************************************************/

static int flatz_close(void)
{
	if (flatzfs.read_initialised)
		inflateEnd(&flatzfs.strm);
	flatzfs.read_initialised = 0;
	if (flatzfs.write)
		deflateEnd(&flatzfs.strm);
	flatzfs.write = 0;
	if (flatzfs.output)
		free(flatzfs.output);
	flatzfs.output = NULL;
	if (flatzfs.input)
		free(flatzfs.input);
	flatzfs.input = NULL;
	return 0;
}

/*****************************************************************************/

static int flatz_finalise(int dowrite)
{
	int res;
	int rc = 0;

	for (;;) {
		res = deflate(&flatzfs.strm, Z_FINISH);

		if (res == Z_OK && flatzfs.strm.avail_out < OUTPUT_SIZE) {

			if (dowrite && (rc = flat_dev_write(flatzfs.offset, flatzfs.output, flatzfs.output_size - flatzfs.strm.avail_out)) < 0)
				return rc;
			flatzfs.offset += rc; 

			if (flatzfs.strm.avail_out == 0) {
				flatzfs.strm.avail_out = flatzfs.output_size;
				flatzfs.strm.next_out = flatzfs.output;
			}

		} else if (res != Z_STREAM_END) {
			break;

		} else {

			if (dowrite && (rc = flat_dev_write(flatzfs.offset, flatzfs.output, flatzfs.output_size - flatzfs.strm.avail_out)) < 0)
				return rc;
			break;
		}
	}

	return 0;
}

/*****************************************************************************/

/*
 * Compressed data write.
 */

static int flatz_write(const char *buf, size_t len, int do_write)
{
	int res;

	flatzfs.strm.next_in = (char *)buf;
	flatzfs.strm.avail_in = len;

	for (;;) {
		res = deflate(&flatzfs.strm, Z_NO_FLUSH);

		if (flatzfs.strm.avail_out == 0) {
			int rc = 0;
			if (do_write && (rc = flat_dev_write(flatzfs.offset, flatzfs.output, flatzfs.output_size - flatzfs.strm.avail_out)) < 0) 
				return rc;
			
			flatzfs.offset += flatzfs.output_size - flatzfs.strm.avail_out;
			flatzfs.strm.next_out = flatzfs.output;
			flatzfs.strm.avail_out = flatzfs.output_size;
		} else {
			break;
		}
	}

	return 0;
}

/*****************************************************************************/

/*
 * Just like flat_read, but reads from a compressed romfs thing.
 */

static int flatz_read(char *buf, size_t len)
{
	int res;
	int flush = Z_NO_FLUSH;

	if (len == 0)
		return 0;

	flatzfs.strm.avail_out = len;
	flatzfs.strm.next_out = buf;

	do {
		int bytes_read;

		if (flatzfs.strm.avail_in == 0) {

			flatzfs.strm.next_in = flatzfs.input;
			flatzfs.strm.avail_in = 0;

			bytes_read = flat_read(flatzfs.strm.next_in,
				flatzfs.input_size);

			if (bytes_read < flatzfs.input_size)
				flush = Z_FINISH;

			flatzfs.strm.avail_in = bytes_read;

			if ((res = flatz_read_init()) < 0)
				return res;
		}

		res = inflate(&flatzfs.strm, flush);

		if (res < 0 && (res != Z_BUF_ERROR || flatzfs.strm.avail_in == 0)) {
			syslog(LOG_INFO, "Result from reading flatfs3 - %d", res);
			return res;
		}

		if (res == Z_STREAM_END) {
			return len - flatzfs.strm.avail_out;
		}
	} while (flatzfs.strm.avail_out);

	return len;
}

/*****************************************************************************/

/*
 * Check for a valid partition in flash. We attempt to restore an fs
 * (with dowrite inactive ofcourse :-)  If it succeeds then we have at
 * least one good partition to use.
 *
 * Unfortunately this is probably not exactly what we want in the case of
 * running checkfs strait after doing a savefs. We would ideally like to
 * only check the partition we just wrote. But that is not simple to
 * determine here that is actually what we are trying to test for.
 */

int flat3_checkfs(void)
{
	int rc;
	/* Now, really check that it is valid */
	if ((rc = flat3_restorefs(3, 0)) < 0)
		return rc;
	return 0;
}

/*****************************************************************************/

/*
 * Read header at specific offset. If it is in someway invalid then return
 * an empty (zeroed out) header structure.
 */
int flat3_gethdroffset(off_t off, struct flathdr3 *hp)
{
	memset(hp, 0, sizeof(*hp));
        if (flat_seek(off, SEEK_SET) != off)
                return ERROR_CODE();
	if (flat_read((void *) hp, sizeof(*hp)) != sizeof(*hp))
		return ERROR_CODE();
	if (hp->magic != FLATFS_MAGIC_V3)
		return ERROR_CODE();
	return 0;
}

/*****************************************************************************/

/*
 * Find any valid header we can in the flash (from either of the 2
 * partitions).
 */

unsigned int flat3_gethdr(void)
{
	struct flathdr3 hdr;
	unsigned int psize;
	int rc;

	psize = flat_dev_length() / 2;
	rc = flat3_gethdroffset(0, &hdr);
	if ((rc < 0) || (hdr.magic != FLATFS_MAGIC_V3)) {
		rc = flat3_gethdroffset(psize, &hdr);
		if (rc < 0)
			hdr.magic = 0;
	}
	return hdr.magic;
}

/*****************************************************************************/

#ifndef HAS_RTC
static void parseconfig(char *buf)
{
	char *confline, *confdata;

	confline = strtok(buf, "\n");
	while (confline) {
		confdata = strchr(confline, ' ');
		if (confdata) {
			*confdata = '\0';
			confdata++;
			if (!strcmp(confline, "time")) {
				time_t t;
				t = atol(confdata);
				if (t > time(NULL))
					stime(&t);
			}
		}
		confline = strtok(NULL, "\n");
	}
}
#endif

/*****************************************************************************/

/*
 * Read the contents of a flat file-system and dump them out as regular files.
 * Takes the offset of the filesystem into the flash address space (this
 * is to allow support multiple filesystems in a single flash partition).
 */

static int flat3_restorefsoffset(off_t offset, int dowrite)
{
	struct flathdr3 hdr;
	struct flatent ent;
	unsigned int size, n = 0;
	char filename[128], *confbuf;
	unsigned char buf[BUF_SIZE];
	mode_t mode;
	int fdfile, rc;

	if ((rc = flatz_open("r")) < 0)
		return rc;

	if (flat_seek(offset+sizeof(hdr), SEEK_SET) != (offset+sizeof(hdr))) {
		flatz_close();
		return ERROR_CODE();
	}

	for (numfiles = 0, numbytes = 0; ; numfiles++) {
		/* Get the name of next file. */
		if ((rc = flatz_read((void *) &ent, sizeof(ent))) != sizeof(ent)) {
			flatz_close();
			return ERROR_CODE();
		}

		if (ent.filelen == FLATFS_EOF)
			break;

		n = ((ent.namelen + 3) & ~0x3);
		if (n > sizeof(filename)) {
			/*fprintf(stderr, "filename length is wrong\n");*/
			flatz_close();
			return ERROR_CODE();
		}

		if (flatz_read((void *) &filename[0], n) != n) {
			flatz_close();
			return ERROR_CODE();
		}

		if (flatz_read((void *) &mode, sizeof(mode)) != sizeof(mode)) {
			flatz_close();
			return ERROR_CODE();
		}

		/*fprintf(stderr, "filename - %s, mode - %o, namelen - %d\n",
				filename, mode, ent.namelen);*/

		if (strcmp(filename, FLATFSD_CONFIG) == 0) {
			/* Read our special flatfsd config file into memory */
			if (ent.filelen == 0) {
#ifndef HAS_RTC
				/* This file was not written correctly, so just ignore it */
				syslog(LOG_WARNING, "%s is zero length, ignoring", filename);
#endif
			} else if ((confbuf = malloc(ent.filelen)) == 0) {
				syslog(LOG_ERR, "Failed to allocate memory for %s -- ignoring it", filename);
			} else {
				if (flatz_read(confbuf, ent.filelen) != ent.filelen) {
					flatz_close();
					return ERROR_CODE();
				}
#ifndef HAS_RTC
				if (dowrite)
					parseconfig(confbuf);
#endif
				free(confbuf);
			}
		} else {
			/* Write contents of file out for real. */
			if (dowrite) {
				fdfile = open(filename, (O_WRONLY | O_TRUNC | O_CREAT), mode);
				if (fdfile < 0) {
					flatz_close();
					return ERROR_CODE();
				}
			} else {
				fdfile = -1;
			}
			
			for (size = ent.filelen; (size > 0); size -= n) {
				n = (size > sizeof(buf)) ? sizeof(buf) : size;
				if (flatz_read(&buf[0], n) != n) {
					flatz_close();
					return ERROR_CODE();
				}
				if (dowrite) {
					if (write(fdfile, (void *) &buf[0], n) != n) {
						flatz_close();
						return ERROR_CODE();
					}
				}
			}

			if (dowrite)
				close(fdfile);
		}

		/* Read alignment padding */
		n = ((ent.filelen + 3) & ~0x3) - ent.filelen;
		if (flatz_read(&buf[0], n) != n) {
			flatz_close();
			return ERROR_CODE();
		}

		numbytes += ent.filelen;
	}

	flatz_close();

	return 0;
}

/*****************************************************************************/

/*
 * Restore the flat filesystem contents with the most up-to-date config
 * that can be found in the flash parition. For partitions with 2 images
 * we pick the most recent. If 'dowrite' is zero then we don't actually
 * restore the files, merely check that the save fs is valid.
 */

int flat3_restorefs(int version, int dowrite)
{
	struct flathdr3 hdr[2];
	unsigned int off, psize;
	int part, nrparts, rc;

	part = 0;
	psize = flat_dev_length() / 2;

	/* Figure out how many partitions we can have */
	nrparts = 2;
	psize = flat_dev_length();
	if ((psize / flat_dev_erase_length()) <= 1)
		nrparts = 1;
	else
		psize /= 2;

	/* Get base header, and see how many partitions we have */
	rc = flat3_gethdroffset(0, &hdr[0]);
	if (hdr[0].magic != FLATFS_MAGIC_V3)
		memset(&hdr[0], 0, sizeof(hdr[0]));

	if ((hdr[0].nrparts == 2) || (nrparts == 2)) {
		/* Get other header, if not valid then use base header */
		if ((rc = flat3_gethdroffset(psize, &hdr[1])) != 0) {
			memset(&hdr[1], 0, sizeof(hdr[0]));
			goto dobase;
		}

		/* Use which ever is most recent */
		if (hdr[1].tstamp > hdr[0].tstamp)
			part = 1;

		off = (part) ? psize : 0;

		if ((rc = flat3_restorefsoffset(off, dowrite)) >= 0) {
			numvalid = part;
			numstamp = hdr[part].tstamp;
			if (dowrite) {
#ifdef LOGGING
				char ecmd[64];
				sprintf(ecmd, "/bin/logd read-partition %d, tstamp=%d",
					part, hdr[part].tstamp);
				system(ecmd);
#endif
				syslog(LOG_INFO, "restore fs- from partition "
					"%d, tstamp=%d", part, numstamp);
			}
			return rc;
		}

#ifdef LOGGING
		/*
		 * I am adding a logd message so we catch this in the flash
		 * log. It would not normally happen, so if it does we should
		 * know about it.
		 */
		if (dowrite) {
			char ecmd[64];
			sprintf(ecmd, "/bin/logd message restore partition "
				"%d failed, tstamp=%d", part, hdr[part].tstamp);
			system(ecmd);
		}
#endif
		/* Falling through to other partition */
		part = (part) ? 0 : 1;
	}

dobase:
	if (hdr[part].magic != FLATFS_MAGIC_V3)
		return ERROR_CODE();

	off = (part) ? psize : 0;
	rc = flat3_restorefsoffset(off, dowrite);
	numvalid = part;
	numstamp = hdr[part].tstamp;
	if (dowrite) {
#ifdef LOGGING
		char ecmd[64];
		sprintf(ecmd, "/bin/logd read-partition %d, tstamp=%d",
			part, hdr[part].tstamp);
		system(ecmd);
#endif
		syslog(LOG_INFO, "restore fs+ from partition %d, tstamp=%d",
			part, numstamp);
	}
	return rc;
}

/*****************************************************************************/

static int writefile(char *name, unsigned int *ptotal, int dowrite)
{
	struct flatent ent;
	struct stat st;
	unsigned int size;
	int fdfile, zero = 0;
	mode_t mode;
	char buf[BUF_SIZE];
	int n, written;

	/*
	 * Write file entry into flat fs. Names and file
	 * contents are aligned on long word boundaries.
	 * They are padded to that length with zeros.
	 */
	if (stat(name, &st) < 0)
		return ERROR_CODE();

	size = strlen(name) + 1;
	if (size > 128) {
		numdropped++;
		return ERROR_CODE();
	}

	ent.namelen = size;
	ent.filelen = st.st_size;
	if (flatz_write((char *) &ent, sizeof(ent), dowrite) < 0)
		return ERROR_CODE();

	/* Write file name out, with padding to align */
	if (flatz_write(name, size, dowrite) < 0)
		return ERROR_CODE();
	size = ((size + 3) & ~0x3) - size;
	if (flatz_write((char *)&zero, size, dowrite) < 0)
		return ERROR_CODE();

	/* Write out the permissions */
	mode = (mode_t) st.st_mode;
	size = sizeof(mode);
	if (flatz_write((char *) &mode, size, dowrite) < 0)
		return ERROR_CODE();

	/* Write the contents of the file. */
	size = st.st_size;

	written = 0;

	if (size > 0) {
		if ((fdfile = open(name, O_RDONLY)) < 0)
			return ERROR_CODE();
		while (size>written) {
			int bytes_read;
			n = ((size-written) > sizeof(buf))?sizeof(buf):(size-written);
			if ((bytes_read = read(fdfile, buf, n)) != n) {
				/* Somebody must have trunced the file. */
				syslog(LOG_WARNING, "File %s was shorter than "
					"expected.", name);
				if (bytes_read <= 0)
					break;
			}
			if (flatz_write(buf, bytes_read, dowrite) < 0) {
				close(fdfile);
				return ERROR_CODE();
			}
			written += bytes_read;
		}
		if (lseek(fdfile, 0, SEEK_END) != written) {
			/* 
			 * Log the file being longer than expected.
			 * We can't write more than expected because the size
			 * is already written.
			 */
			syslog(LOG_WARNING, "File %s was longer than expected.", name);
		}
		close(fdfile);

		/* Pad to align */
		written = ((st.st_size + 3) & ~0x3)- st.st_size;
		if (flatz_write((char *)&zero, written, dowrite) < 0)
			return ERROR_CODE();
	}

	numfiles++;

	return 0;
}

/*****************************************************************************/

/*
 * Writes out the contents of all files. Does not actually do the write
 * if 'dowrite' is not set. In this case, it just checks to see that the
 * config will fit. The total length of data written (or simulated) is
 * stored in *total. Does not remove .flatfsd
 *
 * Note that if the flash has been erased, aborting early will just lose
 * data. So we try to work around problems as much as possible.
 *
 * Returns 0 if OK, or < 0 if error.
 */

int flat3_savefsoffset(int dowrite, off_t off, size_t len, int nrparts, unsigned *total)
{
	struct flathdr3 hdr;
	struct flatent ent;
	struct dirent *dp;
	DIR *dirp;
	int rc, ret = 0;

#ifdef DEBUG
	syslog(LOG_DEBUG, "flat3_savefsoffset(dowrite=%d)", dowrite);
#endif

	if (dowrite) {
		/* Lets erase the relevant flash segments */
		if ((rc = flat_dev_erase(off, len)) < 0)
			return rc;
	}

	/* Write out contents of all files, skip over header */
	numfiles = 0;
	numbytes = 0;
	numdropped = 0;
	*total = sizeof(hdr);

	if ((rc = flatz_open("w")) < 0) {
		syslog(LOG_ERR, "Couldn't init compression engine\n");
		return rc;
	}

	flatzfs.offset = off + sizeof(hdr);

#ifndef HAS_RTC
	rc = writefile(FLATFSD_CONFIG, total, dowrite);
	if ((rc < 0) && !ret)
		ret = rc;
#endif

	/* Scan directory */
	if ((dirp = opendir(".")) == NULL) {
		rc = ERROR_CODE();
		if ((rc < 0) && !ret)
			ret = rc;
		flatz_close();
		/* Really nothing we can do at this point */
		return ret;
	}

	while ((dp = readdir(dirp)) != NULL) {

		if ((strcmp(dp->d_name, ".") == 0) ||
		    (strcmp(dp->d_name, "..") == 0) ||
		    (strcmp(dp->d_name, FLATFSD_CONFIG) == 0))
			continue;

		rc = writefile(dp->d_name, total, dowrite);
		if (rc < 0) {
			syslog(LOG_ERR, "Failed to write write file %s "
				"(%d): %m %d", dp->d_name, rc, errno);
			if (!ret)
				ret = rc;
		}
	}
	closedir(dirp);

	/* Write the terminating entry */
	ent.namelen = FLATFS_EOF;
	ent.filelen = FLATFS_EOF;
	rc = flatz_write((char *) &ent, sizeof(ent), dowrite);
	if (rc < 0 && !ret)
		ret = rc;

	flatz_finalise(dowrite);

	*total += flatzfs.strm.total_out;

	if (dowrite) {
		/* Construct header */
		hdr.magic = FLATFS_MAGIC_V3;
		hdr.chksum = 0;
		hdr.nrparts = nrparts;
		hdr.tstamp = ++numstamp;

		rc = flat_dev_write(off, (char *)&hdr, sizeof(hdr));
		if ((rc < 0) && !ret)
			ret = rc;
	}

#ifdef DEBUG
	syslog(LOG_DEBUG, "flat3_savefsoffset(): returning ret=%d, total=%u",
		ret, *total);
#endif

	flatz_close();
	return ret;
}

/*****************************************************************************/

/*
 * Write out the filesystem to flash/disk. If we store 2 parititions then
 * we need to figure out which one to write too. Run through a restorefs
 * (with no writing) to make sure we replace the oldest image.
 */

int flat3_savefs(int dowrite, unsigned int *total)
{
	struct flathdr3 hdr[2];
	unsigned int off, size, psize;
	int nrparts, part, rc;

	part = 0;
	numvalid = -1;
	numstamp = 0;

	/* Figure out how many partitions we can have */
	nrparts = 2;
	size = psize = flat_dev_length();
	if ((size / flat_dev_erase_length()) <= 1)
		nrparts = 1;

	/* Figure out which partition to use */
	if (nrparts > 1) {
		psize = size / 2;
		flat3_gethdroffset(0, &hdr[0]);
		flat3_gethdroffset(psize, &hdr[1]);

		/* Choose a partition */
		if (hdr[0].magic != FLATFS_MAGIC_V3)
			part = 0;
		else if (hdr[1].magic != FLATFS_MAGIC_V3)
			part = 1;
		else if (hdr[0].tstamp == 0xffffffff)
			part = 0;
		else if (hdr[1].tstamp == 0xffffffff)
			part = 1;
		else if (hdr[0].tstamp > hdr[1].tstamp)
			part = 1;
		else
			part = 0;

		/* Set highest current tstamp */
		if (hdr[0].tstamp == 0xffffffff)
			hdr[0].tstamp = 0;
		if (hdr[1].tstamp == 0xffffffff)
			hdr[1].tstamp = 0;
		if (hdr[1].tstamp > hdr[0].tstamp)
			numstamp = hdr[1].tstamp;
		else
			numstamp = hdr[0].tstamp;
	}

	off = (part) ? psize : 0;
	if (dowrite) {
#ifdef LOGGING
		char ecmd[64];
		sprintf(ecmd, "/bin/logd write-partition %d, tstamp=%d",
			part, numstamp+1);
		system(ecmd);
#endif
		syslog(LOG_INFO, "saving fs to partition %d, tstamp=%d\n",
			part, numstamp+1);
	}
	
	rc = flat3_savefsoffset(dowrite, off, psize, nrparts, total);
	return rc;
}

/*****************************************************************************/
