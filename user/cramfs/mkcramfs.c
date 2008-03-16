/* vi: set sw=8 ts=8: */
/*
 * mkcramfs - make a cramfs file system
 *
 * Copyright (C) 1999-2002 Transmeta Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Added device table support (code taken from mkfs.jffs2.c, credit to
 * Erik Andersen <andersen@codepoet.org>) as well as an option to squash
 * permissions. - Russ Dill <Russ.Dill@asu.edu> September 2002
 *
 * Reworked, cleaned up, and updated for cramfs-1.1, December 2002
 *  - Erik Andersen <andersen@codepoet.org>
 *
 */

/*
 * If you change the disk format of cramfs, please update fs/cramfs/README.
 */

#define _GNU_SOURCE
#include <sys/types.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <dirent.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <libgen.h>
#include <ctype.h>
#include <assert.h>
#include <getopt.h>
#include <linux/cramfs_fs.h>
#include <zlib.h>
#ifdef DMALLOC
#include <dmalloc.h>
#endif

#ifndef MAP_ANONYMOUS
# define MAP_ANONYMOUS MAP_ANON
#endif

/* Exit codes used by mkfs-type programs */
#define MKFS_OK          0	/* No errors */
#define MKFS_ERROR       8	/* Operational error */
#define MKFS_USAGE       16	/* Usage or syntax error */

/* The kernel only supports PAD_SIZE of 0 and 512. */
#define PAD_SIZE 512

/* The kernel assumes PAGE_CACHE_SIZE as block size. */
#define PAGE_CACHE_SIZE (4096)

/*
 * The longest filename component to allow for in the input directory tree.
 * ext2fs (and many others) allow up to 255 bytes.  A couple of filesystems
 * allow longer (e.g. smbfs 1024), but there isn't much use in supporting
 * >255-byte names in the input directory tree given that such names get
 * truncated to CRAMFS_MAXPATHLEN (252 bytes) when written to cramfs.
 *
 * Old versions of mkcramfs generated corrupted filesystems if any input
 * filenames exceeded CRAMFS_MAXPATHLEN (252 bytes), however old
 * versions of cramfsck seem to have been able to detect the corruption.
 */
#define MAX_INPUT_NAMELEN 255

/*
 * Maximum size fs you can create is roughly 256MB.  (The last file's
 * data must begin within 256MB boundary but can extend beyond that.)
 *
 * Note that if you want it to fit in a ROM then you're limited to what the
 * hardware and kernel can support.
 */
#define MAXFSLEN ((((1 << CRAMFS_OFFSET_WIDTH) - 1) << 2) /* offset */ \
		  + (1 << CRAMFS_SIZE_WIDTH) - 1 /* filesize */ \
		  + (1 << CRAMFS_SIZE_WIDTH) * 4 / PAGE_CACHE_SIZE /* block pointers */ )


/* The kernel assumes PAGE_CACHE_SIZE as block size. */
#define PAGE_CACHE_SIZE (4096)


static const char *progname = "mkcramfs";
static unsigned int blksize = PAGE_CACHE_SIZE;
static long total_blocks = 0, total_nodes = 1; /* pre-count the root node */
static int image_length = 0;


/*
 * If opt_holes is set, then mkcramfs can create explicit holes in the
 * data, which saves 26 bytes per hole (which is a lot smaller a
 * saving than most most filesystems).
 *
 * Note that kernels up to at least 2.3.39 don't support cramfs holes,
 * which is why this is turned off by default.
 *
 * If opt_verbose is 1, be verbose.  If it is higher, be even more verbose.
 */
static u32 opt_edition = 0;
static int opt_errors = 0;
static int opt_holes = 0;
static int opt_pad = 0;
static int opt_verbose = 0;
static int opt_squash = 0;
static char *opt_image = NULL;
static char *opt_name = NULL;

static int warn_dev, warn_gid, warn_namelen, warn_skip, warn_size, warn_uid;
static const char *const memory_exhausted = "memory exhausted";

/* In-core version of inode / directory entry. */
struct entry {
	/* stats */
	unsigned char *name;
	unsigned int mode, size, uid, gid;

	/* these are only used for non-empty files */
	char *path;		/* always null except non-empty files */
	int fd;			/* temporarily open files while mmapped */

	/* FS data */
	void *uncompressed;
	/* points to other identical file */
	struct entry *same;
	unsigned int offset;		/* pointer to compressed data in archive */
	unsigned int dir_offset;	/* Where in the archive is the directory entry? */

	/* organization */
	struct entry *child; /* null for non-directories and empty directories */
	struct entry *next;
};

/* Input status of 0 to print help and exit without an error. */
static void usage(int status)
{
	FILE *stream = status ? stderr : stdout;

	fprintf(stream, "usage: %s [-h] [-e edition] [-i file] [-n name] [-D file] dirname outfile\n"
		" -h         print this help\n"
		" -E         make all warnings errors (non-zero exit status)\n"
		" -e edition set edition number (part of fsid)\n"
		" -i file    insert a file image into the filesystem (requires >= 2.4.0)\n"
		" -n name    set name of cramfs filesystem\n"
		" -p         pad by %d bytes for boot code\n"
		" -s         sort directory entries (old option, ignored)\n"
		" -v         be more verbose\n"
		" -z         make explicit holes (requires >= 2.3.39)\n"
		" -D         Use the named FILE as a device table file\n"
		" -q         squash permissions (make everything owned by root)\n"
		" dirname    root of the filesystem to be compressed\n"
		" outfile    output file\n", progname, PAD_SIZE);

	exit(status);
}

static void verror_msg(const char *s, va_list p)
{
	fflush(stdout);
	fprintf(stderr, "mkcramfs: ");
	vfprintf(stderr, s, p);
}

static void vperror_msg(const char *s, va_list p)
{
	int err = errno;

	if (s == 0)
		s = "";
	verror_msg(s, p);
	if (*s)
		s = ": ";
	fprintf(stderr, "%s%s\n", s, strerror(err));
}

static void perror_msg(const char *s, ...)
{
	va_list p;

	va_start(p, s);
	vperror_msg(s, p);
	va_end(p);
}

static void error_msg_and_die(const char *s, ...)
{
	va_list p;

	va_start(p, s);
	verror_msg(s, p);
	va_end(p);
	putc('\n', stderr);
	exit(MKFS_ERROR);
}

static void perror_msg_and_die(const char *s, ...)
{
	va_list p;

	va_start(p, s);
	vperror_msg(s, p);
	va_end(p);
	exit(MKFS_ERROR);
}
#ifndef DMALLOC
extern char *xstrdup(const char *s)
{
	char *t;

	if (s == NULL)
		return NULL;
	t = strdup(s);
	if (t == NULL)
		error_msg_and_die(memory_exhausted);
	return t;
}

extern void *xmalloc(size_t size)
{
	void *ptr = malloc(size);

	if (ptr == NULL && size != 0)
		error_msg_and_die(memory_exhausted);
	return ptr;
}

extern void *xcalloc(size_t nmemb, size_t size)
{
	void *ptr = calloc(nmemb, size);

	if (ptr == NULL && nmemb != 0 && size != 0)
		error_msg_and_die(memory_exhausted);
	return ptr;
}

extern void *xrealloc(void *ptr, size_t size)
{
	ptr = realloc(ptr, size);
	if (ptr == NULL && size != 0)
		error_msg_and_die(memory_exhausted);
	return ptr;
}
#endif

static FILE *xfopen(const char *path, const char *mode)
{
	FILE *fp;

	if ((fp = fopen(path, mode)) == NULL)
		perror_msg_and_die("%s", path);
	return fp;
}

extern int xopen(const char *pathname, int flags, mode_t mode)
{
	int ret;
	
	if (flags & O_CREAT)
		ret = open(pathname, flags, mode);
	else
		ret = open(pathname, flags);
	if (ret == -1) {
		perror_msg_and_die("%s", pathname);
	}
	return ret;
}

extern char *xreadlink(const char *path)
{                       
	static const int GROWBY = 80; /* how large we will grow strings by */

	char *buf = NULL;   
	int bufsize = 0, readsize = 0;

	do {
		buf = xrealloc(buf, bufsize += GROWBY);
		readsize = readlink(path, buf, bufsize); /* 1st try */
		if (readsize == -1) {
		    perror_msg("%s:%s", progname, path);
		    return NULL;
		}
	}           
	while (bufsize < readsize + 1);

	buf[readsize] = '\0';

	return buf;
}       

static void map_entry(struct entry *entry)
{
	if (entry->path) {
		entry->fd = open(entry->path, O_RDONLY);
		if (entry->fd < 0) {
			error_msg_and_die("open failed: %s", entry->path);
		}
		entry->uncompressed = mmap(NULL, entry->size, PROT_READ, MAP_PRIVATE, entry->fd, 0);
		if (entry->uncompressed == MAP_FAILED) {
			error_msg_and_die("mmap failed: %s", entry->path);
		}
	}
}

static void unmap_entry(struct entry *entry)
{
	if (entry->path) {
		if (munmap(entry->uncompressed, entry->size) < 0) {
			error_msg_and_die("munmap failed: %s", entry->path);
		}
		entry->uncompressed=NULL;
		close(entry->fd);
	}
}

static int find_identical_file(struct entry *orig, struct entry *newfile)
{
	if (orig == newfile)
		return 1;
	if (!orig)
		return 0;
	if (orig->size == newfile->size && (orig->path || orig->uncompressed))
	{
		map_entry(orig);
		map_entry(newfile);
		if (!memcmp(orig->uncompressed, newfile->uncompressed, orig->size))
		{
			newfile->same = orig;
			unmap_entry(newfile);
			unmap_entry(orig);
			return 1;
		}
		unmap_entry(newfile);
		unmap_entry(orig);
	}
	return (find_identical_file(orig->child, newfile) ||
		find_identical_file(orig->next, newfile));
}

static void eliminate_doubles(struct entry *root, struct entry *orig) 
{
	if (orig) {
		if (orig->size && (orig->path || orig->uncompressed))
			find_identical_file(root, orig);
		eliminate_doubles(root, orig->child);
		eliminate_doubles(root, orig->next);
	}
}

/*
 * We define our own sorting function instead of using alphasort which
 * uses strcoll and changes ordering based on locale information.
 */
static int cramsort (const void *a, const void *b)
{
	return strcmp ((*(const struct dirent **) a)->d_name,
		       (*(const struct dirent **) b)->d_name);
}

static unsigned int parse_directory(struct entry *root_entry, const char *name, struct entry **prev, off_t *fslen_ub)
{
	struct dirent **dirlist;
	int totalsize = 0, dircount, dirindex;
	char *path, *endpath;
	size_t len = strlen(name);

	/* Set up the path. */
	/* TODO: Reuse the parent's buffer to save memcpy'ing and duplication. */
	path = xmalloc(len + 1 + MAX_INPUT_NAMELEN + 1);
	memcpy(path, name, len);
	endpath = path + len;
	*endpath = '/';
	endpath++;

	/* read in the directory and sort */
	dircount = scandir(name, &dirlist, 0, cramsort);

	if (dircount < 0) {
		error_msg_and_die("scandir failed: %s", name);
	}

	/* process directory */
	for (dirindex = 0; dirindex < dircount; dirindex++) {
		struct dirent *dirent;
		struct entry *entry;
		struct stat st;
		int size;
		size_t namelen;

		dirent = dirlist[dirindex];

		/* Ignore "." and ".." - we won't be adding them to the archive */
		if (dirent->d_name[0] == '.') {
			if (dirent->d_name[1] == '\0')
				continue;
			if (dirent->d_name[1] == '.') {
				if (dirent->d_name[2] == '\0')
					continue;
			}
		}
		namelen = strlen(dirent->d_name);
		if (namelen > MAX_INPUT_NAMELEN) {
			error_msg_and_die(
				"Very long (%u bytes) filename `%s' found.\n"
				" Please increase MAX_INPUT_NAMELEN in mkcramfs.c and recompile.  Exiting.\n",
				namelen, dirent->d_name);
		}
		memcpy(endpath, dirent->d_name, namelen + 1);

		if (lstat(path, &st) < 0) {
			perror(endpath);
			warn_skip = 1;
			continue;
		}
		entry = xcalloc(1, sizeof(struct entry));
		entry->name = xstrdup(dirent->d_name);
		/* truncate multi-byte UTF-8 filenames on character boundary */
		if (namelen > CRAMFS_MAXPATHLEN) {
			namelen = CRAMFS_MAXPATHLEN;
			warn_namelen = 1;
			/* the first lost byte must not be a trail byte */
			while ((entry->name[namelen] & 0xc0) == 0x80) {
				namelen--;
				/* are we reasonably certain it was UTF-8 ? */
				if (entry->name[namelen] < 0x80 || !namelen) {
					error_msg_and_die("cannot truncate filenames not encoded in UTF-8");
				}
			}
			entry->name[namelen] = '\0';
		}
		entry->mode = st.st_mode;
		entry->size = st.st_size;
		entry->uid = opt_squash ? 0 : st.st_uid;
		if (entry->uid >= 1 << CRAMFS_UID_WIDTH)
			warn_uid = 1;
		entry->gid = opt_squash ? 0 : st.st_gid;
		if (entry->gid >= 1 << CRAMFS_GID_WIDTH) {
			/* TODO: We ought to replace with a default
			   gid instead of truncating; otherwise there
			   are security problems.  Maybe mode should
			   be &= ~070.  Same goes for uid once Linux
			   supports >16-bit uids. */
			warn_gid = 1;
		}
		size = sizeof(struct cramfs_inode) + ((namelen + 3) & ~3);
		*fslen_ub += size;
		if (S_ISDIR(st.st_mode)) {
			entry->size = parse_directory(root_entry, path, &entry->child, fslen_ub);
		} else if (S_ISREG(st.st_mode)) {
			if (entry->size) {
				if (access(path, R_OK) < 0) {
					warn_skip = 1;
					continue;
				}
				entry->path = xstrdup(path);
				if ((entry->size >= 1 << CRAMFS_SIZE_WIDTH)) {
					warn_size = 1;
					entry->size = (1 << CRAMFS_SIZE_WIDTH) - 1;
				}
			}
		} else if (S_ISLNK(st.st_mode)) {
			entry->uncompressed = xreadlink(path);
			if (!entry->uncompressed) {
				warn_skip = 1;
				continue;
			}
		} else if (S_ISFIFO(st.st_mode) || S_ISSOCK(st.st_mode)) {
			/* maybe we should skip sockets */
			entry->size = 0;
		} else if (S_ISCHR(st.st_mode) || S_ISBLK(st.st_mode)) {
			entry->size = st.st_rdev;
			if (entry->size & -(1<<CRAMFS_SIZE_WIDTH))
				warn_dev = 1;
		} else {
			error_msg_and_die("bogus file type: %s", entry->name);
		}

		if (S_ISREG(st.st_mode) || S_ISLNK(st.st_mode)) {
			int blocks = ((entry->size - 1) / blksize + 1);

			/* block pointers & data expansion allowance + data */
			if (entry->size)
				*fslen_ub += (4+26)*blocks + entry->size + 3;
		}

		/* Link it into the list */
		*prev = entry;
		prev = &entry->next;
		totalsize += size;
	}
	free(path);
	free(dirlist);		/* allocated by scandir() with malloc() */
	return totalsize;
}

/* Returns sizeof(struct cramfs_super), which includes the root inode. */
static unsigned int write_superblock(struct entry *root, char *base, int size)
{
	struct cramfs_super *super = (struct cramfs_super *) base;
	unsigned int offset = sizeof(struct cramfs_super) + image_length;

	if (opt_pad) {
		offset += opt_pad;	/* 0 if no padding */
	}

	super->magic = CRAMFS_32(CRAMFS_MAGIC);
	super->flags = CRAMFS_FLAG_FSID_VERSION_2 | CRAMFS_FLAG_SORTED_DIRS;
	if (opt_holes)
		super->flags |= CRAMFS_FLAG_HOLES;
	if (image_length > 0)
		super->flags |= CRAMFS_FLAG_SHIFTED_ROOT_OFFSET;
	super->flags = CRAMFS_32(super->flags);
	super->size = CRAMFS_32(size);
	memcpy(super->signature, CRAMFS_SIGNATURE, sizeof(super->signature));

	super->fsid.crc = CRAMFS_32(crc32(0L, Z_NULL, 0));
	super->fsid.edition = CRAMFS_32(opt_edition);
	super->fsid.blocks = CRAMFS_32(total_blocks);
	super->fsid.files = CRAMFS_32(total_nodes);

	memset(super->name, 0x00, sizeof(super->name));
	if (opt_name)
		strncpy(super->name, opt_name, sizeof(super->name));
	else
		strncpy(super->name, "Compressed", sizeof(super->name));

	super->root.mode = CRAMFS_16(root->mode);
	super->root.uid = CRAMFS_16(root->uid);
	super->root.gid = root->gid;
	super->root.size = CRAMFS_24(root->size);
	CRAMFS_SET_OFFSET(&(super->root), offset >> 2);

	return offset;
}

static void set_data_offset(struct entry *entry, char *base, unsigned long offset)
{
	struct cramfs_inode *inode = (struct cramfs_inode *) (base + entry->dir_offset);

	if ((offset & 3) != 0) {
		error_msg_and_die("illegal offset of %lu bytes", offset);
	}
	if (offset >= (1 << (2 + CRAMFS_OFFSET_WIDTH))) {
		error_msg_and_die("filesystem too big");
	}
	CRAMFS_SET_OFFSET(inode, offset >> 2);
}

/*
 * TODO: Does this work for chars >= 0x80?  Most filesystems use UTF-8
 * encoding for filenames, whereas the console is a single-byte
 * character set like iso-latin-1.
 */
static void print_node(struct entry *e)
{
	char info[12];
	char type = '?';

	if (S_ISREG(e->mode)) type = 'f';
	else if (S_ISDIR(e->mode)) type = 'd';
	else if (S_ISLNK(e->mode)) type = 'l';
	else if (S_ISCHR(e->mode)) type = 'c';
	else if (S_ISBLK(e->mode)) type = 'b';
	else if (S_ISFIFO(e->mode)) type = 'p';
	else if (S_ISSOCK(e->mode)) type = 's';

	if (S_ISCHR(e->mode) || (S_ISBLK(e->mode))) {
		/* major/minor numbers can be as high as 2^12 or 4096 */
		snprintf(info, 11, "%4d,%4d", major(e->size), minor(e->size));
	}
	else {
		/* size be as high as 2^24 or 16777216 */
		snprintf(info, 11, "%9d", e->size);
	}

	printf("%c %04o %s %5d:%-3d %s\n",
	       type, e->mode & ~S_IFMT, info, e->uid, e->gid, e->name);
}

/*
 * We do a width-first printout of the directory
 * entries, using a stack to remember the directories
 * we've seen.
 */
static unsigned int write_directory_structure(struct entry *entry, char *base, unsigned int offset)
{
	int stack_entries = 0;
	int stack_size = 64;
	struct entry **entry_stack = NULL;

	entry_stack = xmalloc(stack_size * sizeof(struct entry *));
	for (;;) {
		int dir_start = stack_entries;
		while (entry) {
			struct cramfs_inode *inode = (struct cramfs_inode *) (base + offset);
			size_t len = strlen(entry->name);

			entry->dir_offset = offset;

			inode->mode = CRAMFS_16(entry->mode);
			inode->uid = CRAMFS_16(entry->uid);
			inode->gid = entry->gid;
			inode->size = CRAMFS_24(entry->size);
			inode->offset = 0;
			/* Non-empty directories, regfiles and symlinks will
			   write over inode->offset later. */

			offset += sizeof(struct cramfs_inode);
			total_nodes++;	/* another node */
			memcpy(base + offset, entry->name, len);
			/* Pad up the name to a 4-byte boundary */
			while (len & 3) {
				*(base + offset + len) = '\0';
				len++;
			}
			CRAMFS_SET_NAMELEN(inode, len >> 2);
			offset += len;

			if (opt_verbose)
				print_node(entry);

			if (entry->child) {
				if (stack_entries >= stack_size) {
					stack_size *= 2;
					entry_stack = xrealloc(entry_stack, stack_size * sizeof(struct entry *));
				}
				entry_stack[stack_entries] = entry;
				stack_entries++;
			}
			entry = entry->next;
		}

		/*
		 * Reverse the order the stack entries pushed during
		 * this directory, for a small optimization of disk
		 * access in the created fs.  This change makes things
		 * `ls -UR' order.
		 */
		{
			struct entry **lo = entry_stack + dir_start;
			struct entry **hi = entry_stack + stack_entries;
			struct entry *tmp;

			while (lo < --hi) {
				tmp = *lo;
				*lo++ = *hi;
				*hi = tmp;
			}
		}

		/* Pop a subdirectory entry from the stack, and recurse. */
		if (!stack_entries)
			break;
		stack_entries--;
		entry = entry_stack[stack_entries];

		set_data_offset(entry, base, offset);
		if (opt_verbose) {
		    printf("'%s':\n", entry->name);
		}
		entry = entry->child;
	}
	free(entry_stack);
	return offset;
}

static int is_zero(char const *begin, unsigned len)
{
	if (opt_holes)
		/* Returns non-zero iff the first LEN bytes from BEGIN are
		   all NULs. */
		return (len-- == 0 ||
			(begin[0] == '\0' &&
			 (len-- == 0 ||
			  (begin[1] == '\0' &&
			   (len-- == 0 ||
			    (begin[2] == '\0' &&
			     (len-- == 0 ||
			      (begin[3] == '\0' &&
			       memcmp(begin, begin + 4, len) == 0))))))));
	else
		/* Never create holes. */
		return 0;
}

/*
 * One 4-byte pointer per block and then the actual blocked
 * output. The first block does not need an offset pointer,
 * as it will start immediately after the pointer block;
 * so the i'th pointer points to the end of the i'th block
 * (i.e. the start of the (i+1)'th block or past EOF).
 *
 * Note that size > 0, as a zero-sized file wouldn't ever
 * have gotten here in the first place.
 */
static unsigned int do_compress(char *base, unsigned int offset, struct entry *entry)
{
	unsigned int size = entry->size;
	unsigned long original_size = size;
	unsigned long original_offset = offset;
	unsigned long new_size;
	unsigned long blocks = (size - 1) / blksize + 1;
	unsigned long curr = offset + 4 * blocks;
	int change;
	char *uncompressed = entry->uncompressed;

	total_blocks += blocks; 

	do {
		unsigned long len = 2 * blksize;
		unsigned int input = size;
		if (input > blksize)
			input = blksize;
		size -= input;
		if (!is_zero (uncompressed, input)) {
			compress(base + curr, &len, uncompressed, input);
			curr += len;
		}
		uncompressed += input;

		if (len > blksize*2) {
			/* (I don't think this can happen with zlib.) */
			error_msg_and_die("AIEEE: block \"compressed\" to > 2*blocklength (%ld)\n", len);
		}

		*(u32 *) (base + offset) = CRAMFS_32(curr);
		offset += 4;
	} while (size);

	curr = (curr + 3) & ~3;
	new_size = curr - original_offset;
	/* TODO: Arguably, original_size in these 2 lines should be
	   st_blocks * 512.  But if you say that then perhaps
	   administrative data should also be included in both. */
	change = new_size - original_size;
#if 0
	if (opt_verbose) {
	    printf("%6.2f%% (%+d bytes)\t%s\n",
		    (change * 100) / (double) original_size, change, entry->name);
	}
#endif

	return curr;
}


/*
 * Traverse the entry tree, writing data for every item that has
 * non-null entry->path (i.e. every non-empty regfile) and non-null
 * entry->uncompressed (i.e. every symlink).
 */
static unsigned int write_data(struct entry *entry, char *base, unsigned int offset)
{
	do {
		if (entry->path || entry->uncompressed) {
			if (entry->same) {
				set_data_offset(entry, base, entry->same->offset);
				entry->offset = entry->same->offset;
			}
			else {
				set_data_offset(entry, base, offset);
				entry->offset = offset;
				map_entry(entry);
				offset = do_compress(base, offset, entry);
				unmap_entry(entry);
			}
		}
		else if (entry->child)
			offset = write_data(entry->child, base, offset);
		entry=entry->next;
	} while (entry);
	return offset;
}

static unsigned int write_file(char *file, char *base, unsigned int offset)
{
	int fd;
	char *buf;

	fd = xopen(file, O_RDONLY, 0);
	buf = mmap(NULL, image_length, PROT_READ, MAP_PRIVATE, fd, 0);
	if (buf == MAP_FAILED) {
		error_msg_and_die("mmap failed");
	}
	memcpy(base + offset, buf, image_length);
	munmap(buf, image_length);
	close (fd);
	/* Pad up the image_length to a 4-byte boundary */
	while (image_length & 3) {
		*(base + offset + image_length) = '\0';
		image_length++;
	}
	return (offset + image_length);
}

static struct entry *find_filesystem_entry(struct entry *dir, char *name, mode_t type)
{
	struct entry *e = dir;

	if (S_ISDIR(dir->mode)) {
		e = dir->child;
	}
	while (e) {
		/* Only bother to do the expensive strcmp on matching file types */
		if (type == (e->mode & S_IFMT) && e->name) {
			if (S_ISDIR(e->mode)) {
				int len = strlen(e->name);

				/* Check if we are a parent of the correct path */
				if (strncmp(e->name, name, len) == 0) {
					/* Is this an _exact_ match? */
					if (strcmp(name, e->name) == 0) {
						return (e);
					}
					/* Looks like we found a parent of the correct path */
					if (name[len] == '/') {
						if (e->child) {
							return (find_filesystem_entry (e, name + len + 1, type));
						} else {
							return NULL;
						}
					}
				}
			} else {
				if (strcmp(name, e->name) == 0) {
					return (e);
				}
			}
		}
		e = e->next;
	}
	return (NULL);
}

void modify_entry(char *full_path, unsigned long uid, unsigned long gid, 
	unsigned long mode, unsigned long rdev, struct entry *root, off_t *fslen_ub)
{
	char *name, *path, *full;
	struct entry *curr, *parent, *entry, *prev;
	
	full = xstrdup(full_path);
	path = xstrdup(dirname(full));
	name = full_path + strlen(path) + 1;
	free(full);
	if (strcmp(path, "/") == 0) {
		parent = root;
		name = full_path + 1;
	} else {
		if (!(parent = find_filesystem_entry(root, path+1, S_IFDIR)))
			error_msg_and_die("%s/%s: could not find parent\n", path, name);
	}
	if ((entry = find_filesystem_entry(parent, name, (mode & S_IFMT)))) {
		/* its there, just modify permissions */
		entry->mode = mode;
		entry->uid = uid;
		entry->gid = gid;
	} else { /* make a new entry */
	
		/* code partially replicated from parse_directory() */
		size_t namelen;
		if (S_ISREG(mode)) {
			error_msg_and_die("%s: regular file from device_table file must exist on disk!", full_path);
		}

		namelen = strlen(name);
		if (namelen > MAX_INPUT_NAMELEN) {
			error_msg_and_die(
				"Very long (%u bytes) filename `%s' found.\n"
				" Please increase MAX_INPUT_NAMELEN in mkcramfs.c and recompile.  Exiting.\n",
				namelen, name);
		}
		entry = xcalloc(1, sizeof(struct entry));
		entry->name = xstrdup(name);
		/* truncate multi-byte UTF-8 filenames on character boundary */
		if (namelen > CRAMFS_MAXPATHLEN) {
			namelen = CRAMFS_MAXPATHLEN;
			warn_namelen = 1;
			/* the first lost byte must not be a trail byte */
			while ((entry->name[namelen] & 0xc0) == 0x80) {
				namelen--;
				/* are we reasonably certain it was UTF-8 ? */
				if (entry->name[namelen] < 0x80 || !namelen) {
					error_msg_and_die("cannot truncate filenames not encoded in UTF-8");
				}
			}
			entry->name[namelen] = '\0';
		}
		entry->mode = mode;
		entry->uid = uid;
		entry->gid = gid;
		entry->size = 0;
		if (S_ISBLK(mode) || S_ISCHR(mode)) {
			entry->size = rdev;
			if (entry->size & -(1<<CRAMFS_SIZE_WIDTH))
				warn_dev = 1;
		}
		
		/* ok, now we have to backup and correct the size of all the entries above us */
		*fslen_ub += sizeof(struct cramfs_inode) + ((namelen + 3) & ~3);
		parent->size += sizeof(struct cramfs_inode) + ((namelen + 3) & ~3);

		/* alright, time to link us in */
		curr = parent->child;
		prev = NULL;
		while (curr && strcmp(name, curr->name) > 0) {
			prev = curr;
			curr = curr->next;
		}
		if (!prev) parent->child = entry;
		else prev->next = entry;
		entry->next = curr;
		entry->child = NULL;
	}
	if (entry->uid >= 1 << CRAMFS_UID_WIDTH)
		warn_uid = 1;
	if (entry->gid >= 1 << CRAMFS_GID_WIDTH) {
		/* TODO: We ought to replace with a default
		   gid instead of truncating; otherwise there
		   are security problems.  Maybe mode should
		   be &= ~070.  Same goes for uid once Linux
		   supports >16-bit uids. */
		warn_gid = 1;
	}
	free(path);
}

/* the GNU C library has a wonderful scanf("%as", string) which will
 allocate the string with the right size, good to avoid buffer overruns. 
 the following macros use it if available or use a hacky workaround...
 */

#ifdef __GNUC__
#define SCANF_PREFIX "a"
#define SCANF_STRING(s) (&s)
#define GETCWD_SIZE 0
#else
#define SCANF_PREFIX "511"
#define SCANF_STRING(s) (s = xmalloc(512))
#define GETCWD_SIZE -1
inline int snprintf(char *str, size_t n, const char *fmt, ...)
{
	int ret;
	va_list ap;

	va_start(ap, fmt);
	ret = vsprintf(str, fmt, ap);
	va_end(ap);
	return ret;
}
#endif

/*  device table entries take the form of:
    <path>	<type> <mode>	<uid>	<gid>	<major>	<minor>	<start>	<inc>	<count>
    /dev/mem     c    640       0       0         1       1       0     0         -

    type can be one of: 
	f	A regular file
	d	Directory
	c	Character special device file
	b	Block special device file
	p	Fifo (named pipe)

    I don't bother with symlinks (permissions are irrelevant), hard
    links (special cases of regular files), or sockets (why bother).

    Regular files must exist in the target root directory.  If a char,
    block, fifo, or directory does not exist, it will be created.
*/

static int interpret_table_entry(char *line, struct entry *root, off_t *fslen_ub)
{
	char type, *name = NULL;
	unsigned long mode = 0755, uid = 0, gid = 0, major = 0, minor = 0;
	unsigned long start = 0, increment = 1, count = 0;

	if (sscanf (line, "%" SCANF_PREFIX "s %c %lo %lu %lu %lu %lu %lu %lu %lu",
		 SCANF_STRING(name), &type, &mode, &uid, &gid, &major, &minor,
		 &start, &increment, &count) < 0) 
	{
		return 1;
	}

	if (!strcmp(name, "/")) {
		error_msg_and_die("Device table entries require absolute paths");
	}

	switch (type) {
	case 'd':
		mode |= S_IFDIR;
		modify_entry(name, uid, gid, mode, 0, root, fslen_ub);
		break;
	case 'f':
		mode |= S_IFREG;
		modify_entry(name, uid, gid, mode, 0, root, fslen_ub);
		break;
	case 'p':
		mode |= S_IFIFO;
		modify_entry(name, uid, gid, mode, 0, root, fslen_ub);
		break;
	case 'c':
	case 'b':
		mode |= (type == 'c') ? S_IFCHR : S_IFBLK;
		if (count > 0) {
			char *buf;
			unsigned long i;
			dev_t rdev;

			for (i = start; i < count; i++) {
				asprintf(&buf, "%s%lu", name, i);
				rdev = makedev(major, minor + (i * increment - start));
				modify_entry(buf, uid, gid, mode, rdev, root, fslen_ub);
				free(buf);
			}
		} else {
			dev_t rdev = makedev(major, minor);
			modify_entry(name, uid, gid, mode, rdev, root, fslen_ub);
		}
		break;
	default:
		error_msg_and_die("Unsupported file type");
	}
	free(name);
	return 0;
}

static int parse_device_table(FILE *file, struct entry *root, off_t *fslen_ub)
{
	char *line;
	int status = 0;
	size_t length = 0;

	/* Turn off squash, since we must ensure that values
	 * entered via the device table are not squashed */
	opt_squash = 0;

	/* Looks ok so far.  The general plan now is to read in one
	 * line at a time, check for leading comment delimiters ('#'),
	 * then try and parse the line as a device table.  If we fail
	 * to parse things, try and help the poor fool to fix their
	 * device table with a useful error msg... */
	line = NULL;
	while (getline(&line, &length, file) != -1) {
		/* First trim off any whitespace */
		int len = strlen(line);

		/* trim trailing whitespace */
		while (len > 0 && isspace(line[len - 1]))
			line[--len] = '\0';
		/* trim leading whitespace */
		memmove(line, &line[strspn(line, " \n\r\t\v")], len);

		/* How long are we after trimming? */
		len = strlen(line);

		/* If this is NOT a comment line, try to interpret it */
		if (len && *line != '#') {
			if (interpret_table_entry(line, root, fslen_ub))
				status = 1;
		}

		free(line);
		line = NULL;
	}
	free(line);
	fclose(file);

	return status;
}

void traverse(struct entry *entry, int depth)
{
	struct entry *curr = entry;
	int i;

	while (curr) {
		for (i = 0; i < depth; i++) putchar(' ');
		printf("%s: size=%d mode=%d same=%p\n",
			(curr->name)? (char*)curr->name : "/", 
			curr->size, curr->mode, curr->same);
		if (curr->child) traverse(curr->child, depth + 4);
		curr = curr->next;
	}
}

static void free_filesystem_entry(struct entry *dir)
{
	struct entry *e = dir, *last;

	if (S_ISDIR(dir->mode)) {
		e = dir->child;
	}
	while (e) {
		if (e->name)
			free(e->name);
		if (e->path)
			free(e->path);
		if (e->uncompressed)
			free(e->uncompressed);
		last = e;
		if (e->child) {
			free_filesystem_entry(e);
		}
		e = e->next;
		free(last);
	}
}


/*
 * Usage:
 *
 *      mkcramfs directory-name outfile
 *
 * where "directory-name" is simply the root of the directory
 * tree that we want to generate a compressed filesystem out
 * of.
 */
int main(int argc, char **argv)
{
	struct stat st;		/* used twice... */
	struct entry *root_entry;
	char *rom_image;
	ssize_t offset, written;
	int fd;
	/* initial guess (upper-bound) of required filesystem size */
	off_t fslen_ub = sizeof(struct cramfs_super);
	char const *dirname, *outfile;
	u32 crc;
	int c;			/* for getopt */
	char *ep;		/* for strtoul */
	FILE *devtable = NULL;

	total_blocks = 0;

	if (argc)
		progname = argv[0];

	/* command line options */
	while ((c = getopt(argc, argv, "hEe:i:n:psvzD:q")) != EOF) {
		switch (c) {
		case 'h':
			usage(MKFS_OK);
		case 'E':
			opt_errors = 1;
			break;
		case 'e':
			errno = 0;
			opt_edition = strtoul(optarg, &ep, 10);
			if (errno || optarg[0] == '\0' || *ep != '\0')
				usage(MKFS_USAGE);
			break;
		case 'i':
			opt_image = optarg;
			if (lstat(opt_image, &st) < 0) {
				error_msg_and_die("lstat failed: %s", opt_image);
			}
			image_length = st.st_size; /* may be padded later */
			fslen_ub += (image_length + 3); /* 3 is for padding */
			break;
		case 'n':
			opt_name = optarg;
			break;
		case 'p':
			opt_pad = PAD_SIZE;
			fslen_ub += PAD_SIZE;
			break;
		case 's':
			/* old option, ignored */
			break;
		case 'v':
			opt_verbose++;
			break;
		case 'z':
			opt_holes = 1;
			break;
		case 'q':
			opt_squash = 1;
			break;
		case 'D':
			devtable = xfopen(optarg, "r");
			if (fstat(fileno(devtable), &st) < 0)
				perror_msg_and_die(optarg);
			if (st.st_size < 10)
				error_msg_and_die("%s: not a proper device table file\n", optarg);
			break;
		}
	}

	if ((argc - optind) != 2)
		usage(MKFS_USAGE);
	dirname = argv[optind];
	outfile = argv[optind + 1];

	if (stat(dirname, &st) < 0) {
		error_msg_and_die("stat failed: %s", dirname);
	}
	fd = xopen(outfile, O_WRONLY | O_CREAT | O_TRUNC, 0666);

	root_entry = xcalloc(1, sizeof(struct entry));
	root_entry->mode = st.st_mode;
	root_entry->uid = st.st_uid;
	root_entry->gid = st.st_gid;

	root_entry->size = parse_directory(root_entry, dirname, &root_entry->child, &fslen_ub);

	if (devtable) {
		parse_device_table(devtable, root_entry, &fslen_ub);
	}

	/* always allocate a multiple of blksize bytes because that's
           what we're going to write later on */
	fslen_ub = ((fslen_ub - 1) | (blksize - 1)) + 1;

	if (fslen_ub > MAXFSLEN) {
		fprintf(stderr,
			"warning: estimate of required size (upper bound) is %LdMB, but maximum image size is %uMB, we might die prematurely\n",
			fslen_ub >> 20,
			MAXFSLEN >> 20);
		fslen_ub = MAXFSLEN;
	}

	/* find duplicate files. TODO: uses the most inefficient algorithm
	   possible. */
	eliminate_doubles(root_entry, root_entry);

	/* TODO: Why do we use a private/anonymous mapping here
	   followed by a write below, instead of just a shared mapping
	   and a couple of ftruncate calls?  Is it just to save us
	   having to deal with removing the file afterwards?  If we
	   really need this huge anonymous mapping, we ought to mmap
	   in smaller chunks, so that the user doesn't need nn MB of
	   RAM free.  If the reason is to be able to write to
	   un-mmappable block devices, then we could try shared mmap
	   and revert to anonymous mmap if the shared mmap fails. */
	rom_image = mmap(NULL, fslen_ub?fslen_ub:1, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if (rom_image == MAP_FAILED) {
		error_msg_and_die("mmap failed");
	}

	/* Skip the first opt_pad bytes for boot loader code */
	offset = opt_pad;
	memset(rom_image, 0x00, opt_pad);

	/* Skip the superblock and come back to write it later. */
	offset += sizeof(struct cramfs_super);

	/* Insert a file image. */
	if (opt_image) {
		printf("Including: %s\n", opt_image);
		offset = write_file(opt_image, rom_image, offset);
	}

	offset = write_directory_structure(root_entry->child, rom_image, offset);
	if (opt_verbose)
	printf("Directory data: %d bytes\n", offset);

	offset = write_data(root_entry, rom_image, offset);

	/* We always write a multiple of blksize bytes, so that
	   losetup works. */
	offset = ((offset - 1) | (blksize - 1)) + 1;
	if (opt_verbose)
	printf("Everything: %d kilobytes\n", offset >> 10);

	/* Write the superblock now that we can fill in all of the fields. */
	write_superblock(root_entry, rom_image+opt_pad, offset);
	if (opt_verbose)
	printf("Super block: %d bytes\n", sizeof(struct cramfs_super));

	/* Put the checksum in. */
	crc = crc32(0L, Z_NULL, 0);
	crc = crc32(crc, (rom_image+opt_pad), (offset-opt_pad));
	((struct cramfs_super *) (rom_image+opt_pad))->fsid.crc = CRAMFS_32(crc);
	if (opt_verbose)
	printf("CRC: %x\n", crc);

	/* Check to make sure we allocated enough space. */
	if (fslen_ub < offset) {
		error_msg_and_die("not enough space allocated for ROM "
			"image (%Ld allocated, %d used)", fslen_ub, offset);
	}

	written = write(fd, rom_image, offset);
	if (written < 0) {
		error_msg_and_die("write failed");
	}
	if (offset != written) {
		error_msg_and_die("ROM image write failed (wrote %d of %d bytes)", written, offset);
	}
	
	/* Free up memory */
	free_filesystem_entry(root_entry);
	free(root_entry);

	/* (These warnings used to come at the start, but they scroll off the
	   screen too quickly.) */
	if (warn_namelen)
		fprintf(stderr, /* bytes, not chars: think UTF-8. */
			"warning: filenames truncated to %d bytes (possibly less if multi-byte UTF-8)\n",
			CRAMFS_MAXPATHLEN);
	if (warn_skip)
		fprintf(stderr, "warning: files were skipped due to errors\n");
	if (warn_size)
		fprintf(stderr,
			"warning: file sizes truncated to %luMB (minus 1 byte)\n",
			1L << (CRAMFS_SIZE_WIDTH - 20));
	if (warn_uid) /* (not possible with current Linux versions) */
		fprintf(stderr,
			"warning: uids truncated to %u bits (this may be a security concern)\n",
			CRAMFS_UID_WIDTH);
	if (warn_gid)
		fprintf(stderr,
			"warning: gids truncated to %u bits (this may be a security concern)\n",
			CRAMFS_GID_WIDTH);
	if (warn_dev)
		fprintf(stderr,
			"WARNING: device numbers truncated to %u bits (this almost certainly means\n"
			"that some device files will be wrong)\n",
			CRAMFS_OFFSET_WIDTH);
	if (opt_errors &&
	    (warn_namelen||warn_skip||warn_size||warn_uid||warn_gid||warn_dev))
		exit(MKFS_ERROR);

	exit(MKFS_OK);
}

/*
 * Local variables:
 * c-file-style: "linux"
 * End:
 */
