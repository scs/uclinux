/* mtd-super.c: MTD-based romfs
 *
 * Copyright (C) 2006 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/module.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/time.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/blkdev.h>
#include <linux/parser.h>
#include <linux/smp_lock.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/statfs.h>
#include <linux/romfs_fs.h>
#include <linux/mtd/mtd.h>
#include <linux/ctype.h>
#include <asm/uaccess.h>

struct romfs_sb_info {
	struct mtd_info	*mtd;
	size_t		size;		/* image size */
};

struct romfs_inode_info {
	struct inode	vfs_inode;
	unsigned long	i_metasize;	/* size of non-data area */
	unsigned long	i_dataoffset;	/* from the start of fs */
};

#define ROMFS_SB_INFO(sb) ((struct romfs_sb_info *) (sb)->s_fs_info)
#define ROMFS_SB_MTD(sb) (((struct romfs_sb_info *) (sb)->s_fs_info)->mtd)
#define ROMFS_READ(sb, ...) (ROMFS_SB_MTD(sb)->read(ROMFS_SB_MTD(sb),##__VA_ARGS__))

static inline int ROMFS_READX(struct super_block *sb, unsigned long pos,
			      void *buf, size_t buflen)
{
	struct mtd_info	*mtd = ROMFS_SB_MTD(sb);
	size_t rlen;
	int ret;

	ret = mtd->read(mtd, pos, buflen, &rlen, buf);
	return (ret < 0 || rlen != buflen) ? -EIO : 0;
}

static inline size_t romfs_maxsize(struct super_block *sb)
{
	return ROMFS_SB_INFO(sb)->size;
}

static inline struct romfs_inode_info *ROMFS_I(struct inode *inode)
{
	return container_of(inode, struct romfs_inode_info, vfs_inode);
}

#if 0
#define kenter(FMT, ...)	printk("==> %s("FMT")\n",__FUNCTION__ ,##__VA_ARGS__)
#define kleave(FMT, ...)	printk("<== %s()"FMT"\n",__FUNCTION__ ,##__VA_ARGS__)
#define kdebug(FMT, ...)	printk(FMT"\n" ,##__VA_ARGS__)
#else
#define kenter(FMT, ...) do {} while (0)
#define kleave(FMT, ...) do {} while (0)
#define kdebug(FMT, ...) do {} while (0)
#endif

static kmem_cache_t *romfs_inode_cachep;

static const umode_t romfs_modemap[8] =
{
	0,			/* hard link */
	S_IFDIR  | 0644,	/* directory */
	S_IFREG  | 0644,	/* regular file */
	S_IFLNK  | 0777,	/* symlink */
	S_IFBLK  | 0600,	/* blockdev */
	S_IFCHR  | 0600,	/* chardev */
	S_IFSOCK | 0644,	/* socket */
	S_IFIFO  | 0644		/* FIFO */
};

static const unsigned char romfs_dtype_table[] = {
	DT_UNKNOWN, DT_DIR, DT_REG, DT_LNK, DT_BLK, DT_CHR, DT_SOCK, DT_FIFO
};

static struct inode *romfs_iget(struct super_block *sb, unsigned long pos);

/*
 * try to determine where a shared mapping can be made
 * - only supported for NOMMU at the moment (MMU can't doesn't copy private
 *   mappings)
 * - attempts to map through to the underlying MTD device
 */
#ifndef CONFIG_MMU
static unsigned long romfs_get_unmapped_area(struct file *file,
					     unsigned long addr,
					     unsigned long len,
					     unsigned long pgoff,
					     unsigned long flags)
{
	struct inode *inode = file->f_mapping->host;
	struct mtd_info *mtd = ROMFS_SB_MTD(inode->i_sb);
	unsigned long isize, offset;

	isize = i_size_read(inode);
	offset = pgoff << PAGE_SHIFT;
	if (offset > isize || len > isize || offset > isize - len)
		return (unsigned long) -EINVAL;

	if (mtd->get_unmapped_area) {

		if (addr != 0)
			return (unsigned long) -EINVAL;

		if (len > mtd->size || pgoff >= (mtd->size >> PAGE_SHIFT))
			return (unsigned long) -EINVAL;

		offset += ROMFS_I(inode)->i_dataoffset;
		if (offset > mtd->size - len)
			return (unsigned long) -EINVAL;

		return mtd->get_unmapped_area(mtd, len, offset, flags);
	}

	/* can't map directly */
	return (unsigned long) -ENOSYS;

}

/*
 * permit a R/O mapping to be made directly through onto an MTD device if
 * possible
 */
static int romfs_mmap(struct file *file, struct vm_area_struct *vma)
{
	return vma->vm_flags & (VM_SHARED | VM_MAYSHARE) ? 0 : -ENOSYS;
}
#endif

static struct file_operations romfs_ro_fops = {
	.llseek			= generic_file_llseek,
	.read			= generic_file_read,
	.sendfile		= generic_file_sendfile,
#ifdef CONFIG_MMU
	.mmap			= generic_file_readonly_mmap,
#else
	.mmap			= romfs_mmap,
	.get_unmapped_area	= romfs_get_unmapped_area,
#endif
};

/*
 * read a page worth of data from the image
 */
static int romfs_readpage(struct file *file, struct page *page)
{
	struct inode *inode = page->mapping->host;
	unsigned long pos;
	loff_t offset, avail, readlen;
	void *buf;
	int ret;

	buf = kmap(page);
	if (!buf)
		return -ENOMEM;

	/* 32 bit warning -- but not for us :) */
	offset = page_offset(page);
	if (offset < i_size_read(inode)) {
		avail = inode->i_size - offset;
		readlen = min_t(unsigned long, avail, PAGE_SIZE);

		pos = ROMFS_I(inode)->i_dataoffset + offset;

		ret = ROMFS_READX(inode->i_sb, pos, buf, readlen);
		if (ret == 0) {
			if (readlen < PAGE_SIZE)
				memset(buf + readlen, 0, PAGE_SIZE - readlen);
			SetPageUptodate(page);
			goto out;
		}
	}

	memset(buf, 0, PAGE_SIZE);
	SetPageError(page);
	ret = -EIO;

out:
	flush_dcache_page(page);
	kunmap(page);
	unlock_page(page);
	return ret;
}

static struct address_space_operations romfs_aops = {
	.readpage	= romfs_readpage
};

/*
 * determine the length of a string in romfs
 */
static unsigned long romfs_strnlen(struct super_block *sb, unsigned long pos,
				   size_t limit)
{
	unsigned long n = 0, max;
	u_char buf[16], *p;
	size_t len;
	int ret;

	max = romfs_maxsize(sb);
	if (pos >= max)
		return -EIO;
	if (limit > max || pos + limit > max)
		limit = max - pos;

	/* scan the string up to 16 bytes at a time */
	while (limit > 0) {
		max = limit > 16 ? 16 : limit;
		ret = ROMFS_READ(sb, pos, max, &len, buf);
		if (ret < 0)
			return (unsigned long) ret;
		p = memchr(buf, 0, len);
		if (p)
			return n + (p - buf);
		limit -= len;
		pos += len;
		n += len;
	}

	return n;
}

/*
 * compare a string to one in romfs
 * - return 1 if matched, 0 if differ, -ve if error
 */
static int romfs_strncmp(struct super_block *sb, unsigned long pos,
			 const char *str, size_t size)
{
	u_char buf[16];
	size_t len, max;
	int ret;

	max = romfs_maxsize(sb);
	if (pos >= max)
		return -EIO;

	if (size > ROMFS_MAXFN)
		return -ENAMETOOLONG;
	if (size > max || pos + size > max)
		size = max - pos;

	/* scan the string up to 16 bytes at a time */
	while (size > 0) {
		max = size > 16 ? 16 : size;
		ret = ROMFS_READ(sb, pos, max, &len, buf);
		if (ret < 0)
			return ret;
		if (memcmp(buf, str, len) != 0)
			return 0;
		size -= len;
		pos += len;
		str += len;
	}

	return 1;
}

/*
 * read the entries from a directory
 */
static int romfs_readdir(struct file *filp, void *dirent, filldir_t filldir)
{
	struct inode *i = filp->f_dentry->d_inode;
	struct romfs_inode ri;
	unsigned long offset, maxoff;
	int j, ino, nextfh;
	int stored = 0;
	char fsname[ROMFS_MAXFN];	/* XXX dynamic? */
	int ret;

	maxoff = romfs_maxsize(i->i_sb);

	offset = filp->f_pos;
	if (!offset) {
		offset = i->i_ino & ROMFH_MASK;
		ret = ROMFS_READX(i->i_sb, offset, &ri, ROMFH_SIZE);
		if (ret < 0)
			goto out;
		offset = be32_to_cpu(ri.spec) & ROMFH_MASK;
	}

	/* Not really failsafe, but we are read-only... */
	for (;;) {
		if (!offset || offset >= maxoff) {
			offset = maxoff;
			filp->f_pos = offset;
			goto out;
		}
		filp->f_pos = offset;

		/* Fetch inode info */
		ret = ROMFS_READX(i->i_sb, offset, &ri, ROMFH_SIZE);
		if (ret < 0)
			goto out;

		j = romfs_strnlen(i->i_sb, offset + ROMFH_SIZE,
				  sizeof(fsname) - 1);
		if (j < 0)
			goto out;

		ret = ROMFS_READX(i->i_sb, offset + ROMFH_SIZE, fsname, j);
		if (ret < 0)
			goto out;
		fsname[j] = '\0';

		ino = offset;
		nextfh = be32_to_cpu(ri.next);
		if ((nextfh & ROMFH_TYPE) == ROMFH_HRD)
			ino = be32_to_cpu(ri.spec);
		if (filldir(dirent, fsname, j, offset, ino,
			    romfs_dtype_table[nextfh & ROMFH_TYPE]) < 0)
			goto out;

		stored++;
		offset = nextfh & ROMFH_MASK;
	}

out:
	return stored;
}

/*
 * look up an entry in a directory
 */
static struct dentry *romfs_lookup(struct inode *dir, struct dentry *dentry,
				   struct nameidata *nd)
{
	unsigned long offset, maxoff;
	struct inode *inode;
	struct romfs_inode ri;
	const char *name;		/* got from dentry */
	int len, ret;

	offset = dir->i_ino & ROMFH_MASK;
	ret = ROMFS_READX(dir->i_sb, offset, &ri, ROMFH_SIZE);
	if (ret < 0)
		goto error;

	/* search all the file entries in the list starting from the one
	 * pointed to by the directory's special data */
	maxoff = romfs_maxsize(dir->i_sb);
	offset = be32_to_cpu(ri.spec) & ROMFH_MASK;

	name = dentry->d_name.name;
	len = dentry->d_name.len;

	for (;;) {
		if (!offset || offset >= maxoff)
			goto out0;

		ret = ROMFS_READX(dir->i_sb, offset, &ri, sizeof(ri));
		if (ret < 0)
			goto error;

		/* try to match the first 16 bytes of name */
		ret = romfs_strncmp(dir->i_sb, offset + ROMFH_SIZE, name, len);
		if (ret < 0)
			goto error;
		if (ret == 1)
			break;

		/* next entry */
		offset = be32_to_cpu(ri.next) & ROMFH_MASK;
	}

	/* Hard link handling */
	if ((be32_to_cpu(ri.next) & ROMFH_TYPE) == ROMFH_HRD)
		offset = be32_to_cpu(ri.spec) & ROMFH_MASK;

	inode = romfs_iget(dir->i_sb, offset);
	if (IS_ERR(inode)) {
		ret = PTR_ERR(inode);
		goto error;
	}
	goto outi;

	/*
	 * it's a bit funky, _lookup needs to return an error code
	 * (negative) or a NULL, both as a dentry.  ENOENT should not
	 * be returned, instead we need to create a negative dentry by
	 * d_add(dentry, NULL); and return 0 as no error.
	 * (Although as I see, it only matters on writable file
	 * systems).
	 */
out0:
	inode = NULL;
outi:
	d_add(dentry, inode);
	ret = 0;
error:
	return ERR_PTR(ret);
}

static struct file_operations romfs_dir_operations = {
	.read		= generic_read_dir,
	.readdir	= romfs_readdir,
};

static struct inode_operations romfs_dir_inode_operations = {
	.lookup		= romfs_lookup,
};

/*
 * get a romfs inode based on its position in the image (which doubles as the
 * inode number)
 */
static struct inode *romfs_iget(struct super_block *sb, unsigned long pos)
{
	struct romfs_inode_info *inode;
	struct romfs_inode ri;
	struct inode *i;
	unsigned long nlen;
	unsigned nextfh, ret;
	umode_t mode;

	kenter(",%lu", pos);

	/* we might have to traverse a chain of "hard link" file entries to get
	 * to the actual file */
	for (;;) {
		ret = ROMFS_READX(sb, pos, &ri, sizeof(ri));
		if (ret < 0)
			goto error;

		/* XXX: do romfs_checksum here too (with name) */

		nextfh = be32_to_cpu(ri.next);
		if ((nextfh & ROMFH_TYPE) != ROMFH_HRD)
			break;

		pos = be32_to_cpu(ri.spec) & ROMFH_MASK;
	}

	/* determine the length of the filename */
        nlen = romfs_strnlen(sb, pos + ROMFH_SIZE, ROMFS_MAXFN);
	if (IS_ERR_VALUE(nlen))
		goto eio;

	/* get an inode for this image position */
	i = iget_locked(sb, pos);
	if (!i) {
		kleave(" = -ENOMEM");
		return ERR_PTR(-ENOMEM);
	}

	if (!(i->i_state & I_NEW)) {
		kleave(" = %p [extant]", i);
		return i;
	}

        /* precalculate the data offset */
	inode = ROMFS_I(i);
        inode->i_metasize = (ROMFH_SIZE + nlen + 1 + ROMFH_PAD) & ROMFH_MASK;
        inode->i_dataoffset = pos + inode->i_metasize;

	i->i_nlink = 1;		/* Hard to decide.. */
	i->i_size = be32_to_cpu(ri.size);
	i->i_mtime.tv_sec = i->i_atime.tv_sec = i->i_ctime.tv_sec = 0;
	i->i_mtime.tv_nsec = i->i_atime.tv_nsec = i->i_ctime.tv_nsec = 0;
	i->i_uid = i->i_gid = 0;

	/* set up mode and ops */
        mode = romfs_modemap[nextfh & ROMFH_TYPE];

	switch (nextfh & ROMFH_TYPE) {
		case ROMFH_DIR:
			i->i_size = ROMFS_I(i)->i_metasize;
			i->i_op = &romfs_dir_inode_operations;
			i->i_fop = &romfs_dir_operations;
			if (nextfh & ROMFH_EXEC)
				mode |= S_IXUGO;
			break;
		case ROMFH_REG:
			i->i_fop = &romfs_ro_fops;
			i->i_data.a_ops = &romfs_aops;
			i->i_data.backing_dev_info =
				ROMFS_SB_MTD(i->i_sb)->backing_dev_info;
			if (nextfh & ROMFH_EXEC)
				mode |= S_IXUGO;
			break;
		case ROMFH_SYM:
			i->i_op = &page_symlink_inode_operations;
			i->i_data.a_ops = &romfs_aops;
			mode |= S_IRWXUGO;
			break;
		default:
			/* depending on MBZ for sock/fifos */
			nextfh = be32_to_cpu(ri.spec);
			init_special_inode(i, mode, MKDEV(nextfh >> 16,
							  nextfh & 0xffff));
			break;
	}

	i->i_mode = mode;

	unlock_new_inode(i);
	kleave(" = %p [new]", i);
	return i;

eio:
	ret = -EIO;
error:
	printk("ROMFS: read error for inode 0x%lx\n", pos);
	return ERR_PTR(ret);
}

/*
 * allocate a new inode
 */
static struct inode *romfs_alloc_inode(struct super_block *sb)
{
	struct romfs_inode_info *inode;
	inode = kmem_cache_alloc(romfs_inode_cachep, SLAB_KERNEL);
	return inode ? &inode->vfs_inode : NULL;
}

/*
 * return a spent inode to the slab cache
 */
static void romfs_destroy_inode(struct inode *inode)
{
	kmem_cache_free(romfs_inode_cachep, ROMFS_I(inode));
}

/*
 * get filesystem statistics
 */
static int romfs_statfs(struct super_block *sb, struct kstatfs *buf)
{
	buf->f_type = ROMFS_MAGIC;
	buf->f_namelen = ROMFS_MAXFN;
	buf->f_bsize = ROMBSIZE;
	buf->f_bfree = buf->f_bavail = buf->f_ffree;
	buf->f_blocks =
		(romfs_maxsize(sb) + ROMBSIZE - 1) >> ROMBSBITS;
	return 0;
}

/*
 * remounting must involve read-only
 */
static int romfs_remount(struct super_block *sb, int *flags, char *data)
{
	*flags |= MS_RDONLY;
	return 0;
}

static struct super_operations romfs_super_ops = {
	.alloc_inode	= romfs_alloc_inode,
	.destroy_inode	= romfs_destroy_inode,
	.statfs		= romfs_statfs,
	.remount_fs	= romfs_remount,
};

/*
 * checksum check on part of a romfs filesystem
 */
static __u32 romfs_checksum(const void *data, int size)
{
	const __be32 *ptr = data;
	__u32 sum;

	sum = 0;
	size >>= 2;
	while (size > 0) {
		sum += be32_to_cpu(*ptr++);
		size--;
	}
	return sum;
}

/*
 * fill in the superblock
 */
static int romfs_fill_super(struct super_block *sb, void *data, int silent)
{
	struct romfs_super_block *rsb;
	struct romfs_sb_info *super = data;
	struct inode *root;
	unsigned long pos;
	size_t len;
	int ret;

	kenter("");

	sb->s_blocksize = ROMBSIZE;
	sb->s_blocksize_bits = blksize_bits(ROMBSIZE);
	sb->s_maxbytes = 0xFFFFFFFF;
	sb->s_magic = ROMFS_MAGIC;
	sb->s_flags |= MS_RDONLY | MS_NOATIME;
	sb->s_op = &romfs_super_ops;

	/* read the image superblock and check it */
	rsb = kmalloc(512, GFP_KERNEL);
	if (!rsb)
		return -ENOMEM;

	ret = ROMFS_READX(sb, 0, rsb, 512);
	if (ret < 0)
		goto error_rsb;

	super = ROMFS_SB_INFO(sb);
	super->size = be32_to_cpu(rsb->size);

	if (rsb->word0 != ROMSB_WORD0 || rsb->word1 != ROMSB_WORD1 ||
	    super->size < ROMFH_SIZE
	    ) {
		if (!silent)
			printk("VFS:"
			       " Can't find a romfs filesystem on dev %s.\n",
			       sb->s_id);
		goto error_rsb_inval;
	}

	if (romfs_checksum(rsb, min_t(size_t, super->size, 512))) {
		printk(KERN_ERR "ROMFS: bad initial checksum on dev %s.\n",
		       sb->s_id);
		goto error_rsb_inval;
	}

	len = strnlen(rsb->name, ROMFS_MAXFN);
	if (!silent)
		printk("ROMFS: Mounting image '%*.*s'\n", len, len, rsb->name);

	kfree(rsb);
	rsb = NULL;

	/* find the root directory */
	pos = (ROMFH_SIZE + len + 1 + ROMFH_PAD) & ROMFH_MASK;

	root = romfs_iget(sb, pos);
	if (!root)
		goto error;

	sb->s_root = d_alloc_root(root);
	if (!sb->s_root)
		goto error_i;

	return 0;

error_i:
	kleave(" = %d [i]", ret);
	iput(root);
error:
	kleave(" = %d", ret);
	return -EINVAL;
error_rsb_inval:
	ret = -EINVAL;
error_rsb:
	kleave(" = %d [rsb]", ret);
	return ret;
}

/*
 * compare superblocks to see if they're equivalent
 * - they are if the underlying MTD device is the same
 */
static int romfs_sb_compare(struct super_block *sb, void *data)
{
	struct romfs_sb_info *p = data;
	struct romfs_sb_info *c = ROMFS_SB_INFO(sb);

	if (c->mtd == p->mtd) {
		kdebug("romfs_sb_compare: match on device %d (\"%s\")\n",
		       p->mtd->index, p->mtd->name);
		return 1;
	}

	kdebug("romfs_sb_compare:"
	       " No match, device %d (\"%s\"), device %d (\"%s\")\n",
	       c->mtd->index, c->mtd->name, p->mtd->index, p->mtd->name);
	return 0;
}

/*
 * mark the superblock by the MTD device it is using
 * - set the device number to be the correct MTD block device for pesuperstence
 *   of NFS exports
 */
static int romfs_sb_set(struct super_block *sb, void *data)
{
	struct romfs_sb_info *super = data;

	sb->s_fs_info = super;
	sb->s_dev = MKDEV(MTD_BLOCK_MAJOR, super->mtd->index);

	return 0;
}

/*
 * get a superblock on an MTD-backed filesystem
 */
static struct super_block *romfs_get_sb_mtd(struct file_system_type *fs_type,
					    int flags, const char *dev_name,
					    void *data, struct mtd_info *mtd)
{
	struct romfs_sb_info *super;
	struct super_block *sb;
	int ret;

	super = kzalloc(sizeof(*super), GFP_KERNEL);
	if (!super)
		return ERR_PTR(-ENOMEM);

	super->mtd = mtd;

	sb = sget(fs_type, romfs_sb_compare, romfs_sb_set, super);

	if (IS_ERR(sb))
		goto out_put;

	if (sb->s_root) {
		/* new mountpoint for ROMFS which is already mounted */
		kdebug("ROMFS: Device %d (\"%s\") is already mounted\n",
		       mtd->index, mtd->name);
		goto out_put;
	}

	kdebug("ROMFS: New superblock for device %d (\"%s\")\n",
	       mtd->index, mtd->name);

	ret = romfs_fill_super(sb, data, flags & MS_VERBOSE ? 0 : 1);
	if (ret < 0) {
		up_write(&sb->s_umount);
		deactivate_super(sb);
		return ERR_PTR(ret);
	}

	/* go */
	sb->s_flags |= MS_ACTIVE;
	return sb;

out_put:
	kfree(super);
	put_mtd_device(mtd);
	return sb;
}

/*
 * get a superblock on an MTD-backed filesystem by MTD device number
 */
static struct super_block *romfs_get_sb_mtdnr(struct file_system_type *fs_type,
					      int flags, const char *dev_name,
					      void *data, int mtdnr)
{
	struct mtd_info *mtd;

	mtd = get_mtd_device(NULL, mtdnr);
	if (!mtd) {
		kdebug("ROMFS: MTD device #%u doesn't appear to exist\n",
		       mtdnr);
		return ERR_PTR(-EINVAL);
	}

	return romfs_get_sb_mtd(fs_type, flags, dev_name, data, mtd);
}

/*
 * get a superblock for mounting
 */
static struct super_block *romfs_get_sb(struct file_system_type *fs_type,
					int flags, const char *dev_name,
					void *data)
{
	int err;
	struct nameidata nd;
	int mtdnr;

	kdebug("ROMFS: get_sb");

	if (!dev_name)
		return ERR_PTR(-EINVAL);

	kdebug("ROMFS: dev_name \"%s\"\n", dev_name);

	/* the preferred way of mounting in future; especially when
	 * CONFIG_BLK_DEV is implemented - we specify the underlying
	 * MTD device by number or by name, so that we don't require
	 * block device support to be present in the kernel. */
	if (dev_name[0] == 'm' && dev_name[1] == 't' && dev_name[2] == 'd') {
		/* probably mounting without the blkdev crap */
		if (dev_name[3] == ':') {
			struct mtd_info *mtd;

			/* mount by MTD device name */
			kdebug("romfs_get_sb(): mtd:%%s, name \"%s\"\n",
			       dev_name + 4);

			for (mtdnr = 0; mtdnr < MAX_MTD_DEVICES; mtdnr++) {
				mtd = get_mtd_device(NULL, mtdnr);
				if (mtd) {
					if (!strcmp(mtd->name, dev_name+4))
						return romfs_get_sb_mtd(
							fs_type, flags,
							dev_name, data, mtd);

					put_mtd_device(mtd);
				}
			}

			printk(KERN_NOTICE "ROMFS:"
			       " MTD device with name \"%s\" not found.\n",
			       dev_name + 4);

		} else if (isdigit(dev_name[3])) {
			/* mount by MTD device number name */
			char *endptr;

			mtdnr = simple_strtoul(dev_name + 3, &endptr, 0);
			if (!*endptr) {
				/* It was a valid number */
				kdebug("romfs_get_sb(): mtd%%d, mtdnr %d\n",
				       mtdnr);
				return romfs_get_sb_mtdnr(fs_type, flags,
							  dev_name, data,
							  mtdnr);
			}
		}
	}

	/* try the old way - the hack where we allowed users to mount
	 * /dev/mtdblock$(n) but didn't actually _use_ the blkdev
	 */
	err = path_lookup(dev_name, LOOKUP_FOLLOW, &nd);

	kdebug("romfs_get_sb(): path_lookup() returned %d, inode %p\n",
	       err, nd.dentry ? nd.dentry->d_inode : NULL);

	if (err)
		return ERR_PTR(err);

	err = -EINVAL;

	if (!S_ISBLK(nd.dentry->d_inode->i_mode))
		goto out;

	if (nd.mnt->mnt_flags & MNT_NODEV) {
		err = -EACCES;
		goto out;
	}

	if (imajor(nd.dentry->d_inode) != MTD_BLOCK_MAJOR) {
		if (flags & MS_VERBOSE)
			printk(KERN_NOTICE "ROMFS:"
			       " Attempt to mount non-MTD device \"%s\"\n",
			       dev_name);
		goto out;
	}

	mtdnr = iminor(nd.dentry->d_inode);
	path_release(&nd);

	return romfs_get_sb_mtdnr(fs_type, flags, dev_name, data, mtdnr);

out:
	path_release(&nd);
	return ERR_PTR(err);
}

/*
 * destroy a superblock after unmounting
 */
static void romfs_kill_sb(struct super_block *sb)
{
	struct romfs_sb_info *super = ROMFS_SB_INFO(sb);

	generic_shutdown_super(sb);
	put_mtd_device(super->mtd);
	kfree(super);
}

static struct file_system_type romfs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "romfs",
	.get_sb		= romfs_get_sb,
	.kill_sb	= romfs_kill_sb,
};

/*
 * inode storage initialiser
 */
static void romfs_i_init_once(void *_inode, kmem_cache_t *cachep,
			      unsigned long flags)
{
	struct romfs_inode_info *inode = _inode;

	if ((flags & (SLAB_CTOR_VERIFY|SLAB_CTOR_CONSTRUCTOR)) ==
	    SLAB_CTOR_CONSTRUCTOR)
		inode_init_once(&inode->vfs_inode);
}

/*
 * romfs module initialisation
 */
static int __init init_romfs_fs(void)
{
	int ret;

	printk(KERN_INFO "ROMFS MTD (C) 2006 Red Hat, Inc.\n");

	romfs_inode_cachep =
		kmem_cache_create("romfs_i",
				  sizeof(struct romfs_inode_info), 0,
				  SLAB_RECLAIM_ACCOUNT,
				  romfs_i_init_once, NULL);

	if (!romfs_inode_cachep) {
		printk(KERN_ERR "ROMFS error: Failed to initialise inode cache\n");
		return -ENOMEM;
	}
	ret = register_filesystem(&romfs_fs_type);
	if (ret) {
		printk(KERN_ERR "ROMFS error: Failed to register filesystem\n");
		goto error_register;
	}
	return 0;

error_register:
	kmem_cache_destroy(romfs_inode_cachep);
	return ret;
}

/*
 * romfs module removal
 */
static void __exit exit_romfs_fs(void)
{
	unregister_filesystem(&romfs_fs_type);
	kmem_cache_destroy(romfs_inode_cachep);
}

module_init(init_romfs_fs);
module_exit(exit_romfs_fs);

MODULE_DESCRIPTION("The Journalling Flash File System, v2");
MODULE_AUTHOR("Red Hat, Inc.");
MODULE_LICENSE("GPL"); // Actually dual-licensed, but it doesn't matter for
