/*
 * $Id$
 *
 * (C) 2003 David Woodhouse <dwmw2@infradead.org>
 *
 * Simple read-only (writable only for RAM) mtdblock driver
 *
 * (C) 2002 David McCullough, Added MAGIC_ROM_PTR support
 */

#include <linux/init.h>
#include <linux/slab.h>
#include <linux/mtd/mtd.h>
#include <linux/mtd/blktrans.h>

static int mtdblock_readsect(struct mtd_blktrans_dev *dev,
			      unsigned long block, char *buf)
{
	size_t retlen;

	if (dev->mtd->read(dev->mtd, (block * 512), 512, &retlen, buf))
		return 1;
	return 0;
}

static int mtdblock_writesect(struct mtd_blktrans_dev *dev,
			      unsigned long block, char *buf)
{
	size_t retlen;

	if (dev->mtd->write(dev->mtd, (block * 512), 512, &retlen, buf))
		return 1;
	return 0;
}

static void mtdblock_add_mtd(struct mtd_blktrans_ops *tr, struct mtd_info *mtd)
{
	struct mtd_blktrans_dev *dev = kmalloc(sizeof(*dev), GFP_KERNEL);

	if (!dev)
		return;

	memset(dev, 0, sizeof(*dev));

	dev->mtd = mtd;
	dev->devnum = mtd->index;
	dev->blksize = 512;
	dev->size = mtd->size >> 9;
	dev->tr = tr;
	if ((mtd->flags & (MTD_CLEAR_BITS|MTD_SET_BITS|MTD_WRITEABLE)) !=
	    (MTD_CLEAR_BITS|MTD_SET_BITS|MTD_WRITEABLE))
		dev->readonly = 1;

	add_mtd_blktrans_dev(dev);
}

#ifdef MAGIC_ROM_PTR
static int
mtdblock_romptr(kdev_t dev, struct vm_area_struct * vma)
{
	struct mtd_info *mtd;
	u_char *ptr;
	size_t len;

	mtd = __get_mtd_device(NULL, MINOR(dev));

	if (!mtd->point)
		return -ENOSYS; /* Can't do it, No function to point to correct addr */

	if ((*mtd->point)(mtd,vma->vm_offset,vma->vm_end-vma->vm_start,&len,&ptr) != 0)
		return -ENOSYS;

	vma->vm_start = (unsigned long) ptr;
	vma->vm_end = vma->vm_start + len;
	return 0;
}
#endif

static void mtdblock_remove_dev(struct mtd_blktrans_dev *dev)
{
	del_mtd_blktrans_dev(dev);
	kfree(dev);
}

struct mtd_blktrans_ops mtdblock_tr = {
	.name		= "mtdblock",
	.major		= 31,
	.part_bits	= 0,
	.readsect	= mtdblock_readsect,
	.writesect	= mtdblock_writesect,
	.add_mtd	= mtdblock_add_mtd,
	.remove_dev	= mtdblock_remove_dev,
	.owner		= THIS_MODULE,
#ifdef MAGIC_ROM_PTR
	.romptr		= mtdblock_romptr,
#endif
};

static int __init mtdblock_init(void)
{
	return register_mtd_blktrans(&mtdblock_tr);
}

static void __exit mtdblock_exit(void)
{
	deregister_mtd_blktrans(&mtdblock_tr);
}

module_init(mtdblock_init);
module_exit(mtdblock_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("David Woodhouse <dwmw2@infradead.org>");
MODULE_DESCRIPTION("Simple read-only block device emulation access to MTD devices");
