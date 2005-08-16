/*
 * Flash memory access on BlackFin BF533 based devices
 * 
 * (C) 2004 LG Soft India
 * 
 */
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/mtd/map.h>
#include <linux/mtd/mtd.h>
#include <linux/mtd/flashchip.h>
#include <linux/init.h>

#include <linux/interrupt.h>

#define MAX_SMT_CHIPS 8

#define DEVICE_TYPE_X8  (8 / 8)
#define DEVICE_TYPE_X16 (16 / 8)
#define DEVICE_TYPE_X32 (32 / 8)

/* Addresses */
#define ADDR_MANUFACTURER		0x0000
#define ADDR_DEVICE_ID			0x0002

#define ADDR_UNLOCK_1			0x0555
#define ADDR_UNLOCK_2			0x02AA
#define ADDR_UNLOCK_3			0x0555

/* Commands */
#define CMD_UNLOCK_DATA_1		0x00aa
#define CMD_UNLOCK_DATA_2		0x0055
#define CMD_UNLOCK_DATA_3		0x00a0

#define CMD_MANUFACTURER_UNLOCK_DATA	0x00a0
#define CMD_PROGRAM_UNLOCK_DATA		0x00A0

#define CMD_RESET_DATA			0x00F0


#define CMD_SECTOR_ERASE_UNLOCK_ADDR_1	0x555
#define CMD_SECTOR_ERASE_UNLOCK_ADDR_2	0x2aa
#define CMD_SECTOR_ERASE_UNLOCK_ADDR_3	0x555
#define CMD_SECTOR_ERASE_UNLOCK_ADDR_4	0x555
#define CMD_SECTOR_ERASE_UNLOCK_ADDR_5	0x2aa

#define CMD_SECTOR_ERASE_UNLOCK_DATA_1	0xAA	
#define CMD_SECTOR_ERASE_UNLOCK_DATA_2	0x55
#define CMD_SECTOR_ERASE_UNLOCK_DATA_3	0x80
#define CMD_SECTOR_ERASE_UNLOCK_DATA_4	0xAA
#define CMD_SECTOR_ERASE_UNLOCK_DATA_5	0x55

struct stm_flash_private {
	int device_type;
	int interleave;
	int numchips;
	unsigned long chipshift;
	struct flchip chips[0];
};

struct stm_flash_info {
	const __u16 mfr_id;
	const __u16 dev_id;
	const char *name;
	const u_long size;
	const int numeraseregions;
	const struct mtd_erase_region_info regions[4];
};

static int stm_flash_read(struct mtd_info *, loff_t, size_t, size_t *, unsigned char *);
static int stm_flash_write(struct mtd_info *, loff_t, size_t, size_t *, const unsigned char *);
static void stm_flash_sync(struct mtd_info *);
static int stm_flash_erase(struct mtd_info *, struct erase_info *);
static void stm_flash_destroy(struct mtd_info*);
static struct mtd_info* stm_flash_probe(struct map_info *);
static int stm_flash_suspend(struct mtd_info *mtd);
static void stm_flash_resume(struct mtd_info *mtd);

static struct mtd_chip_driver stm_flash_chipdrv = {
	probe:		stm_flash_probe,
	destroy:	stm_flash_destroy,
	name:		"stm_flash",
	module:		THIS_MODULE
};

static const char im_name[] = "stm_flash";

static void send_unlock(struct map_info *map, unsigned long base)
{
	map_word mw;

	mw.x[0] = CMD_UNLOCK_DATA_1;
	map->write(map, mw , base + ADDR_UNLOCK_1);
	mw.x[0] = CMD_UNLOCK_DATA_2;
	map->write(map, mw , base + ADDR_UNLOCK_2);
	mw.x[0] = CMD_UNLOCK_DATA_3;
	map->write(map, mw , base + ADDR_UNLOCK_3);
}

static int probe_new_chip(struct mtd_info *mtd, __u32 base, 
			  struct flchip *chips,
			  struct stm_flash_private *private,
			  const struct stm_flash_info *table,
			  int table_size)
{
	__u32 mfr_id, dev_id;
	struct map_info *map = mtd->priv;
	struct stm_flash_private temp;
	int i;
	map_word mfr_id1,dev_id1,mw;

	temp.device_type = DEVICE_TYPE_X16;
	temp.interleave = 1;
	map->fldrv_priv = &temp;
	
	mw.x[0] = CMD_UNLOCK_DATA_1;
	map->write(map, mw , base + ADDR_UNLOCK_1);
	mw.x[0] = CMD_UNLOCK_DATA_2;
	map->write(map, mw , base + ADDR_UNLOCK_2);
	mw.x[0] = CMD_RESET_DATA;
	map->write(map, mw , base);

	mw.x[0] = CMD_UNLOCK_DATA_1;
	map->write(map, mw , base + ADDR_UNLOCK_1);
	mw.x[0] = CMD_UNLOCK_DATA_2;
	map->write(map, mw , base + ADDR_UNLOCK_2);
	mw.x[0] = 0x90; 
	map->write(map, mw , base + ADDR_UNLOCK_3);

	mfr_id1=map->read(map, base + ADDR_MANUFACTURER) ;
	dev_id1=map->read(map, base + ADDR_DEVICE_ID) ;

	mfr_id = mfr_id1.x[0] & 0x00FF;
	dev_id = dev_id1.x[0] & 0x00FF;

	for (i = 0; i < table_size; i++)
	{
		if ((mfr_id == table[i].mfr_id) &&
		    (dev_id == table[i].dev_id))
		{
			if (chips)
			{
				int j;

				for (j = 0; j < private->numchips; j++)
				{
					mfr_id1=map->read(map, chips[j].start +	ADDR_MANUFACTURER);
						
					dev_id1=map->read(map, chips[j].start +
							 ADDR_DEVICE_ID) ;
					if ((mfr_id1.x[0] == mfr_id) && ( dev_id1.x[0] == dev_id))
	
					{
						/* Exit autoselect mode */
						mw.x[0] = CMD_UNLOCK_DATA_1;
						map->write(map, mw , base + ADDR_UNLOCK_1);
						mw.x[0] = CMD_UNLOCK_DATA_2;
						map->write(map, mw , base + ADDR_UNLOCK_2);
						mw.x[0] = CMD_RESET_DATA;
						map->write(map, mw , base);
						return -1;
					}
				}

				if (private->numchips == MAX_SMT_CHIPS)
				{
					printk(KERN_WARNING "%s: Too many "
						"flash chips detected. "
						"Increase MAX_SMT_CHIPS "
						"from %d.\n", map->name,
						MAX_SMT_CHIPS);
					return -1;
				}

				chips[private->numchips].start = base;
				chips[private->numchips].state = FL_READY;
				chips[private->numchips].mutex =
					&chips[private->numchips]._spinlock;
				private->numchips++;
			}
			printk("%s: Found %d x %ldMiB %s at 0x%08x\n",
				map->name, temp.interleave, 
				(table[i].size)/(1024*1024),
				table[i].name, base);
			
			mtd->size += table[i].size * temp.interleave;
			mtd->numeraseregions += table[i].numeraseregions;

			break;
		}
	}
	
	printk("mfr id 0x%02x, dev_id 0x%02x\n", mfr_id, dev_id);

	mw.x[0] = CMD_UNLOCK_DATA_1;
	map->write(map, mw , base + ADDR_UNLOCK_1);
	mw.x[0] = CMD_UNLOCK_DATA_2;
	map->write(map, mw , base + ADDR_UNLOCK_2);
	mw.x[0] = CMD_RESET_DATA;
	map->write(map, mw , base);

	if (i == table_size)
	{
		printk(KERN_DEBUG "%s: unknown flash device at 0x%08x, "
			"mfr id 0x%02x, dev_id 0x%02x\n", map->name,
			base, mfr_id, dev_id);
		map->fldrv_priv = NULL;

		return -1;
	}

	private->device_type = temp.device_type;
	private->interleave = temp.interleave;

	return i;
}

static struct mtd_info* stm_flash_probe(struct map_info *map)
{
	const struct stm_flash_info table[] = {
	{
		mfr_id: 0x20,
		dev_id: 0xCB,
		name: "ST MW320D",
		size: 0x00400000,
		numeraseregions: 1,
		regions: {
		  { offset: 0x000000, erasesize: 0x10000, numblocks: 64}, 
		}
	}
	};
	struct mtd_info *mtd;
	struct flchip chips[MAX_SMT_CHIPS];
	int table_pos[MAX_SMT_CHIPS];
	struct stm_flash_private temp;
	struct stm_flash_private *private;
	unsigned long base;
	unsigned long size;
	int i;
	int offset, reg_idx;

	mtd = (struct mtd_info*)kmalloc(sizeof(*mtd), GFP_KERNEL);
	if (!mtd)
	{
		printk(KERN_WARNING "%s: kmalloc failed for info structure\n",
			map->name);
		return NULL;
	}
	memset(mtd, 0, sizeof(*mtd));
	mtd->priv = map;

	memset(&temp, 0, sizeof(temp));
	
	printk("%s: Probing for STM MW320D compatible flash...\n", map->name);
	
	if ((table_pos[0] = probe_new_chip(mtd, 0, NULL, &temp, table,
					sizeof(table)/sizeof(table[0]))) == -1)
	{
		printk(KERN_WARNING 
			"%s: Found no STM MW320D compatible device at "
			"location zero\n", map->name);
		kfree(mtd);

		return NULL;
	}

	chips[0].start = 0;
	chips[0].state = FL_READY;
	chips[0].mutex = &chips[0]._spinlock;
	temp.numchips = 1;
	for (size = mtd->size; size > 1; size >>= 1)
		temp.chipshift++;

	/* Find out if there are any more chips in the map. */
	for (base = (1 << temp.chipshift); base < map->size;
			base += (1 << temp.chipshift))
	{
		int numchips = temp.numchips;
		table_pos[numchips] = 
			probe_new_chip(mtd, base, chips, &temp, 
				table, sizeof(table)/sizeof(table[0]));
	}

	mtd->eraseregions = kmalloc(sizeof(struct mtd_erase_region_info) *
					mtd->numeraseregions, GFP_KERNEL);

	if (!mtd->eraseregions)
	{
		printk(KERN_WARNING "%s: Failed to allocate memory for "
			"MTD erase region info\n", map->name);
		kfree(mtd);
		map->fldrv_priv = NULL;
		return NULL;
	}

	reg_idx = 0;
	offset = 0;
	for (i = 0; i < temp.numchips; i++)
	{
		int dev_size;
		int j;

		dev_size = 0;
		for (j = 0; j < table[table_pos[i]].numeraseregions; j++)
		{
			mtd->eraseregions[reg_idx].offset = offset + 
				(table[table_pos[i]].regions[j].offset *
				 temp.interleave);
			mtd->eraseregions[reg_idx].erasesize =
				table[table_pos[i]].regions[j].erasesize *
				temp.interleave;
			mtd->eraseregions[reg_idx].numblocks =
				table[table_pos[i]].regions[j].numblocks;
			if (mtd->erasesize < 
					mtd->eraseregions[reg_idx].erasesize)
				mtd->erasesize = 
					mtd->eraseregions[reg_idx].erasesize;

			dev_size += mtd->eraseregions[reg_idx].erasesize *
				mtd->eraseregions[reg_idx].numblocks;
			reg_idx++;
		}
		offset += dev_size;
	}

	mtd->type = MTD_NORFLASH;
	mtd->flags = MTD_CAP_NORFLASH;
	mtd->name = map->name;
	mtd->erase = stm_flash_erase;
	mtd->read = stm_flash_read;
	mtd->write = stm_flash_write;
	mtd->sync = stm_flash_sync;
	mtd->suspend = stm_flash_suspend;
	mtd->resume = stm_flash_resume;

	private = kmalloc(sizeof(*private) + 
			(sizeof(struct flchip) * temp.numchips), GFP_KERNEL);
	if (!private) {
		printk(KERN_WARNING
		       "%s: kmalloc failed for private structure\n", map->name);
		kfree(mtd);
		map->fldrv_priv = NULL;
		return NULL;
	}
	memcpy(private, &temp, sizeof(temp));
	memcpy(private->chips, chips, 
		sizeof(struct flchip) * private->numchips);
	for (i = 0; i < private->numchips; i++)
	{
		init_waitqueue_head(&private->chips[i].wq);
		spin_lock_init(&private->chips[i]._spinlock);
	}

	map->fldrv_priv = private;

	map->fldrv = &stm_flash_chipdrv;
	__module_get(THIS_MODULE);

	return mtd;
}

static void stm_flash_destroy(struct mtd_info *mtd)
{
	struct map_info *map = mtd->priv;
	struct stm_flash_private *private = map->fldrv_priv;
	kfree(private);
}

static void stm_flash_sync(struct mtd_info *mtd)
{
	struct map_info *map = mtd->priv;
	struct stm_flash_private *private = map->fldrv_priv;
	int i;
	struct flchip *chip;
	int ret = 0;

	DECLARE_WAITQUEUE(wait, current);

	for (i = 0; !ret && (i < private->numchips); i++)
	{
		chip = &private->chips[i];

	retry:
		spin_lock_bh(chip->mutex);

		switch (chip->state)
		{
		case FL_READY:
		case FL_STATUS:
		case FL_CFI_QUERY:
		case FL_JEDEC_QUERY:
			chip->oldstate = chip->state;
			chip->state = FL_SYNCING;
		case FL_SYNCING:
			spin_unlock_bh(chip->mutex);
			break;
		default:
			/* Not an idle state */
			add_wait_queue(&chip->wq, &wait);

			spin_unlock_bh(chip->mutex);

			schedule();

			remove_wait_queue(&chip->wq, &wait);

			goto retry;
		}
	}

	/* Unlock the chips again */
	for (i--; i >= 0; i--)
	{
		chip = &private->chips[i];

		spin_lock_bh(chip->mutex);

		if (chip->state == FL_SYNCING) 
		{
			chip->state = chip->oldstate;
			wake_up(&chip->wq);
		}
		spin_unlock_bh(chip->mutex);
	}
}

static int read_one_chip(struct map_info *map, struct flchip *chip, 
			loff_t addr, size_t len, unsigned char *buf)
{
	DECLARE_WAITQUEUE(wait, current);
	unsigned long timeo = jiffies + HZ;

retry:
	spin_lock_bh(chip->mutex);

	if (chip->state != FL_READY)
	{
		printk(KERN_INFO "%s: waiting for chip to read, state = %d\n",
			map->name, chip->state);
		set_current_state(TASK_UNINTERRUPTIBLE);
		add_wait_queue(&chip->wq, &wait);

		spin_unlock_bh(chip->mutex);

		schedule();
		remove_wait_queue(&chip->wq, &wait);

		if (signal_pending(current))
			return -EINTR;

		timeo = jiffies + HZ;

		goto retry;
	}

	addr += chip->start;

	chip->state = FL_READY;

	map->copy_from(map, buf, addr, len);

	wake_up(&chip->wq);
	spin_unlock_bh(chip->mutex);

	return 0;
}

static int stm_flash_read(struct mtd_info *mtd, loff_t from, size_t len,
			  size_t *retlen, unsigned char *buf)
{
	struct map_info *map = mtd->priv;
	struct stm_flash_private *private = map->fldrv_priv;
	unsigned long offset;
	int chipnum;
	int ret = 0;

	if ((from + len) > mtd->size)
	{
		printk(KERN_WARNING "%s: read request past end of device "
			"(0x%lx)\n", map->name, (unsigned long)from + len);
		return -EINVAL;
	}

	/* Offset within the first chip that the first read should start. */
	chipnum = (from >> private->chipshift);
	offset = from - (chipnum << private->chipshift);

	*retlen = 0;

	while (len)
	{
		unsigned long this_len;

		if (chipnum >= private->numchips)
			break;

		if ((len + offset -1) >> private->chipshift)
			this_len = (1 << private->chipshift) - offset;
		else
			this_len = len;

		ret = read_one_chip(map, &private->chips[chipnum], offset,
				this_len, buf);

		if (ret)
			break;

		*retlen += this_len;
		len -= this_len;
		buf += this_len;

		offset = 0;
		chipnum++;
	}

	return ret;
}

extern void reset_flash(void);
static int flash_is_busy(struct map_info *map, unsigned long addr)
{
	unsigned short toggled;
	map_word read11,read21;	
	
	read11 = map->read(map,addr); 
	read21 = map->read(map,addr); 
	
	toggled = (unsigned short)read11.x[0] ^ (unsigned short)read21.x[0];
	
	toggled &= (((unsigned short)1) << 6);

	return toggled;
}

static int write_one_word(struct map_info *map, struct flchip *chip,
		unsigned long addr, unsigned long datum)
{
	unsigned long timeo = jiffies + HZ;
	/*struct stm_flash_private *private = map->fldrv_priv;*/
	DECLARE_WAITQUEUE(wait, current);
	int ret = 0;
	int times_left;
	map_word mw;

retry:
	spin_lock_bh(chip->mutex);

	if (chip->state != FL_READY)
	{
		printk("%s: waiting for chip to write, state = %d\n",
				map->name, chip->state);
		set_current_state(TASK_UNINTERRUPTIBLE);
		add_wait_queue(&chip->wq, &wait);

		spin_unlock_bh(chip->mutex);

		schedule();
		remove_wait_queue(&chip->wq, &wait);
		printk(KERN_INFO "%s: woke up to write\n", map->name);
		if (signal_pending(current))
			return -EINTR;

		timeo = jiffies + HZ;

		goto retry;
	}

	chip->state = FL_WRITING;

	addr += chip->start;

	send_unlock(map, chip->start);
	mw.x[0] = datum;	
	map->write(map, mw, addr);

	times_left = 50000;
	while (times_left-- && flash_is_busy(map, addr))
	{		
		if (need_resched())
		{
			spin_unlock_bh(chip->mutex);
			schedule();
			spin_lock_bh(chip->mutex);
		}
	}
	if (!times_left)
	{
		printk(KERN_WARNING "%s: write to 0x%lx timed out!\n",
				map->name, addr);
		ret = -EIO;
	} else {
		unsigned long verify;
		map_word mw;
	
		mw = map->read(map,addr);
		verify = mw.x[0] ;
		if(verify != datum)
		{
			printk(KERN_WARNING "%s: write to 0x%lx failed. "
				"datum = %lx, verify = %lx\n", map->name,
				addr, datum, verify);
			ret = -EIO;
		}
	}
	chip->state = FL_READY;
	wake_up(&chip->wq);
	spin_unlock_bh(chip->mutex);

	return ret;
}

static int stm_flash_write(struct mtd_info *mtd, loff_t to, size_t len,
			   size_t *retlen, const unsigned char *buf)
{
	struct map_info *map = mtd->priv;
	struct stm_flash_private *private = map->fldrv_priv;
	int ret = 0;
	int chipnum;
	unsigned long offset;
	unsigned long chipstart;

	*retlen = 0;
	if (!len)
		return 0;

	chipnum = to >> private->chipshift;
	offset = to - (chipnum << private->chipshift);
	chipstart = private->chips[chipnum].start;

	/* If it's not bus-aligned, do the first byte write. */
	if (offset & (map->bankwidth -1))
	{
		unsigned long bus_offset = offset & ~(map->bankwidth - 1);
		int i = offset - bus_offset;
		int n = 0;
		unsigned char tmp_buf[4];
		unsigned long datum;

		map->copy_from(map, tmp_buf, 
			       bus_offset + private->chips[chipnum].start,
			       map->bankwidth);
		while (len && i < map->bankwidth)
			tmp_buf[i++] = buf[n++], len--;

		if (map->bankwidth == 2)
			datum = *(__u16*)tmp_buf;
		else if (map->bankwidth == 4)
			datum = *(__u32*)tmp_buf;
		else
			return -EINVAL;

		ret = write_one_word(map, &private->chips[chipnum], bus_offset,
				datum);

		if (ret)
			return ret;

		offset += n;
		buf += n;
		(*retlen) += n;

		if (offset >> private->chipshift)
		{
			chipnum++;
			offset = 0;
			if (chipnum == private->numchips)
				return 0;
		}
	}

	/* We are now aligned, write as much as possible. */
	while (len >= map->bankwidth)
	{
		unsigned long datum;

		if (map->bankwidth == 1)
			datum = *(unsigned char*)buf;
		else if (map->bankwidth == 2)
			datum = *(unsigned short*)buf;
		else if (map->bankwidth == 4)
			datum = *(unsigned long*)buf;
		else
			return -EINVAL;

		ret = write_one_word(map, &private->chips[chipnum], offset, 
				datum);

		if (ret)
			return ret;

		offset += map->bankwidth;
		buf += map->bankwidth;
		(*retlen) += map->bankwidth;
		len -= map->bankwidth;

		if (offset >> private->chipshift)
		{
			chipnum++;
			offset = 0;
			if (chipnum == private->numchips)
				return 0;
			chipstart = private->chips[chipnum].start;
		}
	}

	if (len & (map->bankwidth - 1))
	{
		int i = 0, n = 0;
		unsigned char tmp_buf[2];
		unsigned long datum;

		map->copy_from(map, tmp_buf, 
				offset + private->chips[chipnum].start,
				map->bankwidth);

		while (len--)
			tmp_buf[i++] = buf[n++];

		if (map->bankwidth == 2)
			datum = *(unsigned short*)tmp_buf;
		else if (map->bankwidth == 4)
			datum = *(unsigned long*)tmp_buf;
		else
			return -EINVAL;

		ret = write_one_word(map, &private->chips[chipnum], offset, 
				datum);

		if (ret)
			return ret;

		(*retlen) += n;
	}

	return 0;
}

static int erase_one_block(struct map_info *map, struct flchip *chip,
			   unsigned long addr, unsigned long size)
{
	unsigned long timeo = jiffies + HZ;
	map_word mw;

	DECLARE_WAITQUEUE(wait, current);

retry:
	spin_lock_bh(chip->mutex);

	if (chip->state != FL_READY)
	{
		set_current_state(TASK_UNINTERRUPTIBLE);
		add_wait_queue(&chip->wq, &wait);

		spin_unlock_bh(chip->mutex);

		schedule();
		remove_wait_queue(&chip->wq, &wait);

		if (signal_pending(current))
			return -EINTR;

		timeo = jiffies + HZ;

		goto retry;
	}

	chip->state = FL_ERASING;

	addr += chip->start;
	mw.x[0] = CMD_SECTOR_ERASE_UNLOCK_DATA_1;
	map->write(map, mw , chip->start + CMD_SECTOR_ERASE_UNLOCK_ADDR_1);

	mw.x[0] = CMD_SECTOR_ERASE_UNLOCK_DATA_2;
	map->write(map, mw , chip->start + CMD_SECTOR_ERASE_UNLOCK_ADDR_2);

	mw.x[0] = CMD_SECTOR_ERASE_UNLOCK_DATA_3;
	map->write(map, mw , chip->start + CMD_SECTOR_ERASE_UNLOCK_ADDR_3);

	mw.x[0] = CMD_SECTOR_ERASE_UNLOCK_DATA_4;
	map->write(map, mw , chip->start + CMD_SECTOR_ERASE_UNLOCK_ADDR_4);

	mw.x[0] = CMD_SECTOR_ERASE_UNLOCK_DATA_5;
	map->write(map, mw , chip->start + CMD_SECTOR_ERASE_UNLOCK_ADDR_5);

	mw.x[0] = 0x30; 
	map->write(map,mw,addr);

	timeo = jiffies + (HZ * 20);

	spin_unlock_bh(chip->mutex);
	schedule_timeout(HZ);
	spin_lock_bh(chip->mutex);

	while (flash_is_busy(map, chip->start))
	{
		if (chip->state != FL_ERASING)
		{
			/* Someone's suspended the erase. Sleep. */
			set_current_state(TASK_UNINTERRUPTIBLE);
			add_wait_queue(&chip->wq, &wait);

			spin_unlock_bh(chip->mutex);
			printk(KERN_INFO "%s: erase suspended. Sleeping.\n",
				map->name);
			schedule();
			remove_wait_queue(&chip->wq, &wait);

			if (signal_pending(current))
				return -EINTR;

			timeo = jiffies + (HZ*2);
			spin_lock_bh(chip->mutex);
			continue;
		}

		/* OK Still waiting */
		if (time_after(jiffies, timeo))
		{
			chip->state = FL_READY;
			spin_unlock_bh(chip->mutex);
			printk(KERN_WARNING "%s: waiting for erase to complete "
				"timed out.\n", map->name);

			return -EIO;
		}

		/* Latency issues. Drop the lock, wait a while, and retry. */
		spin_unlock_bh(chip->mutex);

		if (need_resched())		
			schedule();
		else
			udelay(1);

		spin_lock_bh(chip->mutex);
	}

	{
		/* Verify every single word */
		int address;
		int error = 0;
		int verify;
		map_word mw;
		
		for (address = addr; address < (addr + size); address += 2){	
			mw = map->read(map,address);
			verify = mw.x[0];
			if(verify != 0xFFFF)	
			{
				error = 1;
				break;
			}
		}

		if (error)
		{
			chip->state = FL_READY;
			spin_unlock_bh(chip->mutex);
			printk(KERN_WARNING "%s: verify error at 0x%x, size "
				"%ld.\n", map->name, address, size);
			return -EIO;
		}
	}

	chip->state = FL_READY;
	wake_up(&chip->wq);
	spin_unlock_bh(chip->mutex);

	return 0;
}

static int stm_flash_erase(struct mtd_info *mtd, struct erase_info *instr)
{
	struct map_info *map = mtd->priv;
	struct stm_flash_private *private = map->fldrv_priv;
	unsigned long addr, len;
	int chipnum;
	int ret = 0;
	int i, first;
	struct mtd_erase_region_info *regions = mtd->eraseregions;

	if (instr->addr > mtd->size)
		return -EINVAL;

	if ((instr->len + instr->addr) > mtd->size)
		return -EINVAL;

	/*
	 * Check that both start and end of the requested erase are aligned
	 * with the erasesize at the appropriate addresses.
	 */
	i = 0;

	/*
	 * Skip all erase regions which are ended before the start of the
	 * requested erase. Actually, to save on the calculations, we skip
	 * to the first erase region which starts after the start of the 
	 * requested erase, and then go back one.
	 */
	while ((i < mtd->numeraseregions) &&
	       (instr->addr >= regions[i].offset))
		i++;
	i--;

	/*
	 * OK. Now i is pointing at the erase region in which this erase 
	 * request starts. Check the start of the requested erase range
	 * is aligned with the erase size which is in effect here.
	 */
	if (instr->addr & (regions[i].erasesize -1))
		return -EINVAL;

	/*
	 * Remember the erase region we start on.
	 */
	first = i;

	/*
	 * Next, theck that the end of the requested erase is aligned with
	 * the erase region at that address.
	 */
	while ((i < mtd->numeraseregions) &&
	       ((instr->addr + instr->len) >= regions[i].offset))
		i++;
	i--;

	if ((instr->addr + instr->len) & (regions[i].erasesize-1))
		return -EINVAL;

	chipnum = instr->addr >> private->chipshift;
	addr = instr->addr - (chipnum << private->chipshift);
	len = instr->len;

	i = first;

	while (len)
	{
		ret = erase_one_block(map, &private->chips[chipnum], addr,
				regions[i].erasesize);

		if (ret)
			return ret;

		addr += regions[i].erasesize;
		len -= regions[i].erasesize;

		if ((addr % (1 << private->chipshift)) ==
		    ((regions[i].offset + (regions[i].erasesize *
					   regions[i].numblocks))
		     % (1 << private->chipshift)))
			i++;

		if (addr >> private->chipshift)
		{
			addr = 0;
			chipnum++;

			if (chipnum >= private->numchips)
				break;
		}
	}

	instr->state = MTD_ERASE_DONE;
	/*if (instr->callback)
		instr->callback(instr);
	*/
	mtd_erase_callback(instr);

	return 0;
}

static int stm_flash_suspend(struct mtd_info *mtd)
{
	printk("stm_flash_suspend(): not implemented!\n");
	        return -EINVAL;
}

static void stm_flash_resume(struct mtd_info *mtd)
{
	printk("stm_flash_resume(): not implemented!\n");
}

int __init stm_flash_init(void)
{
	register_mtd_chip_driver(&stm_flash_chipdrv);
	return 0;
}

void __exit stm_flash_exit(void)
{
	unregister_mtd_chip_driver(&stm_flash_chipdrv);
}

module_init(stm_flash_init);
module_exit(stm_flash_exit);
