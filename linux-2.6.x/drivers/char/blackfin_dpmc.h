#define DPMC_VERSION "0.1"

static loff_t dpmc_llseek(struct file *file, loff_t offset, int origin);
static ssize_t dpmc_read(struct file *file, char *buf, size_t count, loff_t *ppos);
static int dpmc_ioctl(struct inode *inode, struct file *file, unsigned int cmd, unsigned long arg);
static int dpmc_read_proc(char *page, char **start, off_t off, int count, int *eof, void *data);

void fullon_mode(void);
void active_mode(void);
void sleep_mode(void);
void deep_sleep(void);


#define SDRAM_Tref  	64       /* Refresh period in milliseconds   */
#ifdef CONFIG_EZKIT
	#define SDRAM_NRA   	4096     /* Number of row addresses in SDRAM */
#elif CONFIG_BLKFIN_STAMP
	#define SDRAM_NRA   	8192     /* Number of row addresses in SDRAM */
#endif
#define SDRAM_CL	2

#define FLAG_CSEL	0x0
#define FLAG_SSEL	0x1

