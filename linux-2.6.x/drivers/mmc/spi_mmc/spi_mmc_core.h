	
// struct for keeping performace data for debugging
struct perf_info {
	int read_burst_peak;		/* expressed in CYCLES */
	int read_burst_low;
	cycles_t read_mean;
	int write_burst_peak;
	int write_burst_low;
	cycles_t write_mean;
	int nsect_max;
	int nsect_min;
	unsigned int blocks_read;
	unsigned int blocks_written;
	unsigned int last_block;
};

// internal representation of the MMC over SPI block device
struct Mmc_info {
	unsigned int hardsect_size;	/* Sector size in bytes */
	unsigned int nsectors;		/* Number of sectors */
	unsigned int spi_speed_hz;	/* Currently selected speed */
	unsigned short max_phys_segments;
	unsigned short max_hw_segments;
	unsigned short max_sectors;
	unsigned short max_segment_size;
	short users;			/* How many "users"(nr. of opens issued by kernel) */
	short media_change;		/* Flag a media change? */
	short need_re_init;		/* If abruptly aborted, MMC may need to re-init */
	short card_in_bay;		/* Keeps track if media is inserted or not */
	spinlock_t queue_lock;		/* Block device spinlock(for preemtive kernels) */
	spinlock_t dev_lock;		/* device lock for critical access to MMC device */
	struct semaphore sem;		/* MUTEX */
	struct gendisk *gd;		/* The gendisk structure */
	struct mmc_spi_dev msd;		/* mmc_spi read/write methods to use */
	struct mmc_card card;		/* structure for holding card information */
	struct perf_info pi;		/* struct holding numbers on performace */
	struct spi_device *spi_dev;	/* The assigned spi_device */
	struct workqueue_struct *cd_wq; /* Card detect work queue */
	struct work_struct *cd_ws;	/* The work struct that defines what to do*/
};

typedef struct Mmc_info mmc_info_t;

//static int spi_mmc_release(struct inode *inode, struct file *filp);
