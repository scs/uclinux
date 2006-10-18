// For developing, set this. Can be set from Kconfig.
#ifndef CONFIG_SPI_MMC_DEBUG_MODE
//#define CONFIG_SPI_MMC_DEBUG_MODE
#endif

enum {
	MMC_INIT_TIMEOUT 	= 100,	// msec, Timeout when polling for R1_OK at init of MMC/SDs
	MMC_COMMAND_TIMEOUT	= 100,	// msec, Time to wait for command responses
	MMC_PROG_TIMEOUT	= 800,	// msec, Programming busy time to wait
	BUSY_BLOCK_LEN 		= 1,	// Busy response blockwise(w. DMA preferably, size
	BUSY_BLOCK_LEN_SHORT	= 16,	// Short version, multiple block waits are much faster
	MMC_SECTOR_SIZE		= 512,	// Size of MMC sectors, this should actually be fetched from
	SD_PRE_CMD_ZEROS	= 4,	// Send so many zeros if in SD mode(wake up from pos. sleep)
	SD_CLK_CNTRL		= 2,

// Card command classes
	/* could be implemented to ensure compability */

// Internal error codes
	ERR_SPI_TIMEOUT		= 0xF1,
	ERR_MMC_TIMEOUT		= 0xF2,
	ERR_MMC_PROG_TIMEOUT 	= 0xF3,
	ERR_UNKNOWN_TOK		= 0xF4,

// return values from functions
	RVAL_OK			= 0,
	RVAL_ERROR		= 1,
	RVAL_CRITICAL		= 2,

// Format R1(b) response tokens (1 byte long)
	BUSY_TOKEN		= 0x00,
	R1_OK			= 0x00,
	R1_IDLE_STATE		= 0x01,
	R1_ERASE_STATE		= 0x02,
	R1_ILLEGAL_COMMAND	= 0x04,
	R1_COM_CRC_ERROR	= 0x08,
	R1_ERASE_SEQ_ERROR	= 0x10,
	R1_ADDRESS_ERROR	= 0x20,
	R1_PARAMETER_ERROR	= 0x40,

// Format R2 response tokens (2 bytes long, first is same as R1 responses)
	R2_OK			= 0x00,
	R2_CARD_LOCKED		= 0x01,
	R2_WP_ERASE_SKIP	= 0x02,
	R2_LOCK_UNLOCK_CMD_FAIL	= 0x02,
	R2_ERROR		= 0x04,
	R2_CC_ERROR		= 0x08,
	R2_CARD_ECC_FAILED	= 0x10,
	R2_WP_VIOLATION		= 0x20,
	R2_ERASE_PARAM		= 0x40,
	R2_OUT_OF_RANGE		= 0x80,
	R2_CSD_OVERWRITE	= 0x80,
// TODO: Format R3 response tokens 

// Data response tokens
	DR_MASK			= 0x0F,
	DR_ACCEPTED		= 0x05,
	DR_CRC_ERROR		= 0x0B,
	DR_WRITE_ERROR		= 0x0D,

// Data tokens (4 bytes to (N+3) bytes long), N is data block len
//  format of the Start Data Block Token
	SBT_S_BLOCK_READ	= 0xFE,
	SBT_M_BLOCK_READ	= 0xFE,
	SBT_S_BLOCK_WRITE	= 0xFE,
	SBT_M_BLOCK_WRITE 	= 0xFC,
	STT_M_BLOCK_WRITE	= 0xFD,

// Data error tokens (1 byte long)
	DE_ERROR		= 0x01,
	DE_CC_ERROR		= 0x02,
	DE_CARD_ECC_FAILED	= 0x04,
	DE_OUT_OF_RANGE		= 0x08,
	DE_CARD_IS_LOCKED	= 0x10,

// MMC/SD SPI mode commands
	GO_IDLE_STATE		= 0,
	SEND_OP_COND		= 1,
	SEND_CSD		= 9,
	SEND_CID		= 10,
	STOP_TRANSMISSION	= 12,
	SEND_STATUS		= 13,
	SET_BLOCKLEN		= 16,
	READ_SINGLE_BLOCK	= 17,
	READ_MULTIPLE_BLOCK	= 18,
	WRITE_BLOCK		= 24,
	WRITE_MULTIPLE_BLOCK	= 25,
	SD_SEND_OP_COND		= 41,
	APP_CMD			= 55,
};

/* minimal local versions of CSD/CID structures,
   somewhat ripped from linux MMC layer, the entire
   CSD struct is larger and is not completley parsed
*/
struct cid_str {
	unsigned int		manfid;
	char			prod_name[8];
	unsigned int		serial;
	unsigned short		oemid;
	unsigned short		year;
	unsigned char		hwrev;
	unsigned char		fwrev;
	unsigned char		month;
};

struct csd_str {				/* __csd field name__*/
	unsigned char		mmca_vsn;	/* CSD_STRUCTURE */
	unsigned short		cmdclass;	/* CCC */
	unsigned short		tacc_clks;	/* TAAC */
	unsigned int		tacc_ns;	/* NSAC */
	unsigned int		max_dtr;	/* TRANS_SPEED */
	unsigned int		read_blkbits;	/* READ_BL_LEN */
	unsigned int		capacity;
};

/**
*	mmc_spi_dev - External functions need to configure this struct
*		with callback functions to read and write data that the
*		mmc_spi function can use for its operations. It also have
*		to support it with a function that can return a millisecond
*		time counter for I/O timeouts.
*
*		NOTE: Every function defined here expect exclusive access to
*		any MMC/SD card it is operating on. Functions should be considered
*		critical sections. Also note that the read/write callbacks may a mutex
*		if they may be executed by another context.
*/
struct mmc_spi_dev {
	int		(*read)(unsigned char *buf, unsigned int nbytes, void *priv_data);
	int		(*write)(unsigned char *buf, unsigned int nbytes, void *priv_data);
	void		(*reset_time)(unsigned long msec); /* set time to wait for(use before polling) */
	int		(*elapsed_time)(void); /* evaluates to true after configured msec */
	void		*priv_data;	/* incomming pointer to private data */
	unsigned char 	raw_csd[18];	/* raw csd data to use with external parser */
	unsigned char 	raw_cid[18];	/* raw cid data to use with external parser */
	struct cid_str 	cid;
	struct csd_str 	csd;
	int		sd;		/* set if SD card found */
	unsigned short	force_cs_high;
};

short mmc_spi_get_card(struct mmc_spi_dev *pdev);
short mmc_spi_read_status(struct mmc_spi_dev *pdev);
short mmc_spi_dummy_clocks(struct mmc_spi_dev *pdev, unsigned short nbytes);
short mmc_spi_read_mmc_block(struct mmc_spi_dev *pdev, unsigned char *buf, unsigned int address);
short mmc_spi_read_mult_mmc_block(struct mmc_spi_dev *pdev, unsigned char* buf, unsigned int address, int nblocks);
short mmc_spi_write_mmc_block(struct mmc_spi_dev *pdev, unsigned char *buf, unsigned int address);
short mmc_spi_write_mult_mmc_block(struct mmc_spi_dev *pdev, unsigned char* buf, unsigned int address, int nblocks);
short mmc_spi_init_card(struct mmc_spi_dev *pdev);

