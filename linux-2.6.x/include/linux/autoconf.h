/*
 * Automatically generated C config: don't edit
 */
#define AUTOCONF_INCLUDED
#undef CONFIG_MMU
#undef CONFIG_FPU
#define CONFIG_UID16 1
#define CONFIG_RWSEM_GENERIC_SPINLOCK 1
#undef CONFIG_RWSEM_XCHGADD_ALGORITHM
#define CONFIG_FRIO 1
#define CONFIG_NISA 1

/*
 * Code maturity level options
 */
#define CONFIG_EXPERIMENTAL 1
#define CONFIG_CLEAN_COMPILE 1
#undef CONFIG_STANDALONE
#define CONFIG_BROKEN_ON_SMP 1

/*
 * General setup
 */
#undef CONFIG_SYSVIPC
#undef CONFIG_BSD_PROCESS_ACCT
#undef CONFIG_SYSCTL
#define CONFIG_LOG_BUF_SHIFT 14
#undef CONFIG_IKCONFIG
#define CONFIG_EMBEDDED 1
#define CONFIG_KALLSYMS 1
#define CONFIG_FUTEX 1
#define CONFIG_EPOLL 1
#define CONFIG_IOSCHED_NOOP 1
#define CONFIG_IOSCHED_AS 1
#define CONFIG_IOSCHED_DEADLINE 1
#undef CONFIG_CC_OPTIMIZE_FOR_SIZE

/*
 * Loadable module support
 */
#undef CONFIG_MODULES

/*
 * Processor type and features
 */

/*
 * Processor
 */
#define CONFIG_BF533 1
#undef CONFIG_BF535
#define CONFIG_BLACKFIN 1

/*
 * Platform
 */
#undef CONFIG_EZKIT
#define CONFIG_BLKFIN_STAMP 1
#define CONFIG_RAMKERNEL 1
#undef CONFIG_ROMKERNEL

/*
 * Cache Support
 */
#define CONFIG_BLKFIN_CACHE 1
#undef CONFIG_BLKFIN_DCACHE

/*
 * Crystal Frequency
 */
#define CONFIG_CLKIN 11

/*
 * System Clock
 */
#undef CONFIG_BF53x_SCLK_54_MHZ
#define CONFIG_BF53x_SCLK_99_MHZ 1
#undef CONFIG_BF53x_SCLK_126_MHZ
#undef CONFIG_BF53x_SCLK_129_MHZ
#undef CONFIG_BF53x_SCLK_132_MHZ

/*
 * Interrupt Priority Assignment
 */

/*
 * Priority
 */
#define CONFIG_UART_ERROR 7
#define CONFIG_SPORT0_ERROR 7
#define CONFIG_SPI_ERROR 7
#define CONFIG_SPORT1_ERROR 7
#define CONFIG_PPI_ERROR 7
#define CONFIG_DMA_ERROR 7
#define CONFIG_PLLWAKE_ERROR 7
#define CONFIG_RTC_ERROR 8
#define CONFIG_DMA0_PPI 8
#define CONFIG_DMA1_SPORT0RX 9
#define CONFIG_DMA2_SPORT0TX 9
#define CONFIG_DMA3_SPORT1RX 9
#define CONFIG_DMA4_SPORT1TX 9
#define CONFIG_DMA5_SPI 10
#define CONFIG_DMA6_UARTRX 10
#define CONFIG_DMA7_UARTTX 10
#define CONFIG_TIMER0 11
#define CONFIG_TIMER1 11
#define CONFIG_TIMER2 11
#define CONFIG_PFA 12
#define CONFIG_PFB 12
#define CONFIG_MEMDMA0 13
#define CONFIG_MEMDMA1 13
#define CONFIG_WDTIMER 13

/*
 * Bus options (PCI, PCMCIA, EISA, MCA, ISA)
 */
#undef CONFIG_PCI
#undef CONFIG_HOTPLUG

/*
 * Executable File Formats
 */
#define CONFIG_BINFMT_FLAT 1
#undef CONFIG_BINFMT_ZFLAT
#undef CONFIG_BINFMT_SHARED_FLAT
#undef CONFIG_BINFMT_MISC

/*
 * Power management options
 */
#undef CONFIG_PM

/*
 * Generic Driver Options
 */

/*
 * Memory Technology Devices (MTD)
 */
#define CONFIG_MTD 1
#undef CONFIG_MTD_DEBUG
#define CONFIG_MTD_PARTITIONS 1
#undef CONFIG_MTD_CONCAT
#undef CONFIG_MTD_REDBOOT_PARTS
#undef CONFIG_MTD_CMDLINE_PARTS

/*
 * User Modules And Translation Layers
 */
#undef CONFIG_MTD_CHAR
#undef CONFIG_MTD_BLOCK
#define CONFIG_MTD_BLOCK_RO 1
#undef CONFIG_FTL
#undef CONFIG_NFTL
#undef CONFIG_INFTL

/*
 * RAM/ROM/Flash chip drivers
 */
#undef CONFIG_MTD_CFI
#undef CONFIG_MTD_JEDECPROBE
#define CONFIG_MTD_RAM 1
#undef CONFIG_MTD_ROM
#undef CONFIG_MTD_ABSENT
#undef CONFIG_MTD_OBSOLETE_CHIPS

/*
 * Mapping drivers for chip access
 */
#undef CONFIG_MTD_COMPLEX_MAPPINGS
#define CONFIG_MTD_UCLINUX 1
#undef CONFIG_MTD_SNAPGEARuC

/*
 * Self-contained MTD device drivers
 */
#undef CONFIG_MTD_SLRAM
#undef CONFIG_MTD_MTDRAM
#undef CONFIG_MTD_BLKMTD

/*
 * Disk-On-Chip Device Drivers
 */
#undef CONFIG_MTD_DOC2000
#undef CONFIG_MTD_DOC2001
#undef CONFIG_MTD_DOC2001PLUS

/*
 * NAND Flash Device Drivers
 */
#undef CONFIG_MTD_NAND

/*
 * Parallel port support
 */
#undef CONFIG_PARPORT

/*
 * Plug and Play support
 */

/*
 * Block devices
 */
#undef CONFIG_BLK_DEV_FD
#undef CONFIG_BLK_DEV_LOOP
#undef CONFIG_BLK_DEV_RAM
#undef CONFIG_BLK_DEV_INITRD

/*
 * ATA/ATAPI/MFM/RLL support
 */
#undef CONFIG_IDE

/*
 * SCSI device support
 */
#undef CONFIG_SCSI

/*
 * Multi-device support (RAID and LVM)
 */
#undef CONFIG_MD

/*
 * Fusion MPT device support
 */

/*
 * IEEE 1394 (FireWire) support (EXPERIMENTAL)
 */
#undef CONFIG_IEEE1394

/*
 * I2O device support
 */

/*
 * Networking support
 */
#undef CONFIG_NET

/*
 * Amateur Radio support
 */
#undef CONFIG_HAMRADIO

/*
 * ISDN subsystem
 */

/*
 * Telephony Support
 */
#undef CONFIG_PHONE

/*
 * Input device support
 */
#undef CONFIG_INPUT

/*
 * Userland interfaces
 */

/*
 * Input I/O drivers
 */
#undef CONFIG_GAMEPORT
#define CONFIG_SOUND_GAMEPORT 1
#undef CONFIG_SERIO
#undef CONFIG_SERIO_I8042

/*
 * Input Device Drivers
 */

/*
 * Character devices
 */
#undef CONFIG_VT
#undef CONFIG_SERIAL_NONSTANDARD
#undef CONFIG_LEDMAN
#undef CONFIG_RESETSWITCH

/*
 * Serial drivers
 */
#undef CONFIG_SERIAL_8250

/*
 * Non-8250 serial port support
 */
#define CONFIG_SERIAL_BLACKFIN 1
#define CONFIG_UNIX98_PTYS 1
#define CONFIG_UNIX98_PTY_COUNT 256

/*
 * Mice
 */
#undef CONFIG_BUSMOUSE
#undef CONFIG_QIC02_TAPE

/*
 * IPMI
 */
#undef CONFIG_IPMI_HANDLER

/*
 * Watchdog Cards
 */
#undef CONFIG_WATCHDOG
#undef CONFIG_NVRAM
#undef CONFIG_RTC
#undef CONFIG_GEN_RTC
#define CONFIG_BLACKFIN_RTC 1
#undef CONFIG_DTLK
#undef CONFIG_R3964
#undef CONFIG_APPLICOM

/*
 * Ftape, the floppy tape device driver
 */
#undef CONFIG_FTAPE
#undef CONFIG_AGP
#undef CONFIG_DRM
#undef CONFIG_RAW_DRIVER

/*
 * Multimedia devices
 */
#undef CONFIG_VIDEO_DEV

/*
 * Digital Video Broadcasting Devices
 */

/*
 * File systems
 */
#define CONFIG_EXT2_FS 1
#undef CONFIG_EXT2_FS_XATTR
#undef CONFIG_EXT3_FS
#undef CONFIG_JBD
#undef CONFIG_REISERFS_FS
#undef CONFIG_JFS_FS
#undef CONFIG_XFS_FS
#undef CONFIG_MINIX_FS
#undef CONFIG_ROMFS_FS
#undef CONFIG_QUOTA
#undef CONFIG_AUTOFS_FS
#undef CONFIG_AUTOFS4_FS

/*
 * CD-ROM/DVD Filesystems
 */
#undef CONFIG_ISO9660_FS
#undef CONFIG_UDF_FS

/*
 * DOS/FAT/NT Filesystems
 */
#undef CONFIG_FAT_FS
#undef CONFIG_NTFS_FS

/*
 * Pseudo filesystems
 */
#define CONFIG_PROC_FS 1
#define CONFIG_PROC_KCORE 1
#undef CONFIG_DEVFS_FS
#undef CONFIG_DEVPTS_FS
#undef CONFIG_TMPFS
#undef CONFIG_HUGETLB_PAGE
#define CONFIG_RAMFS 1

/*
 * Miscellaneous filesystems
 */
#undef CONFIG_ADFS_FS
#undef CONFIG_AFFS_FS
#undef CONFIG_HFS_FS
#undef CONFIG_BEFS_FS
#undef CONFIG_BFS_FS
#undef CONFIG_EFS_FS
#undef CONFIG_JFFS_FS
#undef CONFIG_JFFS2_FS
#undef CONFIG_CRAMFS
#undef CONFIG_VXFS_FS
#undef CONFIG_HPFS_FS
#undef CONFIG_QNX4FS_FS
#undef CONFIG_SYSV_FS
#undef CONFIG_UFS_FS

/*
 * Partition Types
 */
#undef CONFIG_PARTITION_ADVANCED
#define CONFIG_MSDOS_PARTITION 1

/*
 * Native Language Support
 */
#undef CONFIG_NLS

/*
 * Graphics support
 */
#undef CONFIG_FB

/*
 * Sound
 */
#undef CONFIG_SOUND

/*
 * USB support
 */

/*
 * USB Gadget Support
 */
#undef CONFIG_USB_GADGET

/*
 * Kernel hacking
 */
#undef CONFIG_FULLDEBUG
#define CONFIG_DEBUG_KERNEL 1
#define CONFIG_DEBUG_SLAB 1
#undef CONFIG_FRAME_POINTER
#undef CONFIG_MAGIC_SYSRQ
#define CONFIG_BOOTPARAM 1
#define CONFIG_BOOTPARAM_STRING "root=/dev/mtdblock0 rw"
#undef CONFIG_NO_KERNEL_MSG

/*
 * Security options
 */
#undef CONFIG_SECURITY

/*
 * Cryptographic options
 */
#undef CONFIG_CRYPTO

/*
 * Library routines
 */
#define CONFIG_CRC32 1
