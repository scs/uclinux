/*
 * Automatically generated C config: don't edit
 */
#define AUTOCONF_INCLUDED
#undef CONFIG_MMU
#undef CONFIG_FPU
#define CONFIG_UID16 1
#define CONFIG_RWSEM_GENERIC_SPINLOCK 1
#undef CONFIG_RWSEM_XCHGADD_ALGORITHM
#define CONFIG_BFIN 1

/*
 * Code maturity level options
 */
#define CONFIG_EXPERIMENTAL 1
#define CONFIG_CLEAN_COMPILE 1
#define CONFIG_BROKEN_ON_SMP 1

/*
 * General setup
 */
#undef CONFIG_POSIX_MQUEUE
#define CONFIG_BSD_PROCESS_ACCT 1
#undef CONFIG_BSD_PROCESS_ACCT_V3
#undef CONFIG_SYSCTL
#undef CONFIG_AUDIT
#define CONFIG_LOG_BUF_SHIFT 14
#undef CONFIG_HOTPLUG
#undef CONFIG_IKCONFIG
#define CONFIG_EMBEDDED 1
#define CONFIG_KALLSYMS 1
#undef CONFIG_KALLSYMS_EXTRA_PASS
#define CONFIG_FUTEX 1
#define CONFIG_EPOLL 1
#define CONFIG_IOSCHED_NOOP 1
#define CONFIG_IOSCHED_AS 1
#define CONFIG_IOSCHED_DEADLINE 1
#define CONFIG_IOSCHED_CFQ 1
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
#undef CONFIG_LARGE_ALLOCS

/*
 * DMA Support
 */
#define CONFIG_BLKFIN_DMA 1

/*
 * Cache Support
 */
#define CONFIG_BLKFIN_CACHE 1
#undef CONFIG_BLKFIN_DCACHE
#undef CONFIG_BLKFIN_CACHE_LOCK
#undef CONFIG_BLKFIN_WB
#define CONFIG_BLKFIN_WT 1

/*
 * Crystal Frequency
 */
#define CONFIG_CLKIN 11

/*
 * Baud Rate
 */
#undef CONFIG_BAUD_9600
#undef CONFIG_BAUD_19200
#undef CONFIG_BAUD_38400
#define CONFIG_BAUD_57600 1
#undef CONFIG_BAUD_115200

/*
 * System Clock
 */
#undef CONFIG_BF53x_SCLK_118_MHZ
#undef CONFIG_BF53x_SCLK_99_MHZ
#undef CONFIG_BF53x_SCLK_126_MHZ
#undef CONFIG_BF53x_SCLK_129_MHZ
#define CONFIG_BF53x_SCLK_132_MHZ 1

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
#define CONFIG_STANDALONE 1
#define CONFIG_PREVENT_FIRMWARE_BUILD 1

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
#define CONFIG_MTD_MAP_BANK_WIDTH_1 1
#define CONFIG_MTD_MAP_BANK_WIDTH_2 1
#define CONFIG_MTD_MAP_BANK_WIDTH_4 1
#undef CONFIG_MTD_MAP_BANK_WIDTH_8
#undef CONFIG_MTD_MAP_BANK_WIDTH_16
#undef CONFIG_MTD_MAP_BANK_WIDTH_32
#define CONFIG_MTD_CFI_I1 1
#define CONFIG_MTD_CFI_I2 1
#undef CONFIG_MTD_CFI_I4
#undef CONFIG_MTD_CFI_I8
#define CONFIG_MTD_RAM 1
#define CONFIG_MTD_ROM 1
#undef CONFIG_MTD_ABSENT

/*
 * Mapping drivers for chip access
 */
#undef CONFIG_MTD_COMPLEX_MAPPINGS
#undef CONFIG_MTD_BF533
#define CONFIG_MTD_UCLINUX 1

/*
 * Self-contained MTD device drivers
 */
#undef CONFIG_MTD_SLRAM
#undef CONFIG_MTD_PHRAM
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
#undef CONFIG_BLK_DEV_NBD
#undef CONFIG_BLK_DEV_RAM

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
 * IEEE 1394 (FireWire) support
 */

/*
 * I2O device support
 */

/*
 * Networking support
 */
#define CONFIG_NET 1

/*
 * Networking options
 */
#define CONFIG_PACKET 1
#undef CONFIG_PACKET_MMAP
#define CONFIG_NETLINK_DEV 1
#define CONFIG_UNIX 1
#undef CONFIG_NET_KEY
#define CONFIG_INET 1
#define CONFIG_IP_MULTICAST 1
#undef CONFIG_IP_ADVANCED_ROUTER
#undef CONFIG_IP_PNP
#undef CONFIG_NET_IPIP
#undef CONFIG_NET_IPGRE
#undef CONFIG_IP_MROUTE
#undef CONFIG_ARPD
#undef CONFIG_SYN_COOKIES
#undef CONFIG_INET_AH
#undef CONFIG_INET_ESP
#undef CONFIG_INET_IPCOMP
#undef CONFIG_IPV6
#undef CONFIG_NETFILTER

/*
 * SCTP Configuration (EXPERIMENTAL)
 */
#undef CONFIG_IP_SCTP
#undef CONFIG_ATM
#undef CONFIG_BRIDGE
#undef CONFIG_VLAN_8021Q
#undef CONFIG_DECNET
#undef CONFIG_LLC2
#undef CONFIG_IPX
#undef CONFIG_ATALK
#undef CONFIG_X25
#undef CONFIG_LAPB
#undef CONFIG_NET_DIVERT
#undef CONFIG_ECONET
#undef CONFIG_WAN_ROUTER
#undef CONFIG_NET_HW_FLOWCONTROL

/*
 * QoS and/or fair queueing
 */
#undef CONFIG_NET_SCHED
#undef CONFIG_NET_CLS_ROUTE

/*
 * Network testing
 */
#undef CONFIG_NET_PKTGEN
#undef CONFIG_NETPOLL
#undef CONFIG_NET_POLL_CONTROLLER
#undef CONFIG_HAMRADIO
#undef CONFIG_IRDA
#undef CONFIG_BT
#define CONFIG_NETDEVICES 1
#undef CONFIG_DUMMY
#undef CONFIG_BONDING
#undef CONFIG_EQUALIZER
#undef CONFIG_TUN
#undef CONFIG_ETHERTAP

/*
 * Ethernet (10 or 100Mbit)
 */
#define CONFIG_NET_ETHERNET 1
#undef CONFIG_MII
#define CONFIG_NET_VENDOR_SMC 1
#define CONFIG_SMSC91C111 1

/*
 * Ethernet (1000 Mbit)
 */

/*
 * Ethernet (10000 Mbit)
 */

/*
 * Token Ring devices
 */

/*
 * Wireless LAN (non-hamradio)
 */
#undef CONFIG_NET_RADIO

/*
 * Wan interfaces
 */
#undef CONFIG_WAN
#undef CONFIG_PPP
#undef CONFIG_SLIP
#undef CONFIG_SHAPER
#undef CONFIG_NETCONSOLE

/*
 * ISDN subsystem
 */
#undef CONFIG_ISDN

/*
 * Telephony Support
 */
#undef CONFIG_PHONE

/*
 * Input device support
 */
#define CONFIG_INPUT 1

/*
 * Userland interfaces
 */
#define CONFIG_INPUT_MOUSEDEV 1
#undef CONFIG_INPUT_MOUSEDEV_PSAUX
#define CONFIG_INPUT_MOUSEDEV_SCREEN_X 1024
#define CONFIG_INPUT_MOUSEDEV_SCREEN_Y 768
#undef CONFIG_INPUT_JOYDEV
#undef CONFIG_INPUT_TSDEV
#undef CONFIG_INPUT_EVDEV
#undef CONFIG_INPUT_EVBUG

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
#undef CONFIG_INPUT_KEYBOARD
#undef CONFIG_INPUT_MOUSE
#undef CONFIG_INPUT_JOYSTICK
#undef CONFIG_INPUT_TOUCHSCREEN
#undef CONFIG_INPUT_MISC

/*
 * Character devices
 */
#undef CONFIG_VT
#undef CONFIG_SERIAL_NONSTANDARD

/*
 * Serial drivers
 */
#undef CONFIG_SERIAL_8250

/*
 * Non-8250 serial port support
 */
#define CONFIG_SERIAL_BLACKFIN 1
#define CONFIG_UNIX98_PTYS 1
#undef CONFIG_LEGACY_PTYS
#undef CONFIG_QIC02_TAPE

/*
 * IPMI
 */
#undef CONFIG_IPMI_HANDLER

/*
 * Watchdog Cards
 */
#undef CONFIG_WATCHDOG
#undef CONFIG_RTC
#undef CONFIG_GEN_RTC
#define CONFIG_BLACKFIN_RTC 1
#undef CONFIG_BLACKFIN_DPMC
#undef CONFIG_DTLK
#undef CONFIG_R3964

/*
 * Ftape, the floppy tape device driver
 */
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
#undef CONFIG_DVB

/*
 * File systems
 */
#define CONFIG_EXT2_FS 1
#define CONFIG_EXT2_FS_XATTR 1
#undef CONFIG_EXT2_FS_POSIX_ACL
#undef CONFIG_EXT2_FS_SECURITY
#undef CONFIG_EXT3_FS
#undef CONFIG_JBD
#define CONFIG_FS_MBCACHE 1
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
#undef CONFIG_MSDOS_FS
#undef CONFIG_VFAT_FS
#undef CONFIG_NTFS_FS

/*
 * Pseudo filesystems
 */
#define CONFIG_PROC_FS 1
#define CONFIG_PROC_KCORE 1
#define CONFIG_SYSFS 1
#undef CONFIG_DEVFS_FS
#define CONFIG_DEVPTS_FS_XATTR 1
#undef CONFIG_DEVPTS_FS_SECURITY
#define CONFIG_TMPFS 1
#undef CONFIG_HUGETLB_PAGE
#define CONFIG_RAMFS 1

/*
 * Miscellaneous filesystems
 */
#undef CONFIG_ADFS_FS
#undef CONFIG_AFFS_FS
#undef CONFIG_HFS_FS
#undef CONFIG_HFSPLUS_FS
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
 * Network File Systems
 */
#undef CONFIG_NFS_FS
#undef CONFIG_NFSD
#undef CONFIG_EXPORTFS
#undef CONFIG_SMB_FS
#undef CONFIG_CIFS
#undef CONFIG_NCP_FS
#undef CONFIG_CODA_FS
#undef CONFIG_AFS_FS

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
#undef CONFIG_DEBUG_KERNEL
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
#undef CONFIG_CRC_CCITT
#define CONFIG_CRC32 1
#undef CONFIG_LIBCRC32C
