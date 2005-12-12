#
# Automatically generated make config: don't edit
# Linux kernel version: 2.6.12.1
# Mon Dec 12 14:22:36 2005
#
# CONFIG_MMU is not set
# CONFIG_FPU is not set
CONFIG_UID16=y
CONFIG_RWSEM_GENERIC_SPINLOCK=y
# CONFIG_RWSEM_XCHGADD_ALGORITHM is not set
CONFIG_BFIN=y
CONFIG_UCLINUX=y
CONFIG_FORCE_MAX_ZONEORDER=14

#
# Code maturity level options
#
CONFIG_EXPERIMENTAL=y
CONFIG_CLEAN_COMPILE=y
CONFIG_BROKEN_ON_SMP=y
CONFIG_INIT_ENV_ARG_LIMIT=32

#
# General setup
#
CONFIG_LOCALVERSION=""
# CONFIG_POSIX_MQUEUE is not set
# CONFIG_BSD_PROCESS_ACCT is not set
CONFIG_SYSCTL=y
# CONFIG_AUDIT is not set
CONFIG_LOG_BUF_SHIFT=14
CONFIG_GENERIC_CALIBRATE_DELAY=y
# CONFIG_HOTPLUG is not set
CONFIG_KOBJECT_UEVENT=y
# CONFIG_IKCONFIG is not set
CONFIG_EMBEDDED=y
CONFIG_KALLSYMS=y
# CONFIG_KALLSYMS_EXTRA_PASS is not set
CONFIG_PRINTK=y
CONFIG_BUG=y
CONFIG_BASE_FULL=y
CONFIG_FUTEX=y
CONFIG_EPOLL=y
# CONFIG_CC_OPTIMIZE_FOR_SIZE is not set
CONFIG_CC_ALIGN_FUNCTIONS=0
CONFIG_CC_ALIGN_LABELS=0
CONFIG_CC_ALIGN_LOOPS=0
CONFIG_CC_ALIGN_JUMPS=0
CONFIG_BASE_SMALL=0

#
# Loadable module support
#
CONFIG_MODULES=y
CONFIG_MODULE_UNLOAD=y
# CONFIG_MODULE_FORCE_UNLOAD is not set
CONFIG_OBSOLETE_MODPARM=y
# CONFIG_MODVERSIONS is not set
# CONFIG_MODULE_SRCVERSION_ALL is not set
CONFIG_KMOD=y

#
# Blackfin Processor Options
#

#
# Processor and Board Settings
#
CONFIG_BF533=y
# CONFIG_BF532 is not set
# CONFIG_BF531 is not set
# CONFIG_BF534 is not set
# CONFIG_BF535 is not set
# CONFIG_BF536 is not set
# CONFIG_BF537 is not set
# CONFIG_BF561 is not set
CONFIG_BLACKFIN=y
CONFIG_BFIN_SINGLE_CORE=y
# CONFIG_BFIN533_EZKIT is not set
CONFIG_BFIN533_STAMP=y
# CONFIG_BFIN537_STAMP is not set
# CONFIG_BFIN533_BLUETECHNIX_CM is not set
# CONFIG_BFIN561_EZKIT is not set
# CONFIG_GENERIC_BOARD is not set
CONFIG_MEM_MT48LC64M4A2FB_7E=y
CONFIG_BFIN_SHARED_FLASH_ENET=y

#
# BF533/2/1 Specific Configuration
#

#
# Interrupt Priority Assignment
#

#
# Priority
#
CONFIG_UART_ERROR=7
CONFIG_SPORT0_ERROR=7
CONFIG_SPI_ERROR=7
CONFIG_SPORT1_ERROR=7
CONFIG_PPI_ERROR=7
CONFIG_DMA_ERROR=7
CONFIG_PLLWAKE_ERROR=7
CONFIG_RTC_ERROR=8
CONFIG_DMA0_PPI=8
CONFIG_DMA1_SPORT0RX=9
CONFIG_DMA2_SPORT0TX=9
CONFIG_DMA3_SPORT1RX=9
CONFIG_DMA4_SPORT1TX=9
CONFIG_DMA5_SPI=10
CONFIG_DMA6_UARTRX=10
CONFIG_DMA7_UARTTX=10
CONFIG_TIMER0=11
CONFIG_TIMER1=11
CONFIG_TIMER2=11
CONFIG_PFA=12
CONFIG_PFB=12
CONFIG_MEMDMA0=13
CONFIG_MEMDMA1=13
CONFIG_WDTIMER=13
CONFIG_BFIN_HAVE_RTC=y

#
# Board specific issues
#

#
# Board Setup
#
CONFIG_CLKIN_HZ=11059200
CONFIG_MEM_SIZE=128
CONFIG_MEM_ADD_WIDTH=11
CONFIG_ENET_FLASH_PIN=1

#
# LED Status Indicators
#
# CONFIG_BFIN_ALIVE_LED is not set
# CONFIG_BFIN_IDLE_LED is not set
CONFIG_BFIN_ALIVE_LED_PORT=0xFFC00700
CONFIG_BFIN_ALIVE_LED_DPORT=0xFFC00730
CONFIG_BFIN_IDLE_LED_PORT=0xFFC00700
CONFIG_BFIN_IDLE_LED_DPORT=0xFFC00730

#
# Console UART Setup
#
# CONFIG_BAUD_9600 is not set
# CONFIG_BAUD_19200 is not set
# CONFIG_BAUD_38400 is not set
CONFIG_BAUD_57600=y
# CONFIG_BAUD_115200 is not set
CONFIG_BAUD_NO_PARITY=y
# CONFIG_BAUD_PARITY is not set
CONFIG_BAUD_1_STOPBIT=y
# CONFIG_BAUD_2_STOPBIT is not set
CONFIG_RAMKERNEL=y
# CONFIG_ROMKERNEL is not set
CONFIG_LARGE_ALLOCS=y
# CONFIG_IRQCHIP_DEMUX_GPIO is not set

#
# DMA Support
#
# CONFIG_NO_DMA is not set
CONFIG_BFIN_DMA_5XX=y

#
# Cache Support
#
CONFIG_BLKFIN_CACHE=y
CONFIG_BLKFIN_DCACHE=y
# CONFIG_BLKFIN_CACHE_LOCK is not set
# CONFIG_BLKFIN_WB is not set
CONFIG_BLKFIN_WT=y
CONFIG_UNCACHED_1M=y

#
# Clock Settings
#
# CONFIG_BFIN_KERNEL_CLOCK is not set

#
# Asynchonous Memory Configuration
#

#
# EBIU_AMBCTL Global Control
#
CONFIG_C_AMCKEN=y
CONFIG_C_CDPRIO=y
# CONFIG_C_AMBEN is not set
# CONFIG_C_AMBEN_B0 is not set
# CONFIG_C_AMBEN_B0_B1 is not set
# CONFIG_C_AMBEN_B0_B1_B2 is not set
CONFIG_C_AMBEN_ALL=y

#
# EBIU_AMBCTL Control
#
CONFIG_BANK_0=0x7BB0
CONFIG_BANK_1=0x7BB0
CONFIG_BANK_2=0x7BB0
CONFIG_BANK_3=0x99B3

#
# Bus options (PCI, PCMCIA, EISA, MCA, ISA)
#
# CONFIG_PCI is not set

#
# PCCARD (PCMCIA/CardBus) support
#
# CONFIG_PCCARD is not set

#
# PCI Hotplug Support
#

#
# Executable File Formats
#
CONFIG_BINFMT_FLAT=y
# CONFIG_BINFMT_ZFLAT is not set
# CONFIG_BINFMT_SHARED_FLAT is not set
# CONFIG_BINFMT_MISC is not set

#
# Power management options
#
# CONFIG_PM is not set

#
# CPU Frequency scaling
#
# CONFIG_CPU_FREQ is not set

#
# Generic Driver Options
#
CONFIG_STANDALONE=y
CONFIG_PREVENT_FIRMWARE_BUILD=y
# CONFIG_FW_LOADER is not set

#
# Memory Technology Devices (MTD)
#
CONFIG_MTD=y
# CONFIG_MTD_DEBUG is not set
# CONFIG_MTD_CONCAT is not set
CONFIG_MTD_PARTITIONS=y
# CONFIG_MTD_REDBOOT_PARTS is not set
# CONFIG_MTD_CMDLINE_PARTS is not set

#
# User Modules And Translation Layers
#
CONFIG_MTD_CHAR=m
CONFIG_MTD_BLOCK=y
# CONFIG_FTL is not set
# CONFIG_NFTL is not set
# CONFIG_INFTL is not set

#
# RAM/ROM/Flash chip drivers
#
# CONFIG_MTD_CFI is not set
CONFIG_MTD_JEDECPROBE=m
CONFIG_MTD_GEN_PROBE=m
# CONFIG_MTD_CFI_ADV_OPTIONS is not set
CONFIG_MTD_MAP_BANK_WIDTH_1=y
CONFIG_MTD_MAP_BANK_WIDTH_2=y
CONFIG_MTD_MAP_BANK_WIDTH_4=y
# CONFIG_MTD_MAP_BANK_WIDTH_8 is not set
# CONFIG_MTD_MAP_BANK_WIDTH_16 is not set
# CONFIG_MTD_MAP_BANK_WIDTH_32 is not set
CONFIG_MTD_CFI_I1=y
CONFIG_MTD_CFI_I2=y
# CONFIG_MTD_CFI_I4 is not set
# CONFIG_MTD_CFI_I8 is not set
# CONFIG_MTD_CFI_INTELEXT is not set
# CONFIG_MTD_CFI_AMDSTD is not set
# CONFIG_MTD_CFI_STAA is not set
CONFIG_MTD_MW320D=m
CONFIG_MTD_M25P64=m
CONFIG_MTD_RAM=y
CONFIG_MTD_ROM=m
# CONFIG_MTD_ABSENT is not set

#
# Mapping drivers for chip access
#
CONFIG_MTD_COMPLEX_MAPPINGS=y
CONFIG_MTD_BF5xx_SPI=m
CONFIG_MTD_BF5xx=m
CONFIG_BFIN_FLASH_SIZE=0x400000
CONFIG_EBIU_FLASH_BASE=0x20000000

#
# FLASH_EBIU_AMBCTL Control
#
CONFIG_BFIN_FLASH_BANK_0=0x7BB0
CONFIG_BFIN_FLASH_BANK_1=0x7BB0
CONFIG_BFIN_FLASH_BANK_2=0x7BB0
CONFIG_BFIN_FLASH_BANK_3=0x7BB0
CONFIG_MTD_UCLINUX=y

#
# Self-contained MTD device drivers
#
# CONFIG_MTD_SLRAM is not set
# CONFIG_MTD_PHRAM is not set
# CONFIG_MTD_MTDRAM is not set
# CONFIG_MTD_BLKMTD is not set
# CONFIG_MTD_BLOCK2MTD is not set

#
# Disk-On-Chip Device Drivers
#
# CONFIG_MTD_DOC2000 is not set
# CONFIG_MTD_DOC2001 is not set
# CONFIG_MTD_DOC2001PLUS is not set

#
# NAND Flash Device Drivers
#
# CONFIG_MTD_NAND is not set

#
# Parallel port support
#
# CONFIG_PARPORT is not set

#
# Plug and Play support
#

#
# Block devices
#
# CONFIG_BLK_DEV_FD is not set
# CONFIG_BLK_DEV_COW_COMMON is not set
# CONFIG_BLK_DEV_LOOP is not set
# CONFIG_BLK_DEV_NBD is not set
CONFIG_BLK_DEV_RAM=y
CONFIG_BLK_DEV_RAM_COUNT=16
CONFIG_BLK_DEV_RAM_SIZE=4096
# CONFIG_BLK_DEV_INITRD is not set
CONFIG_INITRAMFS_SOURCE=""
# CONFIG_CDROM_PKTCDVD is not set

#
# IO Schedulers
#
CONFIG_IOSCHED_NOOP=y
# CONFIG_IOSCHED_AS is not set
# CONFIG_IOSCHED_DEADLINE is not set
CONFIG_IOSCHED_CFQ=y
# CONFIG_ATA_OVER_ETH is not set

#
# ATA/ATAPI/MFM/RLL support
#
# CONFIG_IDE is not set

#
# IDE Extra configuration
#
CONFIG_BFIN_IDE_ADDRESS_MAPPING_MODE0=y
# CONFIG_BFIN_IDE_ADDRESS_MAPPING_MODE1 is not set

#
# SCSI device support
#
# CONFIG_SCSI is not set

#
# Multi-device support (RAID and LVM)
#
# CONFIG_MD is not set

#
# Fusion MPT device support
#

#
# IEEE 1394 (FireWire) support
#

#
# I2O device support
#

#
# Networking support
#
CONFIG_NET=y

#
# Networking options
#
CONFIG_PACKET=y
# CONFIG_PACKET_MMAP is not set
CONFIG_UNIX=y
# CONFIG_NET_KEY is not set
CONFIG_INET=y
# CONFIG_IP_MULTICAST is not set
# CONFIG_IP_ADVANCED_ROUTER is not set
# CONFIG_IP_PNP is not set
# CONFIG_NET_IPIP is not set
# CONFIG_NET_IPGRE is not set
# CONFIG_ARPD is not set
CONFIG_SYN_COOKIES=y
# CONFIG_INET_AH is not set
# CONFIG_INET_ESP is not set
# CONFIG_INET_IPCOMP is not set
# CONFIG_INET_TUNNEL is not set
CONFIG_IP_TCPDIAG=y
# CONFIG_IP_TCPDIAG_IPV6 is not set
# CONFIG_IPV6 is not set
# CONFIG_NETFILTER is not set

#
# SCTP Configuration (EXPERIMENTAL)
#
# CONFIG_IP_SCTP is not set
# CONFIG_ATM is not set
# CONFIG_BRIDGE is not set
# CONFIG_VLAN_8021Q is not set
# CONFIG_DECNET is not set
# CONFIG_LLC2 is not set
# CONFIG_IPX is not set
# CONFIG_ATALK is not set
# CONFIG_X25 is not set
# CONFIG_LAPB is not set
# CONFIG_NET_DIVERT is not set
# CONFIG_ECONET is not set
# CONFIG_WAN_ROUTER is not set

#
# QoS and/or fair queueing
#
# CONFIG_NET_SCHED is not set
# CONFIG_NET_CLS_ROUTE is not set

#
# Network testing
#
# CONFIG_NET_PKTGEN is not set
# CONFIG_NETPOLL is not set
# CONFIG_NET_POLL_CONTROLLER is not set
# CONFIG_HAMRADIO is not set
# CONFIG_IRDA is not set
# CONFIG_BT is not set
CONFIG_NETDEVICES=y
# CONFIG_DUMMY is not set
# CONFIG_BONDING is not set
# CONFIG_EQUALIZER is not set
# CONFIG_TUN is not set

#
# Ethernet (10 or 100Mbit)
#
CONFIG_NET_ETHERNET=y
CONFIG_MII=y
CONFIG_SMC91X=y

#
# Ethernet (1000 Mbit)
#

#
# Ethernet (10000 Mbit)
#

#
# Token Ring devices
#

#
# Wireless LAN (non-hamradio)
#
# CONFIG_NET_RADIO is not set

#
# Wan interfaces
#
# CONFIG_WAN is not set
# CONFIG_PPP is not set
# CONFIG_SLIP is not set
# CONFIG_SHAPER is not set
# CONFIG_NETCONSOLE is not set

#
# ISDN subsystem
#
# CONFIG_ISDN is not set

#
# Telephony Support
#
# CONFIG_PHONE is not set

#
# Input device support
#
# CONFIG_INPUT is not set

#
# Hardware I/O ports
#
# CONFIG_SERIO is not set
# CONFIG_GAMEPORT is not set

#
# I2C support
#
# CONFIG_I2C is not set

#
# Character devices
#
CONFIG_BFIN_SPI_CHANNEL=y
# CONFIG_SPI_ADC_BF533 is not set
# CONFIG_BF533_PFLAGS is not set
# CONFIG_BF5xx_PPIFCD is not set
# CONFIG_BF5xx_PPI is not set
# CONFIG_BFIN_TIMER_LATENCY is not set
# CONFIG_VT is not set
# CONFIG_SERIAL_NONSTANDARD is not set

#
# Serial drivers
#
# CONFIG_SERIAL_8250 is not set

#
# Non-8250 serial port support
#
CONFIG_SERIAL_BLACKFIN=y
CONFIG_SERIAL_BLACKFIN_DMA=y
# CONFIG_SERIAL_BLACKFIN_PIO is not set
CONFIG_UNIX98_PTYS=y
CONFIG_LEGACY_PTYS=y
CONFIG_LEGACY_PTY_COUNT=256

#
# IPMI
#
# CONFIG_IPMI_HANDLER is not set

#
# Watchdog Cards
#
# CONFIG_WATCHDOG is not set
# CONFIG_RTC is not set
# CONFIG_GEN_RTC is not set
CONFIG_BLACKFIN_RTC=y
CONFIG_BLACKFIN_DPMC=y
# CONFIG_DTLK is not set
# CONFIG_R3964 is not set

#
# Ftape, the floppy tape device driver
#
# CONFIG_DRM is not set
# CONFIG_RAW_DRIVER is not set

#
# TPM devices
#

#
# Multimedia devices
#
# CONFIG_VIDEO_DEV is not set

#
# Digital Video Broadcasting Devices
#
# CONFIG_DVB is not set

#
# File systems
#
CONFIG_EXT2_FS=y
CONFIG_EXT2_FS_XATTR=y
# CONFIG_EXT2_FS_POSIX_ACL is not set
# CONFIG_EXT2_FS_SECURITY is not set
# CONFIG_EXT3_FS is not set
# CONFIG_JBD is not set
CONFIG_FS_MBCACHE=y
# CONFIG_REISERFS_FS is not set
# CONFIG_JFS_FS is not set

#
# XFS support
#
# CONFIG_XFS_FS is not set
# CONFIG_MINIX_FS is not set
# CONFIG_ROMFS_FS is not set
# CONFIG_QUOTA is not set
CONFIG_DNOTIFY=y
# CONFIG_AUTOFS_FS is not set
# CONFIG_AUTOFS4_FS is not set

#
# CD-ROM/DVD Filesystems
#
# CONFIG_ISO9660_FS is not set
# CONFIG_UDF_FS is not set

#
# DOS/FAT/NT Filesystems
#
# CONFIG_MSDOS_FS is not set
# CONFIG_VFAT_FS is not set
# CONFIG_NTFS_FS is not set

#
# Pseudo filesystems
#
CONFIG_PROC_FS=y
CONFIG_SYSFS=y
# CONFIG_DEVFS_FS is not set
# CONFIG_DEVPTS_FS_XATTR is not set
# CONFIG_TMPFS is not set
# CONFIG_HUGETLB_PAGE is not set
CONFIG_RAMFS=y

#
# Miscellaneous filesystems
#
# CONFIG_ADFS_FS is not set
# CONFIG_AFFS_FS is not set
# CONFIG_HFS_FS is not set
# CONFIG_HFSPLUS_FS is not set
# CONFIG_BEFS_FS is not set
# CONFIG_BFS_FS is not set
# CONFIG_EFS_FS is not set
# CONFIG_YAFFS_FS is not set
# CONFIG_JFFS_FS is not set
CONFIG_JFFS2_FS=m
CONFIG_JFFS2_FS_DEBUG=0
# CONFIG_JFFS2_FS_NAND is not set
# CONFIG_JFFS2_FS_NOR_ECC is not set
# CONFIG_JFFS2_COMPRESSION_OPTIONS is not set
CONFIG_JFFS2_ZLIB=y
CONFIG_JFFS2_RTIME=y
# CONFIG_JFFS2_RUBIN is not set
# CONFIG_CRAMFS is not set
# CONFIG_VXFS_FS is not set
# CONFIG_HPFS_FS is not set
# CONFIG_QNX4FS_FS is not set
# CONFIG_SYSV_FS is not set
# CONFIG_UFS_FS is not set

#
# Network File Systems
#
CONFIG_NFS_FS=m
CONFIG_NFS_V3=y
# CONFIG_NFS_V4 is not set
# CONFIG_NFS_DIRECTIO is not set
# CONFIG_NFSD is not set
CONFIG_LOCKD=m
CONFIG_LOCKD_V4=y
CONFIG_SUNRPC=m
# CONFIG_RPCSEC_GSS_KRB5 is not set
# CONFIG_RPCSEC_GSS_SPKM3 is not set
CONFIG_SMB_FS=m
# CONFIG_SMB_NLS_DEFAULT is not set
# CONFIG_CIFS is not set
# CONFIG_NCP_FS is not set
# CONFIG_CODA_FS is not set
# CONFIG_AFS_FS is not set

#
# Partition Types
#
# CONFIG_PARTITION_ADVANCED is not set
CONFIG_MSDOS_PARTITION=y

#
# Native Language Support
#
CONFIG_NLS=m
CONFIG_NLS_DEFAULT="iso8859-1"
# CONFIG_NLS_CODEPAGE_437 is not set
# CONFIG_NLS_CODEPAGE_737 is not set
# CONFIG_NLS_CODEPAGE_775 is not set
# CONFIG_NLS_CODEPAGE_850 is not set
# CONFIG_NLS_CODEPAGE_852 is not set
# CONFIG_NLS_CODEPAGE_855 is not set
# CONFIG_NLS_CODEPAGE_857 is not set
# CONFIG_NLS_CODEPAGE_860 is not set
# CONFIG_NLS_CODEPAGE_861 is not set
# CONFIG_NLS_CODEPAGE_862 is not set
# CONFIG_NLS_CODEPAGE_863 is not set
# CONFIG_NLS_CODEPAGE_864 is not set
# CONFIG_NLS_CODEPAGE_865 is not set
# CONFIG_NLS_CODEPAGE_866 is not set
# CONFIG_NLS_CODEPAGE_869 is not set
# CONFIG_NLS_CODEPAGE_936 is not set
# CONFIG_NLS_CODEPAGE_950 is not set
# CONFIG_NLS_CODEPAGE_932 is not set
# CONFIG_NLS_CODEPAGE_949 is not set
# CONFIG_NLS_CODEPAGE_874 is not set
# CONFIG_NLS_ISO8859_8 is not set
# CONFIG_NLS_CODEPAGE_1250 is not set
# CONFIG_NLS_CODEPAGE_1251 is not set
# CONFIG_NLS_ASCII is not set
# CONFIG_NLS_ISO8859_1 is not set
# CONFIG_NLS_ISO8859_2 is not set
# CONFIG_NLS_ISO8859_3 is not set
# CONFIG_NLS_ISO8859_4 is not set
# CONFIG_NLS_ISO8859_5 is not set
# CONFIG_NLS_ISO8859_6 is not set
# CONFIG_NLS_ISO8859_7 is not set
# CONFIG_NLS_ISO8859_9 is not set
# CONFIG_NLS_ISO8859_13 is not set
# CONFIG_NLS_ISO8859_14 is not set
# CONFIG_NLS_ISO8859_15 is not set
# CONFIG_NLS_KOI8_R is not set
# CONFIG_NLS_KOI8_U is not set
# CONFIG_NLS_UTF8 is not set

#
# Graphics support
#
CONFIG_FB=m
# CONFIG_FB_CFB_FILLRECT is not set
# CONFIG_FB_CFB_COPYAREA is not set
# CONFIG_FB_CFB_IMAGEBLIT is not set
# CONFIG_FB_SOFT_CURSOR is not set
# CONFIG_FB_MACMODES is not set
# CONFIG_FB_MODE_HELPERS is not set
# CONFIG_FB_TILEBLITTING is not set
# CONFIG_FB_BFIN_7171 is not set
# CONFIG_FB_S1D13XXX is not set
# CONFIG_FB_VIRTUAL is not set

#
# Logo configuration
#
# CONFIG_LOGO is not set
# CONFIG_BACKLIGHT_LCD_SUPPORT is not set

#
# Sound
#
CONFIG_SOUND=m

#
# Advanced Linux Sound Architecture
#
CONFIG_SND=m
CONFIG_SND_TIMER=m
CONFIG_SND_PCM=m
# CONFIG_SND_SEQUENCER is not set
CONFIG_SND_OSSEMUL=y
CONFIG_SND_MIXER_OSS=m
CONFIG_SND_PCM_OSS=m
# CONFIG_SND_VERBOSE_PRINTK is not set
# CONFIG_SND_DEBUG is not set

#
# Generic devices
#
# CONFIG_SND_DUMMY is not set
# CONFIG_SND_MTPAV is not set
# CONFIG_SND_SERIAL_U16550 is not set
# CONFIG_SND_MPU401 is not set

#
# ALSA Blackfin devices
#
CONFIG_SND_BLACKFIN_ADI1836=m
CONFIG_SND_BLACKFIN_ADI1836_TDM=y
# CONFIG_SND_BLACKFIN_ADI1836_I2S is not set
# CONFIG_SND_BLACKFIN_ADI1836_MULSUB is not set
CONFIG_SND_BLACKFIN_ADI1836_5P1=y
CONFIG_SND_BLACKFIN_SPORT=0
CONFIG_SND_BLACKFIN_SPI_PFBIT=4

#
# Open Sound System
#
# CONFIG_SOUND_PRIME is not set

#
# USB support
#
# CONFIG_USB_ARCH_HAS_HCD is not set
# CONFIG_USB_ARCH_HAS_OHCI is not set

#
# USB Gadget Support
#
# CONFIG_USB_GADGET is not set

#
# Profiling support
#
# CONFIG_PROFILING is not set

#
# Kernel hacking
#
# CONFIG_DEBUG_INFO is not set
# CONFIG_DEBUG_KERNEL is not set
# CONFIG_DEBUG_HWERR is not set
# CONFIG_FRAME_POINTER is not set
# CONFIG_MAGIC_SYSRQ is not set
# CONFIG_BOOTPARAM is not set
# CONFIG_NO_KERNEL_MSG is not set
CONFIG_CPLB_INFO=y

#
# Security options
#
# CONFIG_KEYS is not set
CONFIG_SECURITY=y
# CONFIG_SECURITY_NETWORK is not set
CONFIG_SECURITY_CAPABILITIES=y
# CONFIG_SECURITY_SECLVL is not set
# CONFIG_SECURITY_SELINUX is not set

#
# Cryptographic options
#
# CONFIG_CRYPTO is not set

#
# Hardware crypto devices
#

#
# Library routines
#
# CONFIG_CRC_CCITT is not set
CONFIG_CRC32=y
# CONFIG_LIBCRC32C is not set
CONFIG_ZLIB_INFLATE=m
CONFIG_ZLIB_DEFLATE=m
