#
# Automatically generated make config: don't edit
# Linux kernel version: 2.6.12.1
# Fri Nov 18 10:24:26 2005
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
# CONFIG_CLEAN_COMPILE is not set
CONFIG_BROKEN=y
CONFIG_BROKEN_ON_SMP=y
CONFIG_INIT_ENV_ARG_LIMIT=32

#
# General setup
#
CONFIG_LOCALVERSION=""
CONFIG_BSD_PROCESS_ACCT=y
# CONFIG_BSD_PROCESS_ACCT_V3 is not set
CONFIG_SYSCTL=y
# CONFIG_AUDIT is not set
CONFIG_LOG_BUF_SHIFT=14
CONFIG_GENERIC_CALIBRATE_DELAY=y
# CONFIG_HOTPLUG is not set
# CONFIG_IKCONFIG is not set
CONFIG_EMBEDDED=y
# CONFIG_KALLSYMS is not set
CONFIG_PRINTK=y
CONFIG_BUG=y
CONFIG_BASE_FULL=y
# CONFIG_FUTEX is not set
# CONFIG_EPOLL is not set
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
# CONFIG_MODULE_UNLOAD is not set
CONFIG_OBSOLETE_MODPARM=y
# CONFIG_MODVERSIONS is not set
# CONFIG_MODULE_SRCVERSION_ALL is not set
# CONFIG_KMOD is not set

#
# Blackfin Processor Options
#

#
# Processor and Board Settings
#
# CONFIG_BF533 is not set
# CONFIG_BF532 is not set
# CONFIG_BF531 is not set
# CONFIG_BF534 is not set
# CONFIG_BF535 is not set
# CONFIG_BF536 is not set
# CONFIG_BF537 is not set
CONFIG_BF561=y
CONFIG_BLACKFIN=y
CONFIG_BFIN_DUAL_CORE=y
# CONFIG_BFIN533_EZKIT is not set
# CONFIG_BFIN533_STAMP is not set
# CONFIG_BFIN537_STAMP is not set
# CONFIG_BFIN533_BLUETECHNIX_CM is not set
CONFIG_BFIN561_EZKIT=y
# CONFIG_GENERIC_BOARD is not set
CONFIG_MEM_MT48LC16M16A2TG_75=y

#
# BF561 Specific Configuration
#

#
# Interrupt Priority Assignment
#

#
# Priority
#
CONFIG_IRQ_PLL_WAKEUP=7
CONFIG_IRQ_DMA1_ERROR=7
CONFIG_IRQ_DMA2_ERROR=7
CONFIG_IRQ_IMDMA_ERROR=7
CONFIG_IRQ_PPI0_ERROR=7
CONFIG_IRQ_PPI1_ERROR=7
CONFIG_IRQ_SPORT0_ERROR=7
CONFIG_IRQ_SPORT1_ERROR=7
CONFIG_IRQ_SPI_ERROR=7
CONFIG_IRQ_UART_ERROR=7
CONFIG_IRQ_RESERVED_ERROR=7
CONFIG_IRQ_DMA1_0=8
CONFIG_IRQ_DMA1_1=8
CONFIG_IRQ_DMA1_2=8
CONFIG_IRQ_DMA1_3=8
CONFIG_IRQ_DMA1_4=8
CONFIG_IRQ_DMA1_5=8
CONFIG_IRQ_DMA1_6=8
CONFIG_IRQ_DMA1_7=8
CONFIG_IRQ_DMA1_8=8
CONFIG_IRQ_DMA1_9=8
CONFIG_IRQ_DMA1_10=8
CONFIG_IRQ_DMA1_11=8
CONFIG_IRQ_DMA2_0=9
CONFIG_IRQ_DMA2_1=9
CONFIG_IRQ_DMA2_2=9
CONFIG_IRQ_DMA2_3=9
CONFIG_IRQ_DMA2_4=9
CONFIG_IRQ_DMA2_5=9
CONFIG_IRQ_DMA2_6=9
CONFIG_IRQ_DMA2_7=9
CONFIG_IRQ_DMA2_8=9
CONFIG_IRQ_DMA2_9=9
CONFIG_IRQ_DMA2_10=9
CONFIG_IRQ_DMA2_11=9
CONFIG_IRQ_TIMER0=10
CONFIG_IRQ_TIMER1=10
CONFIG_IRQ_TIMER2=10
CONFIG_IRQ_TIMER3=10
CONFIG_IRQ_TIMER4=10
CONFIG_IRQ_TIMER5=10
CONFIG_IRQ_TIMER6=10
CONFIG_IRQ_TIMER7=10
CONFIG_IRQ_TIMER8=10
CONFIG_IRQ_TIMER9=10
CONFIG_IRQ_TIMER10=10
CONFIG_IRQ_TIMER11=10
CONFIG_IRQ_PROG0_INTA=11
CONFIG_IRQ_PROG0_INTB=11
CONFIG_IRQ_PROG1_INTA=11
CONFIG_IRQ_PROG1_INTB=11
CONFIG_IRQ_PROG2_INTA=11
CONFIG_IRQ_PROG2_INTB=11
CONFIG_IRQ_DMA1_WRRD0=8
CONFIG_IRQ_DMA1_WRRD1=8
CONFIG_IRQ_DMA2_WRRD0=9
CONFIG_IRQ_DMA2_WRRD1=9
CONFIG_IRQ_IMDMA_WRRD0=12
CONFIG_IRQ_IMDMA_WRRD1=12
CONFIG_IRQ_WDTIMER=13

#
# Board specific issues
#

#
# Board Setup
#
CONFIG_CLKIN_HZ=30000000
CONFIG_MEM_SIZE=64
CONFIG_MEM_ADD_WIDTH=9

#
# LED Status Indicators
#

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
# CONFIG_LARGE_ALLOCS is not set
CONFIG_IRQCHIP_DEMUX_GPIO=y

#
# DMA Support
#
# CONFIG_NO_DMA is not set
CONFIG_BLKFIN_SIMPLE_DMA=y

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

#
# VCO Multiplier
#
CONFIG_VCO_MULT=20

#
# Core Clock Divider
#
CONFIG_CCLK_DIV=1

#
# System Clock Divider
#
CONFIG_SCLK_DIV=5

#
# Half clockin
#
# CONFIG_CLKIN_HALF is not set

#
# Bypass PLL
#
# CONFIG_PLL_BYPASS is not set

#
# Asynchonous Memory Configuration
#

#
# EBIU_AMBCTL Global Control
#
CONFIG_C_AMCKEN=y
# CONFIG_C_CDPRIO is not set
CONFIG_C_B0PEN=y
CONFIG_C_B1PEN=y
CONFIG_C_B2PEN=y
# CONFIG_C_B3PEN is not set
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
CONFIG_BINFMT_ZFLAT=y
# CONFIG_BINFMT_SHARED_FLAT is not set
# CONFIG_BINFMT_MISC is not set

#
# Power management options
#
# CONFIG_PM is not set

#
# Generic Driver Options
#
# CONFIG_STANDALONE is not set
CONFIG_PREVENT_FIRMWARE_BUILD=y
# CONFIG_FW_LOADER is not set

#
# Memory Technology Devices (MTD)
#
# CONFIG_MTD is not set

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
CONFIG_BLK_DEV_RAM=y
CONFIG_BLK_DEV_RAM_COUNT=16
CONFIG_BLK_DEV_RAM_SIZE=4096
CONFIG_BLK_DEV_INITRD=y
CONFIG_INITRAMFS_SOURCE=""
# CONFIG_CDROM_PKTCDVD is not set

#
# IO Schedulers
#
CONFIG_IOSCHED_NOOP=y
CONFIG_IOSCHED_AS=y
# CONFIG_IOSCHED_DEADLINE is not set
CONFIG_IOSCHED_CFQ=y

#
# ATA/ATAPI/MFM/RLL support
#
# CONFIG_IDE is not set

#
# IDE Extra configuration
#

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
# CONFIG_IEEE1394 is not set

#
# I2O device support
#

#
# Networking support
#
# CONFIG_NET is not set
# CONFIG_NETPOLL is not set
# CONFIG_NET_POLL_CONTROLLER is not set

#
# ISDN subsystem
#

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
# CONFIG_SPIDMA_BF53x is not set
# CONFIG_SPI_ADC_BF533 is not set
# CONFIG_BF533_PFLAGS is not set
# CONFIG_BF5xx_PPIFCD is not set
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
# CONFIG_BLACKFIN_RTC is not set
# CONFIG_BLACKFIN_DPMC is not set
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

#
# File systems
#
# CONFIG_EXT2_FS is not set
# CONFIG_EXT3_FS is not set
# CONFIG_JBD is not set
# CONFIG_REISERFS_FS is not set
# CONFIG_JFS_FS is not set

#
# XFS support
#
# CONFIG_XFS_FS is not set
# CONFIG_MINIX_FS is not set
CONFIG_ROMFS_FS=y
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
# CONFIG_HUGETLBFS is not set
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
# CONFIG_CRAMFS is not set
# CONFIG_VXFS_FS is not set
# CONFIG_HPFS_FS is not set
# CONFIG_QNX4FS_FS is not set
# CONFIG_SYSV_FS is not set
# CONFIG_UFS_FS is not set

#
# Partition Types
#
# CONFIG_PARTITION_ADVANCED is not set
CONFIG_MSDOS_PARTITION=y

#
# Native Language Support
#
# CONFIG_NLS is not set

#
# Graphics support
#
# CONFIG_FB is not set

#
# Sound
#
# CONFIG_SOUND is not set

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
CONFIG_DEBUG_INFO=y
# CONFIG_DEBUG_KERNEL is not set
# CONFIG_DEBUG_HWERR is not set
# CONFIG_FRAME_POINTER is not set
# CONFIG_MAGIC_SYSRQ is not set
# CONFIG_BOOTPARAM is not set
# CONFIG_NO_KERNEL_MSG is not set
# CONFIG_CPLB_INFO is not set

#
# Security options
#
# CONFIG_KEYS is not set
# CONFIG_SECURITY is not set

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
# CONFIG_CRC32 is not set
# CONFIG_LIBCRC32C is not set
CONFIG_ZLIB_INFLATE=y
