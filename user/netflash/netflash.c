/****************************************************************************/

/*
 * netflash.c:  network FLASH loader.
 *
 * Copyright (C) 1999-2001,  Greg Ungerer (gerg@snapgear.com)
 * Copyright (C) 2000-2001,  Lineo (www.lineo.com)
 * Copyright (C) 2000-2002,  SnapGear (www.snapgear.com)
 *
 * Copied and hacked from rootloader.c which was:
 *
 * Copyright (C) 1998  Kenneth Albanowski <kjahds@kjahds.com>,
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/****************************************************************************/

#define __USE_GNU 1
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <assert.h>
#include <byteswap.h>
#include <ctype.h>
#include <getopt.h>
#include <errno.h>
#include <unistd.h>
#include <dirent.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/termios.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <stdarg.h>

#include <linux/autoconf.h>
#include <linux/version.h>
#include <config/autoconf.h>
#include <linux/major.h>
#ifdef CONFIG_USER_NETFLASH_CRYPTO
#include <openssl/bio.h>
#include "crypto.h"
#endif
#if defined(CONFIG_USER_NETFLASH_SHA256) || defined(CONFIG_USER_NETFLASH_CRYPTO_V2)
#include <openssl/sha.h>
#endif
#if defined(CONFIG_MTD) || defined(CONFIG_MTD_MODULES)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,8)
#include <mtd/mtd-user.h>
#define MTD_CHAR_MAJOR 90
#define MTD_BLOCK_MAJOR 31
#else 
#include <linux/mtd/mtd.h>
#endif
#elif defined(CONFIG_BLK_DEV_BLKMEM)
#include <linux/blkmem.h>
#endif
#ifdef CONFIG_LEDMAN
#include <linux/ledman.h>
#endif
#ifdef CONFIG_USER_NETFLASH_DECOMPRESS
#include <zlib.h>
#endif
#if defined(CONFIG_MTD) || defined(CONFIG_MTD_MODULES)
#include <linux/jffs2.h>
#endif
#if defined(CONFIG_NFTL_RW) && !defined(NFTL_MAJOR)
 #define NFTL_MAJOR 93
#endif
#ifdef CONFIG_IDE
#include <linux/hdreg.h>
#endif
#include <asm/byteorder.h>

#include "fileblock.h"
#include "exit_codes.h"
#include "versioning.h"
#include "netflash.h"

/****************************************************************************/

#ifdef CONFIG_USER_NETFLASH_HMACMD5
#include "hmacmd5.h"
#define HMACMD5_OPTIONS "m:"
#else
#define HMACMD5_OPTIONS
#endif

#ifdef CONFIG_USER_NETFLASH_DECOMPRESS
#define DECOMPRESS_OPTIONS "z"
#else
#define DECOMPRESS_OPTIONS
#endif

#ifdef CONFIG_USER_NETFLASH_SETSRC
#define SETSRC_OPTIONS "I:"
#else
#define SETSRC_OPTIONS
#endif

#ifdef CONFIG_USER_NETFLASH_SHA256
#define	SHA256_OPTIONS "N"
#else
#define	SHA256_OPTIONS
#endif

#define CMD_LINE_OPTIONS "abc:Cd:efFhiHjkKlno:pr:R:sStuv?" DECOMPRESS_OPTIONS HMACMD5_OPTIONS SETSRC_OPTIONS SHA256_OPTIONS

#define PID_DIR "/var/run"
#define DHCPCD_PID_FILE "dhcpcd-"

#define CHECKSUM_LENGTH	4

#ifdef CONFIG_USER_BUSYBOX_WATCHDOGD
#define CONFIG_USER_NETFLASH_WATCHDOG 1
#endif

#define NUM_BLOCKS_TO_KEEP	20
/****************************************************************************/

char *version = "2.2.0";

int exitstatus = 0;

unsigned long image_length = 0;
unsigned int calc_checksum = 0;

int dothrow = 0;		/* Check version info of image; no program */
int dolock, dounlock;		/* do we lock/unlock segments as we go */
int checkimage;			/* Compare with current flash contents */
int checkblank;			/* Do not erase if already blank */
unsigned char *check_buf = NULL;
#if CONFIG_USER_NETFLASH_WATCHDOG
int watchdog = 1;		/* tickle watchdog while writing to flash */
int watchdog_fd = -1;   	/* ensure this is initalised to an invalid fd */
#endif
int preserveconfig;		/* Preserve special bits of flash such as config fs */
int preserve = 0;		/* Preserve and portions of flash not written to */
int offset = 0;			/* Offset to start writing at */
int stop_early = 0;		/* stop at end of input data, do not write full dev. */
int nostop_early = 0;		/* no stop at end of input data, do write full dev. */
int dojffs2;			/* Write the jffs2 magic to unused segments */
#ifdef CONFIG_USER_NETFLASH_DECOMPRESS
int doinflate;			/* Decompress the image */
#endif
int docgi = 0;			/* Read options and data from stdin in mime multipart format */
int dofilesave = 0;		/* Save locally as file, not a flash device */
int dofileautoname = 0;		/* Put file in right directory automatically */
int dobootcfg = 0;		/* Update boot.cfg file to boot image */

#if defined(CONFIG_USER_NETFLASH_WITH_CGI) && !defined(RECOVER_PROGRAM)
char cgi_data[64];      /* CGI section name for the image part */
char cgi_options[64];   /* CGI section name for the command line options part */
char cgi_flash_region[20]; /* CGI section name for the flash region part */
extern size_t cgi_load(const char *data_name, const char *options_name, char options[64], const char *flash_region_name, char flash_region[20], int *error_code);
#endif

extern int tftpverbose;
extern int ftpverbose;

FILE	*nfd;

#ifdef CONFIG_USER_NETFLASH_DECOMPRESS
z_stream z;
unsigned long zoffset;
#endif

struct stat stat_rdev;

#ifdef CONFIG_USER_NETFLASH_SETSRC
char	*srcaddr = NULL;
#endif

#ifdef CONFIG_USER_NETFLASH_CRYPTO
#ifdef CONFIG_USER_NETFLASH_CRYPTO_V2
SHA256_CTX sha_ctx;
#else
MD5_CTX md5_ctx;
#endif

/* Used if the -t option is in effect to calculate the hash as blocks are received */
static unsigned long crypto_hash_total;
static int crypto_hash_init;
#endif

static void (* program_segment)(int rd, unsigned char *sgdata,
		int sgpos, int sglength, int sgsize);

static void exit_failed(int rc);

/****************************************************************************/

#define notice(a...) fprintf(stdout, "netflash: " a); fprintf(stdout, "\n"); fflush(stdout);
#if defined(CONFIG_USER_NETFLASH_WITH_CGI) && !defined(RECOVER_PROGRAM)
#define error(a...) fprintf(stdout, "netflash: " a); fprintf(stdout, "\n"); fflush(stdout);
#else
#define error(a...) fprintf(stderr, "netflash: " a); fprintf(stderr, "\n"); fflush(stderr);
#endif

/****************************************************************************/

void restartinit(void)
{
#if !defined(CONFIG_USER_NETFLASH_WITH_CGI) || defined(RECOVER_PROGRAM)
	error("restarting init process...");
#endif
	if (!docgi) {
		/* Only restart init if we're not being run from the CGI */
		kill(1, SIGCONT);
	} else {
#ifdef CONFIG_PROP_ACLD_ACLD
		/* After we read in all of the POST request from the browser,
		 * the cgix/netflash wrapper program will send either a response 
		 * indicating success or failure. This page will probably contain 
		 * references to image/logo or stylesheet URLs, which means that 
		 * the browser *could* send another GET request on a new TCP connection.
		 * 
		 * Because of all this, we need to have acld running so that the 
		 * browser can authenticate.
		 *
		 * We are about to restart, so don't care about trying to read options 
		 * etc from the inittab entry, we just need it to run for the next few 
		 * seconds.
		 */
		system("/bin/acld &");
#endif
	}
#ifdef CONFIG_USER_NETFLASH_WATCHDOG
	close(watchdog_fd);
	system("watchdog /dev/watchdog");
#endif
}


void update_chksum(unsigned char *data, int length)
{
	while (length > 0) {
		calc_checksum += *data++;
		length--;
	}
}

/*
 *	Generate a checksum over the data.
 */
void chksum()
{
	uint32_t file_checksum;
	void *p;

	if (fb_seek_end(sizeof(file_checksum)) != 0) {
		error("image is too short to contain a checksum");
		exit_failed(IMAGE_SHORT);
	}

	fb_read(&file_checksum, sizeof(file_checksum));
	fb_trim(sizeof(file_checksum));
	file_checksum = ntohl(file_checksum);

	for (p = &file_checksum; p < (void *)(&file_checksum + 1); p++)
		calc_checksum -= *(unsigned char *)p;

	calc_checksum = (calc_checksum & 0xffff) + (calc_checksum >> 16);
	calc_checksum = (calc_checksum & 0xffff) + (calc_checksum >> 16);

	if (calc_checksum != file_checksum) {
		error("bad image checksum=0x%04x, expected checksum=0x%04x",
			calc_checksum, file_checksum);
		exit_failed(BAD_CHECKSUM);
	}
}

#ifdef CONFIG_USER_NETFLASH_HMACMD5
int check_hmac_md5(char *key)
{
	HMACMD5_CTX ctx;
	unsigned char hash[16];
	unsigned char fb_hash[16];

	if (fb_seek_end(16) == 0) {
		fb_read(fb_hash, 16);
		fb_trim(16);

		HMACMD5Init(&ctx, key, strlen(key));
		fb_seek_set(0);
		while ((data = fb_read_block(&length)) != NULL)
			HMACMD5Update(&ctx, data, length);
		HMACMD5Final(hash, &ctx);

		if (memcmp(hash, fb_hash, 16) != 0) {
			error("bad HMAC MD5 signature");
			exit_failed(BAD_HMAC_SIG);
		}

		notice("HMAC MD5 signature ok");
	}
}
#endif

#ifdef CONFIG_USER_NETFLASH_SHA256

int dosha256sum = 1;

int check_sha256_sum(void)
{
	SHA256_CTX ctx;
	unsigned char hash[32];
	unsigned char fb_hash[32];
	unsigned long hash_length, fblength, length, total = 0;

	if (fb_seek_end(32) == 0) {
		hash_length = fb_tell();
		fb_read(fb_hash, 32);

		SHA256_Init(&ctx);
		fb_seek_set(0);
		while ((data = fb_read_block(&fblength)) != NULL) {
			length = fblength;
			if (length > (hash_length - total)) {
				length = hash_length - total;
			}
			SHA256_Update(&ctx, data, length);
			if (length != fblength)
				break;
			total += length;
		}
		SHA256_Final(hash, &ctx);

		if (memcmp(hash, fb_hash, 32) != 0) {
			error("bad SHA256 digest");
			exit_failed(BAD_HMAC_SIG);
		}

		notice("SHA256 digest ok");
	}

	return 0;
}
#endif

#ifdef CONFIG_USER_NETFLASH_CRYPTO
#if 0
static void hexdump(unsigned char *p, unsigned int len)
{
	unsigned int i;
	for (i = 0; (i < len); i++) {
		if ((i % 16) == 0) printf("%08x:  ", p+i);
		printf("%02x ", p[i]);
		if (((i+1) % 16) == 0) printf("\n");
	}
	if ((i % 16) != 0) printf("\n");
}
#endif

int load_public_key(RSA **pkey)
{
	/* Load public key */
	BIO *in;
	struct stat st;

	if (stat(PUBLIC_KEY_FILE, &st) == -1 && errno == ENOENT) {
		printf("WARNING: no public key file found, %s\n",
			PUBLIC_KEY_FILE);
		return 0;
	}
	in = BIO_new(BIO_s_file());
	if (in == NULL) {
		error("cannot allocate a bio structure");
		exit_failed(BAD_DECRYPT);
	}
	if (BIO_read_filename(in, PUBLIC_KEY_FILE) <= 0) {
		error("cannot open public key file");
		exit_failed(BAD_PUB_KEY);
	}
	*pkey = PEM_read_bio_RSA_PUBKEY(in, NULL, NULL, NULL);
	if (*pkey == NULL) {
		error("cannot read public key");
		exit_failed(BAD_PUB_KEY);
	}
	return 1;
}

int decode_header_info(struct header *hdr, RSA *pkey, int *img_len)
{
	struct little_header lhdr;

	/* Decode header information */
	if (fb_seek_end(sizeof(lhdr)) != 0) {
		error("image not cryptographically enabled");
		exit_failed(NO_CRYPT);
	}
	fb_read(&lhdr, sizeof(lhdr));
	if (lhdr.magic != htons(LITTLE_CRYPTO_MAGIC)) {
#ifdef CONFIG_USER_NETFLASH_CRYPTO_OPTIONAL
		return 0;
#else
		error("size magic incorrect");
		exit_failed(BAD_CRYPT_MAGIC);
#endif
	}
	{
		unsigned short hlen = ntohs(lhdr.hlen);
		unsigned char tmp[hlen];
		unsigned char t2[hlen];
		int len;

		if (fb_seek_end(sizeof(lhdr) + hlen) != 0) {
			error("crypt header length invalid");
			exit_failed(BAD_CRYPT_LEN);
		}
		fb_read(tmp, hlen);
#ifdef CONFIG_USER_NETFLASH_CRYPTO_V2
		*img_len = fb_len() - sizeof(lhdr) - hlen;
#else
		fb_trim(sizeof(lhdr) + hlen);
		*img_len = fb_len();
#endif
		len = RSA_public_decrypt(hlen, tmp, t2,
				pkey, RSA_PKCS1_PADDING);
		if (len == -1) {
			error("decrypt failed");
			exit_failed(BAD_DECRYPT);
		}
		if (len != sizeof(struct header)) {
			error("length mismatch %d %d\n", (int)sizeof(struct header), len);
		}
		memcpy(hdr, t2, sizeof(struct header));
	}
	if (hdr->magic != htonl(CRYPTO_MAGIC)) {
		error("image not cryptographically enabled");
		exit_failed(NO_CRYPT);
	}
	return 1;
}

void update_crypto_hash(unsigned char *data, unsigned long length)
{
	if (!crypto_hash_init) {
		crypto_hash_init = 1;
#ifdef CONFIG_USER_NETFLASH_CRYPTO_V2
		SHA256_Init(&sha_ctx);
#else
		MD5_Init(&md5_ctx);
#endif
	}

#ifdef CONFIG_USER_NETFLASH_CRYPTO_V2
	SHA256_Update(&sha_ctx, data, length);
#else
	MD5_Update(&md5_ctx, data, length);
#endif
	crypto_hash_total += length;
}

/*
 *	Check the crypto signature on the image...
 *	This always includes a public key encrypted header and an MD5
 *	(or SHA256) checksum. It optionally includes AES encryption of
 *	the image.
 */
void check_crypto_signature(void)
{
	struct header hdr;
	int hash_length;
	unsigned long fblength, length;
	unsigned char *data;
  	RSA *pkey;
#ifdef CONFIG_USER_NETFLASH_CRYPTO_V2
	unsigned char hash[SHA256_DIGEST_LENGTH];
#else
	unsigned char hash[MD5_DIGEST_LENGTH];
#endif

	if (!load_public_key(&pkey))
		return;
	if (!decode_header_info(&hdr, pkey, &hash_length))
		return;
	RSA_free(pkey);

	/* Decrypt image if needed */
	if (hdr.flags & FLAG_ENCRYPTED) {
		unsigned char cin[AES_BLOCK_SIZE];
		unsigned char cout[AES_BLOCK_SIZE];
		unsigned long s;
		AES_KEY key;

		if (dothrow) {
			error("Can not decrypt encrypted image when -t option is used.");
			exit_failed(BAD_CRYPT);
			return;
		}

		if ((hash_length % AES_BLOCK_SIZE) != 0) {
			error("image size not miscable with cryptography");
			exit_failed(BAD_CRYPT);
		}
		AES_set_decrypt_key(hdr.aeskey, AESKEYSIZE * 8, &key);
		/* Convert the body of the file */
		fb_seek_set(0);
		for (s = 0; s < hash_length; s += AES_BLOCK_SIZE) {
			fb_peek(cin, AES_BLOCK_SIZE);
			AES_decrypt(cin, cout, &key);
			fb_write(cout, AES_BLOCK_SIZE);
		}
	}

#ifndef CONFIG_USER_NETFLASH_CRYPTO_V2
	/* Remove padding */
	if (hdr.padsize)
		fb_trim(hdr.padsize);
#endif

	if (dothrow && crypto_hash_init) {
		if (crypto_hash_total > hash_length) {
			error("hashed too much, try without -t");
			exit_failed(BAD_MD5_SIG);
		}
		fb_seek_set(crypto_hash_total);
	} else {
#ifdef CONFIG_USER_NETFLASH_CRYPTO_V2
		SHA256_Init(&sha_ctx);
#else
		MD5_Init(&md5_ctx);
#endif
		fb_seek_set(0);
	}

	while ((data = fb_read_block(&fblength)) != NULL) {
		length = fblength;
		if (length > (hash_length - crypto_hash_total)) {
			length = hash_length - crypto_hash_total;
		}
#ifdef CONFIG_USER_NETFLASH_CRYPTO_V2
		SHA256_Update(&sha_ctx, data, length);
#else
		MD5_Update(&md5_ctx, data, length);
#endif
		if (length != fblength)
			break;
		crypto_hash_total += length;
	}

#ifdef CONFIG_USER_NETFLASH_CRYPTO_V2
	SHA256_Final(hash, &sha_ctx);
	if (memcmp(hdr.hash, hash, SHA256_DIGEST_LENGTH) != 0) {
		error("bad SHA256 signature");
		exit_failed(BAD_MD5_SIG);
	}
#else
	MD5_Final(hash, &md5_ctx);
	if (memcmp(hdr.md5, hash, MD5_DIGEST_LENGTH) != 0) {
		error("bad MD5 signature");
		exit_failed(BAD_MD5_SIG);
	}
#endif

	notice("signed image approved");
}
#endif


#ifdef CONFIG_USER_NETFLASH_DECOMPRESS
void decompress_skip_bytes(unsigned long len)
{
	if (fb_len() - fb_tell() < len) {
		error("compressed image is too short");
		exit_failed(IMAGE_SHORT);
	}
	fb_seek_inc(len);
}

void decompress_read(void *p, int len)
{
	if (fb_len() - fb_tell() < len) {
		error("compressed image is too short");
		exit_failed(IMAGE_SHORT);
	}
	fb_read(p, len);
}

unsigned long decompress_init(void)
{
	uint8_t method, flg, c;
	uint16_t xlen;
	uint32_t size;
	unsigned long length;

	fb_seek_set(0);

    /* Skip over gzip header */
	decompress_skip_bytes(2);

	decompress_read(&method, 1);
	if (method != 8) {
		error("image is compressed, unknown compression method");
		exit_failed(UNKNOWN_COMP);
    }

	decompress_read(&flg, 1);

    /* Skip mod time, extended flag, and os */
	decompress_skip_bytes(6);

    /* Skip extra field */
    if (flg & 0x04) {
		decompress_read(&xlen, 2);
		xlen = ntohs(bswap_16(xlen));
    }
	
    /* Skip file name */
    if (flg & 0x08) {
		do {
			decompress_read(&c, 1);
		} while (c);
    }
	
    /* Skip comment */
    if (flg & 0x10) {
		do {
			decompress_read(&c, 1);
		} while (c);
    }
	
    /* Skip CRC */
    if (flg & 0x02) {
		decompress_skip_bytes(2);
    }
	
	z.next_in = fb_read_block(&length);
	if (!z.next_in) {
		error("unexpected end of file for decompression");
		exit_failed(BAD_DECOMP);
	}
	z.avail_in = length;
    z.zalloc = Z_NULL;
    z.zfree = Z_NULL;
    z.opaque = Z_NULL;
	zoffset = fb_tell();
    if (inflateInit2(&z, -MAX_WBITS) != Z_OK) {
		error("image is compressed, decompression failed");
		exit_failed(BAD_DECOMP);
    }
    
	if (fb_len() - fb_tell() >= 4) {
		fb_seek_end(4);
		fb_read(&size, 4);
		size = ntohl(bswap_32(size));
	} else {
		size = 0;
	}
    if (size <= 0) {
		error("image is compressed, decompressed length is invalid");
		exit_failed(BAD_DECOMP);
    }

    return size;
}


int decompress(void *data, int length)
{
	unsigned long fblength;
    int rc;

    z.next_out = data;
    z.avail_out = length;

	fb_seek_set(zoffset);
    for (;;) {
		z.next_in = fb_read_block(&fblength);
		if (!z.next_in) {
			error("unexpected end of file for decompression");
			exit_failed(BAD_DECOMP);
		}
		z.avail_in = fblength;
		zoffset = fb_tell();

		rc = inflate(&z, Z_SYNC_FLUSH);
		if (rc == Z_OK) {
			if (z.avail_out == 0)
				return length;
			
			if (z.avail_in != 0) {
				/* Note: This shouldn't happen, but if it does then
				 * need to add code to add another level of buffering
				 * that we append file blocks to...
				 */
				error("decompression deadlock");
				exit_failed(BAD_DECOMP);
			}
		}
		else if (rc == Z_STREAM_END) {
			return length - z.avail_out;
		}
		else {
			error("error during decompression: %x", rc);
			exit_failed(BAD_DECOMP);
		}
    }
}

int check_decompression(int doinflate)
{
	int checkinflate;
	int gotinflate = 0;

#ifdef CONFIG_USER_NETFLASH_AUTODECOMPRESS
	checkinflate = 1;
#else
	checkinflate = doinflate;
#endif

	if (checkinflate && fb_len() > 2) {
		uint8_t gz_magic[2] = {0x1f, 0x8b}; /* gzip magic header */
		uint8_t header[2];

		fb_seek_set(0);
		fb_read(header, 2);
		if (memcmp(header, gz_magic, 2) == 0) {
			gotinflate = 1;
			image_length = decompress_init();
			notice("image is compressed, decompressed length=%ld\n",
					image_length);
		} else {
			image_length = fb_len();
			notice("image is not compressed");
		}
	}
	else {
		image_length = fb_len();
	}

	return gotinflate;
}
#endif

/****************************************************************************/

/*
 *	Local copies of the open/close/write used by tftp loader.
 *	The idea is that we get tftp to do all the work of getting
 *	the file over the network. The following code back ends
 *	that process, preparing the read data for FLASH programming.
 */
int local_creat(char *name, int flags)
{
	return(fileno(nfd));
}

FILE *local_fdopen(int fd, char *flags)
{
	return(nfd);
}

FILE *local_fopen(const char *name, const char *flags)
{
	return(nfd);
}

int local_fclose(FILE *fp)
{
	printf("\n");
	fflush(stdout);
	sleep(1);
	return(0);
}

int local_fseek(FILE *fp, int offset, int whence)
{
	/* Shouldn't happen... */
	return(0);
}

int local_putc(int ch, FILE *fp)
{
	/* Shouldn't happen... */
	return(0);
}

static void local_throw(void *buf, unsigned long count)
{
#ifdef CONFIG_USER_NETFLASH_CRYPTO
	update_crypto_hash(buf, count);
#endif
}

int local_write(int fd, void *buf, int count)
{
#ifdef CONFIG_USER_NETFLASH_WATCHDOG
	if (watchdog_fd >= 0)
		write(watchdog_fd, "\0", 1); 
#endif

	if (!docgi) {
		static unsigned long total = 0;
		static unsigned lastk = 0;

		total += count;
		if (total / 1024 != lastk) {
			lastk = total / 1024;
			printf("\r%dK", lastk); fflush(stdout);
		}
	}

	update_chksum(buf, count);
	if (dothrow)
		fb_throw(1024, local_throw);
	if (fb_write(buf, count) != 0) {
		error("Insufficient memory for image!");
		exit_failed(NO_MEMORY);
	}
	return count;
}

/****************************************************************************/
 
#include "tftp.h"

/*
 * Call to tftp. This will initialize tftp and do a get operation.
 * This will call the local_write() routine with the data that is
 * fetched, and it will create the ioctl structure.
 */
int tftpfetch(char *srvname, char *filename)
{
  char	*tftpargv[8];
  int	tftpmainargc = 0;

  tftpverbose = 0;	/* Set to 1 for tftp trace info */

  tftpargv[tftpmainargc++] = "tftp";
  tftpargv[tftpmainargc++] = srvname;
#ifdef CONFIG_USER_NETFLASH_SETSRC
  if (srcaddr != NULL)
	tftpargv[tftpmainargc++] = srcaddr;
#endif
  tftpmain(tftpmainargc, tftpargv);
  tftpsetbinary(1, tftpargv);
  
  notice("fetching file \"%s\" from %s\n", filename, srvname);
  tftpargv[0] = "get";
  tftpargv[1] = filename;
  tftpget(2, tftpargv);
  return(0);
}

/****************************************************************************/
 
extern int ftpmain(int argc, char *argv[]);
extern void setbinary(void);
extern void get(int argc, char *argv[]);
extern void quit(void);

/*
 * Call to ftp. This will initialize ftp and do a get operation.
 * This will call the local_write() routine with the data that is
 * fetched, and it will create the ioctl structure.
 */
int ftpconnect(char *srvname)
{
#ifdef FTP
  char	*ftpargv[4];

  ftpverbose = 0;	/* Set to 1 for ftp trace info */
  notice("login to remote host %s", srvname);

  ftpargv[0] = "ftp";
  ftpargv[1] = srvname;
  ftpmain(2, ftpargv);
  return(0);

#else
  error("no ftp support builtin");
  return(-1);
#endif /* FTP */
}

int ftpfetch(char *srvname, char *filename)
{
#ifdef FTP
  char	*ftpargv[4];

  ftpverbose = 0;	/* Set to 1 for ftp trace info */
  notice("ftping file \"%s\" from %s", filename, srvname);
  setbinary(); /* make sure we are in binary mode */

  ftpargv[0] = "get";
  ftpargv[1] = filename;
  get(2, ftpargv);

  quit();
  return(0);

#else
  error("no ftp support builtin");
  return(-1);
#endif /* FTP */
}

/****************************************************************************/

extern int openhttp(char *url);

/*
 *	When fetching file we need to even number of bytes in write
 *	buffers. Otherwise FLASH programming will fail. This is mostly
 *	only a problem with http for some reason.
 */

int filefetch(char *filename)
{
  int fd, i, j;
  unsigned char buf[1024];

  if (strncmp(filename, "http://", 7) == 0)
    fd = openhttp(filename);
  else
    fd = open(filename, O_RDONLY);

  if (fd < 0)
    return(-1);

  for (;;) {
    printf(".");
    if ((i = read(fd, buf, sizeof(buf))) <= 0)
      break;
    if (i & 0x1) {
	/* Read more to make even sized buffer */
	if ((j = read(fd, &buf[i], 1)) > 0)
		i += j;
    }
    local_write(-1, buf, i);
  }

  close(fd);
  printf("\n");
  return(0);
}

/****************************************************************************/

int samedev(struct stat *stat_dev, struct stat *stat_rootfs)
{
	if (S_ISBLK(stat_dev->st_mode)) {
		if (stat_dev->st_rdev == stat_rootfs->st_dev) {
			return 1;
		}
#if defined(CONFIG_NFTL_RW)
		/* Check for writing to nftla, with an nftla partition
		 * as the root device. */
		else if (major(stat_dev->st_rdev) == NFTL_MAJOR
				&& major(stat_rootfs->st_dev) == NFTL_MAJOR
				&& minor(stat_dev->st_rdev) == 0) {
			return 1;
		}
#endif
	}
#if defined(CONFIG_MTD) || defined(CONFIG_MTD_MODULES)
	/* Check for matching block/character mtd devices. */
	else if (S_ISCHR(stat_dev->st_mode)) {
		if (major(stat_dev->st_rdev) == MTD_CHAR_MAJOR
				&& major(stat_rootfs->st_dev) == MTD_BLOCK_MAJOR
				&& (minor(stat_dev->st_rdev) >> 1)
					== minor(stat_rootfs->st_dev)) {
			return 1;
		}
	}
#endif
	return 0;
}

/*
 *	Check if we are writing to the root filesystem.
 */
int flashing_rootfs(char *rdev)
{
	static struct stat stat_rootfs, stat_flash;

	/* First a generic check:
	 * is the rootfs device the same as the flash device?
	 */
	if (stat("/", &stat_rootfs) != 0) {
		error("stat(\"/\") failed (errno=%d)", errno);
		exit_failed(BAD_ROOTFS);
	}
	if (samedev(&stat_rdev, &stat_rootfs))
		return 1;

	/* Secondly, a platform specific check:
	 * /dev/flash/all and /dev/flash/image and /dev/flash/rootfs
	 * can overlap, check if we are writing to any of these, and the
	 * root device is /dev/flash/image or /dev/flash/rootfs.
	 * XXX: checking device numbers would be better than strcmp */
	else if (!strcmp(rdev, "/dev/flash/all")
			|| !strcmp(rdev, "/dev/flash/image")
			|| !strcmp(rdev, "/dev/flash/rootfs")) {
		if (stat("/dev/flash/image", &stat_flash) == 0
				&& samedev(&stat_flash, &stat_rootfs))
			return 1;
		if (stat("/dev/flash/rootfs", &stat_flash) == 0
				&& samedev(&stat_flash, &stat_rootfs))
			return 1;
	}
	return 0;
}

/****************************************************************************/

/*
 *	Search for a process and send a signal to it.
 */
int killprocname(const char *name, int signo)
{
	DIR *dir;
	struct dirent *entry;
	FILE *f;
	char path[32];
	char line[64];
	int ret = 0;

	dir = opendir("/proc");
	if (!dir)
		return 0;

	while ((entry = readdir(dir)) != NULL) {
		if (!isdigit(*entry->d_name))
			continue;

		sprintf(path, "/proc/%s/status", entry->d_name);
		if ((f = fopen(path, "r")) == NULL)
			continue;

		while (fgets(line, sizeof(line), f) != NULL) {
			if (line[strlen(line)-1] == '\n') {
				line[strlen(line)-1] = '\0';
				if (strncmp(line, "Name:\t", 6) == 0
						&& strcmp(line+6, name) == 0) {
					kill(atoi(entry->d_name), signo);
					ret = 1;
				}
			}
		}

		fclose(f);
	}
	closedir(dir);
	return ret;
}

/****************************************************************************/

/*
 *  Read a process pid file and send a signal to it.
 */
void killprocpid(char *file, int signo)
{
    FILE* f;
    pid_t pid;
	char value[16];

    f = fopen(file, "r");
    if (f == NULL)
        return;

    if (fread(value, 1, sizeof(value), f) > 0) {
		pid = atoi(value);
		if (pid)
			kill(pid, signo);
        unlink(file);
    }
    fclose(f);
}

/****************************************************************************/

/*
 *	Find the current console device. We output trace to this device
 *	if it is the controlling tty at process start.
 */
char	*consolelist[] = {
	"/dev/console",
	"/dev/ttyS0",
	"/dev/cua0",
	"/dev/ttyS1",
	"/dev/cua1",
	"/dev/ttyAM0"
};

#define	clistsize	(sizeof(consolelist) / sizeof(char *))
 
char *getconsole(void)
{
	struct stat	myst, st;
	int		i;

	if (fstat(0, &myst) < 0)
		return((char *) NULL);

	for (i = 0; (i < clistsize); i++) {
		if (!stat(consolelist[i], &st) && 
				(myst.st_rdev == st.st_rdev))
			return(consolelist[i]);
	}
	return "/dev/null";
}

/****************************************************************************/

static const char *kill_partial[] = {
#ifdef CONFIG_USER_SNORT_SNORT
	"snort",
#endif
#ifdef CONFIG_USER_SQUID_SQUID
	"squid",
#endif
#if defined(CONFIG_USER_FREESWAN) || defined(CONFIG_USER_OPENSWAN)
	"pluto",
#endif
#ifdef CONFIG_USER_CLAMAV_CLAMD
	"clamd",
#endif
#ifdef CONFIG_USER_SSH_SSHKEYGEN
	"ssh-keygen",
	"gen-keys",
#endif
#if CONFIG_PROP_HTTPSCERTGEN_HTTPSCERTGEN
	"https-certgen",
#endif
#ifdef CONFIG_PROP_STATSD_STATSD
	"statsd",
#endif
#ifdef CONFIG_USER_CRON_CRON
	"cron",
#endif
#ifdef CONFIG_PROP_NFLOGD_NFLOGD
	"nflogd",
#endif
#if defined(CONFIG_USER_DNSMASQ_DNSMASQ) || defined(CONFIG_USER_DNSMASQ2_DNSMASQ2)
	"dnsmasq",
#endif
#ifdef CONFIG_PROP_ACLD_ACLD
	"acld",
#endif
#ifdef CONFIG_USER_FLATFSD_FLATFSD
	"flatfsd",
#endif
#ifdef CONFIG_USER_BUSYBOX_BUSYBOX
	"klogd",
	"syslogd",
#endif
	NULL
};

/*
 * Kill off processes to reclaim some memory.  Only kills processes
 * that we know are unnecessary for obtaining the image.
 */
void kill_processes_partial(void)
{
	const char **p;
	int count;

	notice("killing unnecessary tasks...");
	sleep(1);

	kill(1, SIGTSTP);		/* Stop init from reforking tasks */
	atexit(restartinit);		/* If exit prematurely, restart init */
	sync();

	killprocpid("/var/run/ifmond.pid", SIGKILL);

	/* Ask them nicely. */
	count = 0;
	for (p = kill_partial; *p; p++)
		count += killprocname(*p, SIGTERM);
	if (count)
		sleep(5);		/* give em a moment... */

	/* Time for the no-nonsense approach. */
	count = 0;
	for (p = kill_partial; *p; p++)
		count += killprocname(*p, SIGKILL);
	if (count)
		sleep(2);		/* give em another moment... */
}


/*
 * Kill of processes now to reclaim some memory. Need this now so
 * we can buffer an entire firmware image...
 */
void kill_processes(char *console)
{
	int ttyfd;
	struct termios tio;
	DIR *dir;
	struct dirent *dp;
	char filename[128];

	if (console == NULL)
		console = getconsole();

	ttyfd = open(console, O_RDWR|O_NDELAY|O_NOCTTY);
	if (ttyfd >= 0) {
		if (tcgetattr(ttyfd, &tio) >= 0) {
			tio.c_cflag |= CLOCAL;
			tcsetattr(ttyfd, TCSANOW, &tio);
		}
		close(ttyfd);
	}
	if (!docgi) {
		freopen(console, "w", stdout);
		freopen(console, "w", stderr);
	}
	
	notice("killing tasks...");
	fflush(stdout);
	sleep(1);
	
	kill(1, SIGTSTP);		/* Stop init from reforking tasks */
	atexit(restartinit);		/* If exit prematurely, restart init */
	sync();

	signal(SIGTERM,SIG_IGN);	/* Don't kill ourselves... */
	setpgrp(); 			/* Don't let our parent kill us */
	sleep(1);
	signal(SIGHUP, SIG_IGN);	/* Don't die if our parent dies due to
					 * a closed controlling terminal */
	
	killprocpid("/var/run/ifmond.pid", SIGKILL);

	/*Don't take down network interfaces that use dhcpcd*/
	dir = opendir(PID_DIR);
	if (dir) {
		while ((dp = readdir(dir)) != NULL) {
			if (strncmp(dp->d_name, DHCPCD_PID_FILE,
						sizeof(DHCPCD_PID_FILE)-1) != 0)
				continue;
			if (strcmp(dp->d_name + strlen(dp->d_name) - 4,
						".pid") != 0)
				continue;
			snprintf(filename, sizeof(filename), "%s/%s",
					PID_DIR, dp->d_name);
			killprocpid(filename, SIGKILL);
		}
		closedir(dir);
	}

	kill(-1, SIGTERM);		/* Kill everything that'll die */
	sleep(5);			/* give em a moment... (it may take a while for, e.g., pppd to shutdown cleanly */
	kill(-1, SIGKILL);		/* Really make sure that everything is dead */
	sleep(2);			/* give em another moment... */

	if (console)
		freopen(console, "w", stdout);
#if CONFIG_USER_NETFLASH_WATCHDOG
	if (watchdog) {
		watchdog_fd = open("/dev/watchdog", O_WRONLY);
	}
#endif
}

/****************************************************************************/

#if defined(CONFIG_USER_MOUNT_UMOUNT) || defined(CONFIG_USER_BUSYBOX_UMOUNT)
void umount_all(void)
{
	char *localargv[4];
	int localargc;
	pid_t pid;
	int status;

	localargc = 0;
	localargv[localargc++] = "umount";
	localargv[localargc++] = "-a";
	localargv[localargc++] = "-r";
	localargv[localargc++] = NULL;
	pid = vfork();
	if (pid == -1) {
		error("vfork() failed %m");
		exit_failed(VFORK_FAIL);
	} else if (pid == 0) {
		execvp("/bin/umount", localargv);
		_exit(1);
	}
	waitpid(pid, &status, 0);
}
#endif


/****************************************************************************/

static int get_segment(int rd, unsigned char *sgdata, int sgpos, int sgsize)
{
	int sglength;
	int sgoffset;

	if (offset > sgpos)
		sgoffset = offset - sgpos;
	else
		sgoffset = 0;

	/* XXX: preserve case could be optimized to read less */
	if (preserve || sgoffset) {
		if (lseek(rd, sgpos, SEEK_SET) != sgpos) {
			error("lseek(%x) failed\n", sgpos);
			exit_failed(BAD_SEG_SEEK);
		} else if (read(rd, sgdata, preserve ? sgsize : sgoffset) < 0) {
			error("read() failed, pos=%x, errno=%d\n",
					sgpos, errno);
			exit_failed(BAD_SEG_READ);
		}
	}

	sgpos -= offset - sgoffset;
	sgdata += sgoffset;
	sgsize -= sgoffset;

#ifdef CONFIG_USER_NETFLASH_DECOMPRESS
	if (doinflate) {
		sglength = decompress(sgdata, sgsize);
	} else
#endif
	{
		sglength = fb_read(sgdata, sgsize);
	}

	if (sglength !=0) {
		if (preserve)
			sglength = sgsize;
		sglength += sgoffset;
	}

	return sglength;
}

static void check_segment(int rd, unsigned char *sgdata, int sgpos, int sglength)
{
	if (lseek(rd, sgpos, SEEK_SET) != sgpos) {
		error("lseek(%x) failed", sgpos);
		exitstatus = BAD_SEG_SEEK;
	} else if (read(rd, check_buf, sglength) < 0) {
		error("read failed, pos=%x, errno=%d",
				sgpos, errno);
		exitstatus = BAD_SEG_READ;
	} else if (memcmp(sgdata, check_buf, sglength) != 0) {
		int i;
		error("check failed, pos=%x", sgpos);
		for (i = 0; i < sglength; i++) {
			if (sgdata[i] != check_buf[i])
				printf("%x(%x,%x) ", sgpos + i,
						sgdata[i] & 0xff,
						check_buf[i] & 0xff);
		}
		printf("\n");
		exitstatus = BAD_SEG_CHECK;
	}
}

#if defined(CONFIG_MTD) || defined(CONFIG_MTD_MODULES)
static int erase_segment(int rd, erase_info_t *ei)
{
	if (checkblank) {
		int i, blank;

		if (read(rd, check_buf, ei->length) != ei->length) {
			error("pre segment read(%x) failed", ei->start);
			return -1;
		}
		if (lseek(rd, ei->start, SEEK_SET) != ei->start) {
			error("lseek(%x) failed", ei->start);
			return -1;
		}

		for (blank = 1, i = 0; (i < ei->length); i++) {
			if (check_buf[i] != 0xff) {
				blank = 0;
				break;
			}
		}

		if (blank)
			return 0;
	}

	if (ioctl(rd, MEMERASE, ei) < 0) {
		error("ioctl(MEMERASE) failed, errno=%d", errno);
		return -1;
	}

	return 0;
}

static void program_mtd_segment(int rd, unsigned char *sgdata,
		int sgpos, int sglength, int sgsize)
{
	erase_info_t erase_info;
	int pos;

	/* Unlock the segment to be reprogrammed.  */
	if (dounlock) {
		erase_info.start = sgpos;
		erase_info.length = sgsize;
		/* Don't bother checking for failure */
		ioctl(rd, MEMUNLOCK, &erase_info);
	}

	erase_info.start = sgpos;
	erase_info.length = sgsize;
	if (lseek(rd, sgpos, SEEK_SET) != sgpos) {
		error("lseek(%x) failed", sgpos);
		exitstatus = BAD_SEG_SEEK;
	} else if (erase_segment(rd, &erase_info) < 0) {
		exitstatus = ERASE_FAIL;
	} else if (sglength > 0) {
		if (lseek(rd, sgpos, SEEK_SET) != sgpos) {
			error("lseek(%x) failed", sgpos);
			exitstatus = BAD_SEG_SEEK;
		} else {
			/*
			 * Always write in 512 byte chunks as MTD on
			 * a DoC device can only handle 512 byte writes.
			 *
			 * NOTE: we rely on the fact the sgdata buffer is always
			 *       a multiple of 512 in real size (erase_size for MTD)
			 *       which should always be true, I think.
			 */
			for (pos = sgpos; (sglength >= 512); ) {
				if (write(rd, sgdata, 512) == -1) {
					error("write() failed, "
						"pos=%x, errno=%d",
						pos, errno);
					exitstatus = BAD_SEG_WRITE;
				}
				pos += 512;
				sgdata += 512;
				sglength -= 512;
			}
			/*
			 * If there is a remainder, then still write a 512 byte
			 * chunk, but preserve what is already there.
			 */
			if (sglength > 0) {
				char buf[512];

				if (lseek(rd, pos, SEEK_SET) != pos) {
					error("lseek(%x) failed",
						pos);
					exitstatus = BAD_SEG_SEEK;
				} else if (read(rd, buf, 512) == -1) {
					error("read() failed, "
						"pos=%x, errno=%d",
						pos, errno);
					exitstatus = BAD_SEG_READ;
				} else if (lseek(rd, pos, SEEK_SET) != pos) {
					error("lseek(%x) failed",
						pos);
					exitstatus = BAD_SEG_SEEK;
				} else {
					memcpy(buf, sgdata, sglength);
					if (write(rd, buf, 512) == -1) {
						error("write() failed, pos=%x, errno=%d",
							pos, errno);
						exitstatus = BAD_SEG_WRITE;
					}
				}
			}
		}
	} else if (dojffs2) {
		static struct jffs2_unknown_node marker = {
			JFFS2_MAGIC_BITMASK,
			JFFS2_NODETYPE_CLEANMARKER,
			sizeof(struct jffs2_unknown_node),
#if __BYTE_ORDER == __BIG_ENDIAN
			0xf060dc98
#else
			0xe41eb0b1
#endif
		};

		if (lseek(rd, sgpos, SEEK_SET) != sgpos) {
			error("lseek(%x) failed", sgpos);
			exitstatus = BAD_SEG_SEEK;
		} else if (write(rd, &marker, sizeof(marker)) < 0) {
			error("write() failed, pos=%x, "
				"errno=%d", sgpos, errno);
			exitstatus = BAD_SEG_WRITE;
		}
	}

	if (dolock) {
		erase_info.start = sgpos;
		erase_info.length = sgsize;
		if (ioctl(rd, MEMLOCK, &erase_info) < 0) {
			error("ioctl(MEMLOCK) failed, "
				"errno=%d", errno);
			exitstatus = ERASE_FAIL;
		}
	}
}
#elif defined(CONFIG_BLK_DEV_BLKMEM)
static void program_blkmem_segment(int rd, unsigned char *sgdata, int sgpos,
	int sglength, int sgsize)
{
	char buf[128];
	struct blkmem_program_t *prog = (struct blkmem_program_t *)buf;

	prog->magic1 = BMPROGRAM_MAGIC_1;
	prog->magic2 = BMPROGRAM_MAGIC_2;
	prog->reset = 0;
	prog->blocks = 1;
	prog->block[0].data = sgdata;
	prog->block[0].pos = sgpos;
	prog->block[0].length = sglength;
	prog->block[0].magic3 = BMPROGRAM_MAGIC_3;
	if (ioctl(rd, BMPROGRAM, prog) != 0) {
		error("ioctl(BMPROGRAM) failed, errno=%d", errno);
		exitstatus = BAD_SEG_WRITE;
	}
}
#endif

static void program_generic_segment(int rd, unsigned char *sgdata,
		int sgpos, int sglength, int sgsize)
{
	if (!stop_early && sglength < sgsize) {
		memset(sgdata + sglength, 0xff, sgsize - sglength);
		sglength = sgsize;
	}

	if (sglength > 0) {
		if (lseek(rd, sgpos, SEEK_SET) != sgpos) {
			error("lseek(%x) failed", sgpos);
			exitstatus = BAD_SEG_SEEK;
		} else if (write(rd, sgdata, sglength) < 0) {
			error("write() failed, pos=%x, "
					"errno=%d", sgpos, errno);
			exitstatus = BAD_SEG_WRITE;
		} else if (fdatasync(rd) < 0) {
			error("fdatasync() failed, pos=%x, "
					"errno=%d", sgpos, errno);
			exitstatus = BAD_SEG_CHECK;
		}
	}
}

static void program_flash(int rd, int devsize, unsigned char *sgdata, int sgsize)
{
	int sgpos, sglength;
	unsigned long total;
#ifdef CONFIG_LEDMAN
	int ledmancount = 0;
#endif

#ifdef CONFIG_LEDMAN
	ledman_cmd(LEDMAN_CMD_ALT_ON, LEDMAN_NVRAM_1);
	ledman_cmd(LEDMAN_CMD_ALT_ON, LEDMAN_NVRAM_2);
#endif

	/* Round the image size up to the segment size */
	if (stop_early) {
		total = (image_length + sgsize - 1) & ~(sgsize - 1);
	} else {
		total = devsize;
	}

	/* Write the data one segment at a time */
	fb_seek_set(0);
	sgpos = offset - (offset % sgsize);
	for (; sgpos < devsize; sgpos += sgsize) {
		sglength = get_segment(rd, sgdata, sgpos, sgsize);

		if (stop_early && sglength <= 0) {
			break;
		}

		if (checkimage) {
			check_segment(rd, sgdata, sgpos, sglength);
		}
		else
#if defined(CONFIG_MTD_NETtel)
		if (!preserveconfig || sgpos < 0xe0000 || sgpos >= 0x100000) {
#endif
			program_segment(rd, sgdata, sgpos, sglength, sgsize);

#ifdef CONFIG_LEDMAN
			ledman_cmd(LEDMAN_CMD_OFF | LEDMAN_CMD_ALTBIT,
					ledmancount ? LEDMAN_NVRAM_1 : LEDMAN_NVRAM_2);
			ledman_cmd(LEDMAN_CMD_ON | LEDMAN_CMD_ALTBIT,
					ledmancount ? LEDMAN_NVRAM_2 : LEDMAN_NVRAM_1);
			ledmancount = (ledmancount + 1) & 1;
#endif
#ifdef CONFIG_USER_NETFLASH_WATCHDOG
			if (watchdog_fd >= 0)
				write(watchdog_fd, "\0", 1); 
#endif

#if defined(CONFIG_MTD_NETtel)
		} /* if (!preserveconfig || ...) */
#endif
		printf("\r%5dK %3ld%%", (sgpos + sgsize) / 1024, (sgpos + sgsize) * 100L / total);
		fflush(stdout);
	}

	printf("\n"); fflush(stdout);
#ifdef CONFIG_LEDMAN
	ledman_cmd(LEDMAN_CMD_ALT_OFF, LEDMAN_NVRAM_1);
	ledman_cmd(LEDMAN_CMD_ALT_OFF, LEDMAN_NVRAM_2);
#endif

	/* Put the flash back in read mode, some old boot loaders don't */
	lseek(rd, 0, SEEK_SET);
	read(rd, sgdata, 1);
}

/****************************************************************************/

void update_bootcfg(char *filename)
{
	char *contents;
	int size, fd, len;

	if (memcmp(filename, "/sda1", 5) == 0)
		filename += 5;
	len = strlen(filename);

	if ((fd = open("/sda1/boot.cfg", O_RDWR | O_CREAT, 0600)) > 0) {
		size = lseek(fd, 0, SEEK_END);
		if ((contents = malloc(size)) == NULL)
			return;
		lseek(fd, 0, SEEK_SET);
		read(fd, contents, size);
		lseek(fd, 0, SEEK_SET);
		if (len < size) {
			if (memcmp(contents, filename, len) == 0) {
				/* Already entry for this in boot.cfg */
				close(fd);
				return;
			}
		}
		write(fd, filename, len);
		write(fd, "\n", 1);
		write(fd, contents, size);
		free(contents);
		close(fd);
	}
}

/****************************************************************************/

int usage(int rc)
{
  printf("usage: netflash [-abCfFehijklntuv"
#ifdef CONFIG_USER_NETFLASH_DECOMPRESS
	"z"
#endif
#ifdef CONFIG_USER_NETFLASH_SHA256
	"B"
#endif
	"?] [-c console-device] [-d delay] "
#ifdef CONFIG_USER_NETFLASH_SETSRC
	"[-I ip-address] "
#endif
#ifdef CONFIG_USER_NETFLASH_HMACMD5
	"[-m hmac-md5-key] "
#endif
	"[-o offset] [-r flash-device] [-R file-name] "
	"[net-server] file-name\n\n"
	"\t-a\tdon't add filename to bootcfg file (if using -R)\n"
	"\t-b\tdon't reboot hardware when done\n"
	"\t-C\tcheck that image was written correctly\n"
	"\t-f\tuse FTP as load protocol\n"
	"\t-e\tdo not erase flash segments if they are already blank\n"
	"\t-F\tforce overwrite (do not preserve special regions)\n"
  	"\t-h\tprint help\n"
	"\t-i\tignore any version information\n"
	"\t-H\tignore hardware type information\n"
#ifdef CONFIG_USER_NETFLASH_SETSRC
	"\t-I\toriginate TFTP request from this address\n"
#endif
	"\t-j\timage is a JFFS2 filesystem\n"
	"\t-k\tdon't kill other processes (or delays kill until\n"
	"\t\tafter downloading when root filesystem is inside flash)\n"
	"\t-K\tonly kill unnecessary processes (or delays kill until\n"
	"\t\tafter downloading when root filesystem is inside flash)\n"
	"\t-l\tlock flash segments when done\n"
#if CONFIG_USER_NETFLASH_SHA256
  	"\t-N\tfile with no SHA256 checksum\n"
#endif
  	"\t-n\tfile with no checksum at end (implies no version information)\n"
	"\t-p\tpreserve portions of flash segments not actually written.\n"
  	"\t-s\tstop erasing/programming at end of input data\n"
  	"\t-S\tdo not stop erasing/programming at end of input data\n"
	"\t-t\tcheck the image and then throw it away \n"
	"\t-u\tunlock flash segments before programming\n"
  	"\t-v\tdisplay version number\n"
#if CONFIG_USER_NETFLASH_WATCHDOG
  	"\t-w\tdon't tickle hardware watchdog\n"
#endif
#ifdef CONFIG_USER_NETFLASH_DECOMPRESS
	"\t-z\tdecompress image before writing\n"
#endif
  );

  exit(rc);
}

/****************************************************************************/
/*
 * when we call reboot,  we don't want anything in our way, most certainly
 * not logd !
 */

static inline int raw_reboot(int magic, int magic2, int flag)
{
	return syscall(__NR_reboot, magic, magic2, flag);
}

/****************************************************************************/

int netflashmain(int argc, char *argv[])
{
	char *srvname, *filename;
	char *rdev, *console;
	unsigned char *sgdata;
	int rd, rc, tmpfd, delay;
	int dochecksum, dokill, dokillpartial, doreboot, doftp;
	int dopreserve, doversion, doremoveversion, dohardwareversion;
	int devsize = 0, sgsize = 0;

#ifdef CONFIG_USER_NETFLASH_HMACMD5
	char *hmacmd5key = NULL;
#endif
#if defined(CONFIG_USER_NETFLASH_WITH_CGI) && !defined(RECOVER_PROGRAM)
	char options[64];
	char flash_region[20];
	char *new_argv[10];
#endif

	rdev = "/dev/flash/image";
	srvname = NULL;
	filename = NULL;
	console = NULL;
	dochecksum = 1;
	dokill = 1;
	dokillpartial = 0;
	doreboot = 1;
	dolock = 0;
	dounlock = 0;
	delay = 0;
	doftp = 0;
	dothrow = 0;
	dopreserve = 1;
	preserveconfig = 0;
	checkimage = 0;
	checkblank = 0;
	dojffs2 = 0;
	doremoveversion = 1;

#ifdef CONFIG_USER_NETFLASH_VERSION
	doversion = 1;
	dohardwareversion = 1;
#else
	doversion = 0;
	dohardwareversion = 0;
#endif /*CONFIG_USER_NETFLASH_VERSION*/
#ifdef CONFIG_USER_NETFLASH_DECOMPRESS
	doinflate = 0;
#endif
#ifdef CONFIG_USER_NETFLASH_WITH_FILE
	dofileautoname = 1;
	dofilesave = 1;
	dobootcfg = 1;
	stop_early = 1;
#endif

#if defined(CONFIG_USER_NETFLASH_WITH_CGI) && !defined(RECOVER_PROGRAM)
	if (argc == 2 && strncmp(argv[1], "cgi://", 6) == 0) {
		char *pt;
		char *sep;
		int new_argc = 0;

		docgi = 1;

		/* Do the partial kill here before we download the image */
		kill_processes_partial();
		/* Wait a little bit for processes to die and release memory */
		sleep(5);

		/* Our "command line" options come from stdin for cgi
		 * Format of the command line is:
		 * cgi://dataname,optionsname,flash_regionname
		 */
		pt = argv[1] + 6;
		sep = strchr(pt, ',');
		if (sep) {
			int len = sep - pt;
			if (len >= sizeof(cgi_data)) {
				len = sizeof(cgi_data) - 1;
			}
			strncpy(cgi_data, pt, len);
			cgi_data[len] = 0;
			pt = sep + 1;
			sep = strchr(pt, ',');
			if (sep) {
				len = sep - pt;
				strncpy(cgi_options, pt, len);
				cgi_options[len] = 0;

				strncpy(cgi_flash_region, sep + 1, sizeof(cgi_flash_region));
				cgi_flash_region[sizeof(cgi_flash_region) - 1] = 0;
			} else {
				exit_failed(BAD_CGI_FORMAT);
			}
		} else {
			exit_failed(BAD_CGI_FORMAT);
		}

		if (cgi_load(cgi_data, cgi_options, options,
					cgi_flash_region, flash_region, &rc) <= 0) {
			exit_failed(rc);
		}

		if (strcmp(flash_region, "bootloader") == 0) {
#ifndef CONFIG_USER_FLASH_BOOT_LOCKED
			const char *bootloader_params = " -np -r /dev/flash/boot";
#else
			const char *bootloader_params = " -np -r /dev/flash/boot -lu";
#endif
			if ((sizeof(options) - strlen(options)) > strlen(bootloader_params)) {
				strcat(options, bootloader_params);
			}
			else {
				exit_failed(BAD_CGI_DATA);
			}
		}

		new_argv[new_argc++] = argv[0];

		/* Parse the options */
		pt = strtok(options, " \t");
		while (pt) {
			assert(new_argc < 10);
			new_argv[new_argc++] = pt;
			pt = strtok(0, " \t");
		}
		argc = new_argc;
		argv = new_argv;
	}
#endif

	while ((rc = getopt(argc, argv, CMD_LINE_OPTIONS)) > 0) {
		switch (rc) {
		case 'p':
			preserve = 1;
			stop_early = 1;
			break;
		case 's':
			stop_early = 1;
			break;
		case 'S':
			nostop_early = 1;
			break;
		case 'b':
			doreboot = 0;
			break;
		case 'c':
			console = optarg;
			break;
		case 'C':
			checkimage = 1;
			break;
		case 'e':
			checkblank = 1;
			break;
		case 'd':
			delay = (atoi(optarg));
			break;
		case 'f':
			doftp = 1;
			break;
		case 'F':
			dopreserve = 0;
			break;
		case 'i': 
			doversion = 0; 
			break;
		case 'H': 
			dohardwareversion = 0; 
			break;
		case 'j':
			dojffs2 = 1;
			nostop_early = 1;
			break;
		case 'k':
			dokill = 0;
			break;
		case 'K':
			dokill = 1;
			dokillpartial = 1;
			break;
		case 'l':
			dolock++;
			break;
#ifdef CONFIG_USER_NETFLASH_HMACMD5
		case 'm':
			hmacmd5key = optarg;
			break;
#endif
#ifdef CONFIG_USER_NETFLASH_SHA256
		case 'N':
			dosha256sum = 0;
			break;
#endif
		case 'n':
			/* No checksum implies no version */
			dochecksum = doversion = dohardwareversion = doremoveversion = 0;
			break;
		case 'o':
			offset = strtol(optarg, NULL, 0);
			break;
		case 'a':
			dobootcfg = 0;
			break;
		case 'R':
			dofilesave = 1;
			dofileautoname = 0;
			dobootcfg = 1;
			stop_early = 1;
			rdev = optarg;
			break;
		case 'r':
			dofilesave = 0;
			dofileautoname = 0;
			stop_early = 0;
			dobootcfg = 0;
			rdev = optarg;
			break;
		case 't':
			dothrow = 1;
			break;
		case 'u':
			dounlock++;
			break;
		case 'v':
			notice("version %s", version);
			exit(0);
#ifdef CONFIG_USER_NETFLASH_DECOMPRESS
		case 'z':
			doinflate = 1;
			break;
#endif
#ifdef CONFIG_USER_NETFLASH_SETSRC
		case 'I':
			srcaddr = optarg;
			break;
#endif
#ifdef CONFIG_USER_NETFLASH_WATCHDOG
		case 'w':
			watchdog = 0;
			break;
#endif
		case 'h':
		case '?':
			usage(0);
			break;
		}
	}

	/*
	 * for /dev/flash/image we want to stop early unless the user
	 * has told us not to (-S).  This allows us to preserve logd info
	 *
	 * So we override the default of not stopping early for /dev/flash/image
	 */
	if (strcmp(rdev, "/dev/flash/image") == 0) {
		if (nostop_early == 0)
			stop_early = 1;
	}

	if ((nfd = fopen("/dev/null", "rw")) == NULL) {
		error("open(/dev/null) failed: %s", strerror(errno));
		exit_failed(NO_DEV_NULL);
	}

	if (!docgi) {
		if (optind == (argc - 1)) {
			srvname = NULL;
			filename = argv[optind];
		} else if (optind == (argc - 2)) {
			srvname = argv[optind++];
			filename = argv[optind];
		} else {
			usage(1);
		}
	}

	if (delay > 0) {
		/* sleep the required time */
		notice("waiting %d seconds before updating flash...",delay);
		sleep(delay);
	}

	/*
	 *	Need to do any real FTP setup early, before killing processes
	 *	(and this losing association with the controlling tty).
	 */
	if (doftp) {
		if (ftpconnect(srvname)) {
			error("ftpconnect failed");
			exit_failed(FTP_CONNECT_FAIL);
		}
	}

	/* CGI code has already called kill_processes_partial() */
	if (dokill && !docgi) {
		if (dokillpartial)
			kill_processes_partial();
		else
			kill_processes(console);
	}

	/*
	 * Open the flash device and allocate a segment sized block.
	 * This is the largest block we need to allocate, so we do
	 * it first to try to avoid fragmentation effects.
	 */
	if (dopreserve && (strcmp(rdev, "/dev/flash/image") == 0))
		preserveconfig = 1;

	/*
 	 * If we are writing to a real flash device then we open it now,
 	 * and do the sizing checks. If writing to a regular file we hold
 	 * of until we have the image (so ww can do filename/directory name
 	 * completion if required.
 	 */
	if (dofilesave) {
		/* Should be checking space available on filesystem */
		sgsize = 128000;
		devsize = 0x0fffffff;
		program_segment = program_generic_segment;
	} else {
		rd = open(rdev, O_RDWR);
		if (rd < 0) {
			error("open(%s) failed: %s", rdev, strerror(errno));
			exit_failed(BAD_OPEN_FLASH);
		}

		if (stat(rdev, &stat_rdev) != 0) {
			error("stat(%s) failed: %s", rdev, strerror(errno));
			exit_failed(BAD_OPEN_FLASH);
		} else if (S_ISBLK(stat_rdev.st_mode)) {
#ifdef CONFIG_NFTL_RW
			if (major(stat_rdev.st_rdev) == NFTL_MAJOR) {
				unsigned long l;

				program_segment = program_generic_segment;
				preserveconfig = dolock = dounlock = 0;
				if (ioctl(rd, BLKGETSIZE, &l) < 0) {
					error("ioctl(BLKGETSIZE) failed, "
						"errno=%d", errno);
					exit_failed(BAD_OPEN_FLASH);
				}
				/* Sectors are always 512 bytes */
				devsize = l * 512;
				/*
				 * Use a larger sgsize for efficiency, but it
			 	 * must divide evenly into devsize.
			 	 */
				for (sgsize = 512; sgsize < 64*1024; sgsize <<= 1)
					if (devsize & sgsize)
						break;
			}
#endif
#ifdef CONFIG_IDE
			if ((major(stat_rdev.st_rdev) == IDE0_MAJOR) ||
			    (major(stat_rdev.st_rdev) == IDE1_MAJOR) ||
			    (major(stat_rdev.st_rdev) == IDE2_MAJOR) ||
			    (major(stat_rdev.st_rdev) == IDE3_MAJOR)) {
				struct hd_geometry geo;

				program_segment = program_generic_segment;
				preserveconfig = dolock = dounlock = 0;
				if (ioctl(rd, HDIO_GETGEO, &geo) < 0) {
					error("ioctl(HDIO_GETGEO) failed, "
						"errno=%d", errno);
					exit_failed(BAD_OPEN_FLASH);
				}
				devsize = geo.heads * geo.cylinders * geo.sectors * 512;
				/*
				 * Use a larger sgsize for efficiency, but it
				 * must divide evenly into devsize.
				 */
				for (sgsize = 512; sgsize < 64*1024; sgsize <<= 1)
					if (devsize & sgsize)
						break;
			}
#endif
		}
		if (!program_segment) {
#if defined(CONFIG_MTD) || defined(CONFIG_MTD_MODULES)
			mtd_info_t mtd_info, rootfs_info;

			program_segment = program_mtd_segment;

			if (ioctl(rd, MEMGETINFO, &mtd_info) < 0) {
				error("ioctl(MEMGETINFO) failed, errno=%d",
					errno);
				exit_failed(BAD_OPEN_FLASH);
			}
			devsize = mtd_info.size;
			sgsize = mtd_info.erasesize;

			/*
			 * NETtel/x86 boards that boot direct from INTEL FLASH
			 * also have a boot sector at the top of the FLASH.
			 * When programming complete images we need to not
			 * overwrite this.
			 */
			if (preserveconfig) {
				if ((tmpfd = open("/dev/flash/rootfs", O_RDONLY)) > 0) {
					if (ioctl(tmpfd, MEMGETINFO, &rootfs_info) >= 0) {
						if (rootfs_info.size & 0x000fffff) {
							devsize = devsize - (0x00100000 -
									(rootfs_info.size & 0x000fffff));
						}
					}
					close(tmpfd);
				}
			}
#elif defined(CONFIG_BLK_DEV_BLKMEM)
			program_segment = program_blkmem_segment;
	
			if (ioctl(rd, BMGETSIZEB, &devsize) != 0) {
				error("ioctl(BMGETSIZEB) failed, errno=%d",
					errno);
				exit_failed(BAD_OPEN_FLASH);
			}
			if (ioctl(rd, BMSGSIZE, &sgsize) != 0) {
				error("ioctl(BMSGSIZE) failed, errno=%d",
					errno);
				exit_failed(BAD_OPEN_FLASH);
			}
#endif
		}
	}
  
	if (offset < 0) {
		error("offset is less than zero");
		exit_failed(BAD_OFFSET);
	}
	if (offset >= devsize) {
		error("offset is greater than device size (%d)", devsize);
		exit_failed(BAD_OFFSET);
	}

	sgdata = malloc(sgsize);
	if (!sgdata) {
		error("Insufficient memory for image!");
		exit_failed(NO_MEMORY);
	}

	if (checkimage || checkblank) {
		check_buf = malloc(sgsize);
		if (!check_buf) {
			error("Insufficient memory for check buffer!");
			exit_failed(NO_MEMORY);
		}
	}

	/*
	 * Fetch file into memory buffers. Exactly how depends on the exact
	 * load method. Support for tftp, http and local file currently.
	 */
	if (!docgi) {
		if (srvname) {
			if (doftp)
				ftpfetch(srvname, filename);
			else
				tftpfetch(srvname, filename);
		} else if (filefetch(filename) < 0) {
				error("failed to find %s", filename);
				exit_failed(NO_IMAGE);
		}
	}

	if (dofilesave) {
		/*
		 * We fake out the file size here so that the percentage
		 * display looks correct as output.
		 */
		devsize = fb_len();
	}

	if (fb_len() == 0) {
		error("failed to load new image");
		exit_failed(NO_IMAGE);
	}

	if (!docgi) {
		notice("got \"%s\", length=%ld", filename, fb_len());
	}

#if defined(CONFIG_USER_NETFLASH_CRYPTO) && !defined(CONFIG_USER_NETFLASH_CRYPTO_V2)
	check_crypto_signature();
#endif

#ifdef CONFIG_USER_NETFLASH_HMACMD5
	if (hmacmd5key)
		check_hmac_md5(hmacmd5key);
	else
#endif
	if (dochecksum)
		chksum();

	/*
	 * Check the version information.
	 * Side effect: this also checks whether version information is present,
	 * and if so, removes it, since it doesn't need to get written to flash.
	 */
	if (doversion || dohardwareversion || doremoveversion)
		rc = check_vendor();

#ifdef CONFIG_USER_NETFLASH_VERSION
	if (doversion || dohardwareversion) {
		switch (rc){
		case 5:
			error("VERSION - you are trying to load an "
				"image that does not\n         "
				"contain valid version information.");
			exit_failed(NO_VERSION);
		default:
			break;
		}
	}

	if (doversion) {
		switch (rc){
#ifndef CONFIG_USER_NETFLASH_VERSION_ALLOW_CURRENT
		case 3:
			error("VERSION - you are trying to upgrade "
				"with the same firmware\n"
				"         version that you already have.");
			exit_failed(ALREADY_CURRENT);
#endif /* !CONFIG_USER_NETFLASH_VERSION_ALLOW_CURRENT */
#ifndef CONFIG_USER_NETFLASH_VERSION_ALLOW_OLDER
		case 4:
			error("VERSION - you are trying to upgrade "
				"with an older version of\n"
				"         the firmware.");
			exit_failed(VERSION_OLDER);
#endif /* !CONFIG_USER_NETFLASH_VERSION_ALLOW_OLDER */
		case 6:
			error("VERSION - you are trying to load an "
				"image for a different language.");
			exit_failed(BAD_LANGUAGE);
		case 0:
			default:
			break;
		}
	}

	if (dohardwareversion) {
		switch (rc){
		case 1:
			error("VERSION - product name incorrect.");
			exit_failed(WRONG_PRODUCT);
		case 2:
			error("VERSION - vendor name incorrect.");
			exit_failed(WRONG_VENDOR);
		case 0:
		default:
			break;
		}
	}
#endif /*CONFIG_USER_NETFLASH_VERSION*/

	if (dofilesave) {
		if (dofileautoname) {
			rdev = malloc(MAX_VERSION_SIZE + strlen(filename) + 16);
			if (rdev == NULL) {
				rdev = filename;
			} else {
				char *p;
				sprintf(rdev, "/sda1/%s", imageVersion);
				mkdir(rdev, 0777);
				/* already have the file, so any '/'s can't
				 * be at the end, i.e. filename isn't a dir */
				p = strrchr(filename, '/');
				if (p) {
					sprintf(rdev, "/sda1/%s/%s", imageVersion, p+1);
				} else {
					sprintf(rdev, "/sda1/%s/%s", imageVersion, filename);
				}
			}
		}
		if ((rd = open(rdev, O_RDWR|O_CREAT|O_TRUNC, 0400)) < 0) {
			error("open(%s) failed: %s", rdev, strerror(errno));
			exit_failed(BAD_OPEN_FLASH);
		}
	}

#ifdef CONFIG_USER_NETFLASH_SHA256
	/*
	 * To be backword compatible with our images we leave the trailing
	 * old style checksum and product ID "as is". They are stripped of
	 * in the above code. Leaving now the SHA256 checksum. We want to
	 * leave this in place, and have it written to the flash with the
	 * actual image.
	 */
	if (dochecksum && dosha256sum)
		check_sha256_sum();
#endif
#ifdef CONFIG_USER_NETFLASH_CRYPTO_V2
	/*
	 * Modern signed image support is backward compatible, so we don't
	 * do the crypto check until this point. (That is we have stripped
	 * of old style 16bit checksum and the product/version information).
	 * We also leave the sign structures on the image data, so they get
	 * written to flash as well.
	 */
	if (doversion)
		check_crypto_signature();
#endif

#ifdef CONFIG_USER_NETFLASH_DECOMPRESS
	doinflate = check_decompression(doinflate);
#else
	image_length = fb_len();
#endif

	/*
	 * A firmware image will always be bigger than 512K, and bootloader
	 * images will always be less than 512K.
	 */
	if ((image_length < 512 * 1024) && (strcmp(rdev, "/dev/flash/image") == 0)) {
		error("image is not a firmware image");
		exit_failed(NOT_FIRMWARE_IMAGE);
	}

	if ((image_length > 512 * 1024) && (strcmp(rdev, "/dev/flash/boot") == 0)) {
		error("image is not a bootloader image");
		exit_failed(NOT_BOOTLOADER_IMAGE);
	}

	/* Check image that we fetched will actually fit in the FLASH device. */
	if (image_length > devsize - offset) {
		error("image too large for FLASH device (size=%d)",
			devsize - offset);
			exit_failed(IMAGE_TOO_BIG);
	}

	if (dothrow) {
		notice("the image is good.");
		exit(IMAGE_GOOD);
	}
#if defined(CONFIG_USER_NETFLASH_WITH_CGI) && !defined(RECOVER_PROGRAM)
	if (docgi) {
		/* let's let our parent know it's ok. */
		kill(getppid(),SIGUSR1);

		/* 
		 * Ensure that from this point onwards, we will 
		 * definitely reboot, even if there is an error during
		 * programming the flash.
		 */
		doreboot = 1;
	}
#endif
	if (flashing_rootfs(rdev)) {
		/*
		 * Our filesystem is live, so we MUST kill processes if we
		 * haven't done it already.
		 */
		notice("flashing root filesystem, kill is forced");
		if (!dokill || dokillpartial)
			kill_processes(console);
		/* We must reboot on this platform */
		doreboot = 1;
	}

#ifdef CONFIG_PROP_LOGD_LOGD
	log_upgrade();
#endif
#if defined(CONFIG_USER_MOUNT_UMOUNT) || defined(CONFIG_USER_BUSYBOX_UMOUNT)
	if (doreboot) {
		umount_all();
	}
#endif

#ifdef CONFIG_JFFS_FS
	/* Stop the JFFS garbage collector */
	killprocname("jffs_gcd", SIGSTOP);
#endif
#ifdef CONFIG_JFFS2_FS
	/* Stop the JFFS2 garbage collector */
	killprocname("jffs2_gcd_mtd1", SIGSTOP);
#endif

	/*
	 * Program the FLASH device.
	 */
	fflush(stdout);
	sleep(1);
	notice("programming FLASH device %s",
		(dofilesave ? "FLASH device" : "file image"), rdev);

	program_flash(rd, devsize, sgdata, sgsize);

	if (dobootcfg)
		update_bootcfg(rdev);
	if (dofilesave) {
		sync();
		sleep(2);
		sync();
	}
	if (doreboot) {
		usleep(500000);
		raw_reboot(0xfee1dead, 672274793, 0x01234567);
	}

	return exitstatus;
}

static void exit_failed(int rc)
{
#ifdef CONFIG_USER_NETFLASH_WATCHDOG
	close(watchdog_fd);
#endif
	exit(rc);
}
/****************************************************************************/
