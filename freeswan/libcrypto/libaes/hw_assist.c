/****************************************************************************/
#if !defined(HW_ASSIST)
/****************************************************************************/

/*
 *	We do nothing here except for the kernel,  we need to provide
 *	the libaes_init/cleanup functions
 */

#ifndef __KERNEL__
void libaes_init(void) {}
void libaes_cleanup(void) {}
#endif

/****************************************************************************/
#elif !defined(__KERNEL__)
/****************************************************************************/

#include <fcntl.h>
#include <linux/types.h>
#include <string.h>
#include <sys/ioctl.h>
#include "aes.h"
#include "aes_cbc.h"

/****************************************************************************/

#ifdef HIFN
#include <hifn.h>

static int aes_fd = -1;
static int aes_tested = 0;
#endif

/****************************************************************************/
/*
 *	return true if HW aes is present
 */

int hw_aes_assist()
{
#ifdef HIFN
    if (!aes_tested) {
		aes_fd = open("/dev/hifn0", O_RDWR);
		if (aes_fd) {
			aes_tested = 1;
			if (!ioctl(aes_fd, HIFN_DOES_AES, NULL)) {
				close(aes_fd);
				aes_fd = -1;
			}
		}
    }
	return(aes_fd != -1);
#else
	return(0);
#endif
}

/****************************************************************************/

int hw_aes_cbc_encrypt(ctx, input, output, length, ivec, enc)
	aes_context *ctx;
	const __u8 (*input);
	__u8 (*output);
	long length;
	__u8 (*ivec);
	int enc;
{
#ifdef HIFN
	struct hifn_enc_req req;

	req.cmd = HIFN_ENC_AES_CBC;
	req.enc = enc;
	req.length = length;
	memcpy(req.key, ctx->aes_e_key, 32);
	req.aes_key_len = ctx->aes_Nkey;
	memcpy(req.ivec, ivec, 8);
	req.input = (unsigned char*)input;
	req.output = (unsigned char*)output;
	ioctl(aes_fd, HIFN_ENCRYPT, &req);
	return length;
#endif
}

/****************************************************************************/
#else /* __KERNEL__ */
/****************************************************************************/

#include <linux/module.h>
#include <linux/version.h>
#include "aes.h"

#ifndef NULL
#define	NULL	((void *) 0)
#endif

static int false(void);
static int false()
{
	return(0);
}

int (*hw_aes_assist_ptr)(void) = false;
int (*hw_aes_cbc_encrypt_ptr)(aes_context *ctx, const __u8 *input, __u8 *output,
		    int length, const __u8 *ivec, int enc) = NULL;


#if LINUX_VERSION_CODE < 0x020100

static struct symbol_table libaes_syms = {
#include <linux/symtab_begin.h>
	X(hw_aes_assist_ptr),
	X(hw_aes_cbc_encrypt_ptr),
#include <linux/symtab_end.h>
};

void libaes_init(void)
{
	register_symtab(&libaes_syms);
}

void libaes_cleanup(void)
{
	/* unregister_symtab(&libaes_syms); */
}

#else

EXPORT_SYMBOL(hw_aes_assist_ptr);
EXPORT_SYMBOL(hw_aes_cbc_encrypt_ptr);

#endif

/****************************************************************************/
#endif /* HW_ASSIST/__KERNEL__ */
/****************************************************************************/
