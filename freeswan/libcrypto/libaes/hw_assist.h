#ifndef _HW_ASSIST_H
#define _HW_ASSIST_H 1
/****************************************************************************/
#if !defined(HW_ASSIST)
/****************************************************************************/
/*
 *	stub it all out
 */

#define hw_aes_assist() (0)
#define hw_aes_cbc_encrypt(a1,a2,a3,a4,a5,a6)

/****************************************************************************/
#elif defined(__KERNEL__)
/****************************************************************************/

#include "aes.h"

extern int (*hw_aes_assist_ptr)(void);
extern int (*hw_aes_cbc_encrypt_ptr)(aes_context *ctx, const __u8 *input, __u8 *output,
									int length, const __u8 *ivec, int enc);
	
#define hw_aes_assist() (*hw_aes_assist_ptr)()
#define hw_aes_cbc_encrypt(a1,a2,a3,a4,a5,a6) \
				(*hw_aes_cbc_encrypt_ptr)(a1,a2,a3,a4,a5,a6)

/****************************************************************************/
#else /* if ! __KERNEL__ */
/****************************************************************************/

#include <linux/types.h>
#include "aes.h"

extern int hw_aes_assist();
extern int hw_aes_cbc_encrypt(aes_context *ctx, const __u8 *input, __u8 *output,
								int length, const __u8 *ivec, int enc);

/****************************************************************************/
#endif /* __KERNEL__ */
/****************************************************************************/
#endif /* _HW_ASSIST_H */
