/*
 * ipsec_alg NULL cipher stubs
 *
 * Author: JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>
 * 
 * $Id: ipsec_alg_null.c,v 1.1.2.1 2006-10-11 18:14:33 paul Exp $
 * 
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 * 
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 */
#include <linux/config.h>
#include <linux/version.h>

/*	
 *	special case: ipsec core modular with this static algo inside:
 *	must avoid MODULE magic for this file
 */
#if defined(CONFIG_KLIPS_MODULE) && defined(CONFIG_KLIPS_ENC_NULL)
#undef MODULE
#endif

#include <linux/module.h>
#include <linux/init.h>

#include <linux/kernel.h> /* printk() */
#include <linux/errno.h>  /* error codes */
#include <linux/types.h>  /* size_t */
#include <linux/string.h>

/* Check if __exit is defined, if not null it */
#ifndef __exit
#define __exit
#endif

/*	Low freeswan header coupling	*/
#include "openswan/ipsec_alg.h"

#define ESP_NULL		11	/* from ipsec drafts */
#define ESP_NULL_BLK_LEN	1

MODULE_AUTHOR("JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>");
static int debug_null=0;
static int test_null=0;
#ifdef module_param
module_param(debug_null, int, 0600);
module_param(test_null, int, 0600);
#else
MODULE_PARM(debug_null, "i");
MODULE_PARM(test_null, "i");
#endif

typedef int null_context;

struct null_eks{
	null_context null_ctx;
};
static int _null_set_key(struct ipsec_alg_enc *alg, 
			__u8 * key_e, const __u8 * key, 
			size_t keysize) {
	null_context *ctx=&((struct null_eks*)key_e)->null_ctx;
	if (debug_null > 0)
		printk(KERN_DEBUG "klips_debug:_null_set_key:"
				"key_e=%p key=%p keysize=%d\n",
				key_e, key, keysize);
	*ctx = 1;
	return 0;
}
static int _null_cbc_encrypt(struct ipsec_alg_enc *alg, 
		__u8 * key_e, __u8 * in, int ilen, const __u8 * iv, 
		int encrypt) {
	null_context *ctx=&((struct null_eks*)key_e)->null_ctx;
	if (debug_null > 0)
		printk(KERN_DEBUG "klips_debug:_null_cbc_encrypt:"
				"key_e=%p in=%p ilen=%d iv=%p encrypt=%d\n",
				key_e, in, ilen, iv, encrypt);
	(*ctx)++;
	return ilen;
}
static struct ipsec_alg_enc ipsec_alg_NULL = {
	ixt_common: { ixt_version:	IPSEC_ALG_VERSION,
		      ixt_refcnt:	ATOMIC_INIT(0),
		      ixt_name: 	"null",
		      ixt_blocksize:	ESP_NULL_BLK_LEN,
		      ixt_support: {
			ias_exttype:	IPSEC_ALG_TYPE_ENCRYPT,
			ias_id: 	ESP_NULL,
			ias_ivlen:	0,
			ias_keyminbits:	0,
			ias_keymaxbits:	0,
		},
	},
#if defined(CONFIG_KLIPS_ENC_NULL_MODULE)
	ixt_module:	THIS_MODULE,
#endif
	ixt_e_keylen:	0,
	ixt_e_ctx_size:	sizeof(null_context),
	ixt_e_set_key:	_null_set_key,
	ixt_e_cbc_encrypt:_null_cbc_encrypt,
};

#if defined(CONFIG_KLIPS_ENC_NULL_MODULE)
IPSEC_ALG_MODULE_INIT_MOD( ipsec_null_init )
#else
IPSEC_ALG_MODULE_INIT_STATIC( ipsec_null_init )
#endif
{
	int ret, test_ret;
	ret=register_ipsec_alg_enc(&ipsec_alg_NULL);
	printk("ipsec_null_init(alg_type=%d alg_id=%d name=%s): ret=%d\n", 
			ipsec_alg_NULL.ixt_common.ixt_support.ias_exttype,
			ipsec_alg_NULL.ixt_common.ixt_support.ias_id,
			ipsec_alg_NULL.ixt_common.ixt_name, 
			ret);
	if (ret==0 && test_null) {
		test_ret=ipsec_alg_test(
				ipsec_alg_NULL.ixt_common.ixt_support.ias_exttype,
				ipsec_alg_NULL.ixt_common.ixt_support.ias_id,
				test_null);
		printk("ipsec_null_init(alg_type=%d alg_id=%d): test_ret=%d\n", 
				ipsec_alg_NULL.ixt_common.ixt_support.ias_exttype,
				ipsec_alg_NULL.ixt_common.ixt_support.ias_id,
				test_ret);
	}
	return ret;
}
#if defined(CONFIG_KLIPS_ENC_NULL_MODULE)
IPSEC_ALG_MODULE_EXIT_MOD( ipsec_null_fini )
#else
IPSEC_ALG_MODULE_EXIT_STATIC( ipsec_null_fini )
#endif
{
	unregister_ipsec_alg_enc(&ipsec_alg_NULL);
	return;
}
#ifdef MODULE_LICENSE
MODULE_LICENSE("GPL");
#endif
