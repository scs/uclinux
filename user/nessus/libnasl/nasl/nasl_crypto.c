/* Nessus Attack Scripting Language 
 *
 * Copyright (C) 2002 - 2003 Michel Arboi and Renaud Deraison
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * In addition, as a special exception, Renaud Deraison and Michel Arboi
 * give permission to link the code of this program with any
 * version of the OpenSSL library which is distributed under a
 * license identical to that listed in the included COPYING.OpenSSL
 * file, and distribute linked combinations including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * this file, you may extend this exception to your version of the
 * file, but you are not obligated to do so.  If you do not wish to
 * do so, delete this exception statement from your version.
 *
 */
 /*
  * This file contains all the cryptographic functions NASL
  * has
  */
#include <includes.h>
#include <endian.h>
#ifdef HAVE_SSL
#ifdef HAVE_OPENSSL_MD2_H
#include <openssl/md2.h>
#endif
#ifdef HAVE_OPENSSL_MD4_H
#include <openssl/md4.h>
#endif
#ifdef HAVE_OPENSSL_MD5_H
#include <openssl/md5.h>
#endif
#include <openssl/ripemd.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#endif



#include "nasl_tree.h"
#include "nasl_global_ctxt.h"
#include "nasl_func.h"
#include "nasl_var.h"
#include "nasl_lex_ctxt.h"
#include "exec.h"  

#include "nasl_debug.h"

#include "strutils.h"
#include "hmacmd5.h"
#include <assert.h>


#ifdef HAVE_SSL


/*-------------------[  Std. HASH ]-------------------------------------*/
#ifdef HAVE_OPENSSL_MD2_H
tree_cell * nasl_md2(lex_ctxt * lexic)
{
 char * data = get_str_var_by_num(lexic, 0);
 int    len  = get_var_size_by_num(lexic, 0);
 char md[MD2_DIGEST_LENGTH+1];
 tree_cell * retc;
 
 if(data == NULL)
  return NULL;
 
 MD2(data, len, md);

 retc = alloc_tree_cell(0, NULL);
 retc->type = CONST_DATA;
 retc->x.str_val = strndup(md, MD2_DIGEST_LENGTH);
 retc->size = MD2_DIGEST_LENGTH;
 return retc;
}
#endif

#ifdef HAVE_OPENSSL_MD4_H
tree_cell * nasl_md4(lex_ctxt * lexic)
{
 char * data = get_str_var_by_num(lexic, 0);
 int    len  = get_var_size_by_num(lexic, 0);
 char md[MD4_DIGEST_LENGTH+1];
 tree_cell * retc;
 
 if(data == NULL)
  return NULL;
 
 MD4(data, len, md);

 retc = alloc_tree_cell(0, NULL);
 retc->type = CONST_DATA;
 retc->x.str_val = strndup(md, MD4_DIGEST_LENGTH);
 retc->size = MD4_DIGEST_LENGTH;
 return retc;
}
#endif

tree_cell * nasl_md5(lex_ctxt * lexic)
{
 char * data = get_str_var_by_num(lexic, 0);
 int    len  = get_var_size_by_num(lexic, 0);
 char md[MD5_DIGEST_LENGTH+1];
 tree_cell * retc;
 
 if(data == NULL)
  return NULL;
 
 MD5(data, len, md);

 retc = alloc_tree_cell(0, NULL);
 retc->type = CONST_DATA;
 retc->x.str_val = strndup(md, MD5_DIGEST_LENGTH);
 retc->size = MD5_DIGEST_LENGTH;
 return retc;
}

tree_cell * nasl_sha(lex_ctxt * lexic)
{
 char * data = get_str_var_by_num(lexic, 0);
 int    len  = get_var_size_by_num(lexic, 0);
 char md[SHA_DIGEST_LENGTH+1];
 tree_cell * retc;
 
 if(data == NULL)
  return NULL;
 
 SHA(data, len, md);

 retc = alloc_tree_cell(0, NULL);
 retc->type = CONST_DATA;
 retc->x.str_val = strndup(md, SHA_DIGEST_LENGTH);
 retc->size = SHA_DIGEST_LENGTH;
 return retc;
}


tree_cell * nasl_sha1(lex_ctxt * lexic)
{
 char * data = get_str_var_by_num(lexic, 0);
 int    len  = get_var_size_by_num(lexic, 0);
 char md[SHA_DIGEST_LENGTH+1];
 tree_cell * retc;
 
 if(data == NULL)
  return NULL;
 
 SHA1(data, len, md);

 retc = alloc_tree_cell(0, NULL);
 retc->type = CONST_DATA;
 retc->x.str_val = strndup(md, SHA_DIGEST_LENGTH);
 retc->size = SHA_DIGEST_LENGTH;
 return retc;
}


tree_cell * nasl_ripemd160(lex_ctxt * lexic)
{
 char * data = get_str_var_by_num(lexic, 0);
 int    len  = get_var_size_by_num(lexic, 0);
 char md[RIPEMD160_DIGEST_LENGTH+1];
 tree_cell * retc;
 
 if(data == NULL)
  return NULL;
 
 RIPEMD160(data, len, md);

 retc = alloc_tree_cell(0, NULL);
 retc->type = CONST_DATA;
 retc->x.str_val = strndup(md, RIPEMD160_DIGEST_LENGTH);
 retc->size = RIPEMD160_DIGEST_LENGTH;
 return retc;
}




/*-------------------[  HMAC ]-------------------------------------*/



static tree_cell * nasl_hmac(lex_ctxt * lexic, const EVP_MD * evp_md)
{
 char * data = get_str_local_var_by_name(lexic, "data");
 char * key  = get_str_local_var_by_name(lexic, "key");
 int data_len = get_local_var_size_by_name(lexic, "data");
 int  key_len = get_local_var_size_by_name(lexic, "key");
 char hmac[EVP_MAX_MD_SIZE + 1];
 int len = 0;
 tree_cell * retc;
 
 if(data == NULL || key == NULL)
  {
  nasl_perror(lexic, "[%d] HMAC_* functions syntax is : HMAC(data:<data>, key:<key>)\n", getpid());
  return NULL;
 }
 
 HMAC(evp_md, key, key_len, data, data_len, hmac, &len);
 retc = alloc_tree_cell(0, NULL);
 retc->type = CONST_DATA;
 retc->size = len;
 retc->x.str_val = strndup(hmac, len);
 return retc;
}


#ifdef HAVE_OPENSSL_MD2_H
tree_cell * nasl_hmac_md2(lex_ctxt * lexic)
{
 return nasl_hmac(lexic, EVP_md2());
}
#endif

tree_cell * nasl_hmac_md5(lex_ctxt * lexic)
{
 return nasl_hmac(lexic, EVP_md5());
}

tree_cell * nasl_hmac_sha(lex_ctxt * lexic)
{
 return nasl_hmac(lexic, EVP_sha());
}


tree_cell * nasl_hmac_sha1(lex_ctxt * lexic)
{
 return nasl_hmac(lexic, EVP_sha1());
}


tree_cell * nasl_hmac_dss(lex_ctxt * lexic)
{
 return nasl_hmac(lexic, EVP_dss());
}


tree_cell * nasl_hmac_ripemd160(lex_ctxt * lexic)
{
 return nasl_hmac(lexic, EVP_ripemd160());
}


#endif /* HAVE_SSL */



tree_cell * nasl_ntlmv1_hash(lex_ctxt * lexic)
{
 char * cryptkey = get_str_var_by_name(lexic, "cryptkey"); 
 char * password = get_str_var_by_name(lexic, "passhash");
 int pass_len  = get_var_size_by_name(lexic, "passhash");
 unsigned char p21[21];
 tree_cell * retc;
 char * ret;
 
 if(cryptkey == NULL || password == NULL )
  {
   nasl_perror(lexic, "Syntax : ntlmv1_hash(cryptkey:<c>, passhash:<p>)\n");  
   return NULL;
  }
  

  bzero(p21, sizeof(p21));
  memcpy(p21, password, pass_len < 16 ? pass_len : 16);
  
  ret = emalloc(24);
  
  E_P24(p21, cryptkey, ret);
  retc = alloc_tree_cell(0, NULL);
  retc->type = CONST_DATA;
  retc->size  = 24;
  retc->x.str_val = ret;
  
  return retc;
}

#ifdef MD4_DIGEST_LENGTH
tree_cell * nasl_nt_owf_gen(lex_ctxt * lexic)
{
 char * pass = get_str_var_by_num(lexic, 0);
 int    pass_len = get_var_size_by_num(lexic, 0);
 tree_cell * retc;
 char md[MD4_DIGEST_LENGTH+1];
 char pwd[130];
 short upwd[130], * dst;
 short val;
 char * src;
 
 int i;
 
 
 
 
 if(pass_len < 0 || pass == NULL )
 {
   nasl_perror(lexic, "Syntax : nt_owf_gen(cryptkey:<c>, password:<p>)\n");  
   return NULL;
 }
 
 dst = upwd;
 src = pass;
 for(i = 0 ; i < pass_len ; i ++)
 {
  val = *src;  
#if __BYTE_ORDER == __BIG_ENDIAN
  *dst = val << 8;
#else
  *dst = val;
#endif
  dst ++;
  src ++;
  if(val == 0)
   break;
 }
 
 bzero(pwd, sizeof(pwd));
 memcpy(pwd, upwd, sizeof(pwd) < pass_len * 2 ? sizeof(pwd) :  pass_len * 2);
 MD4(pwd, pass_len * 2 > 128 ? 128 : pass_len * 2, md);
 
 retc = alloc_tree_cell(0, NULL);
 retc->type = CONST_DATA;
 retc->size = 16;
 retc->x.str_val = strndup(md, 16);
 return retc;
} 
#endif


tree_cell * nasl_lm_owf_gen(lex_ctxt * lexic)
{
 char * pass = get_str_var_by_num(lexic, 0);
 int    pass_len = get_var_size_by_num(lexic, 0);
 tree_cell * retc;
 char pwd[15];
 char p16[16];
 int i;
 
 
 if(pass_len < 0 || pass == NULL )
 {
   nasl_perror(lexic, "Syntax : nt_lm_gen(cryptkey:<c>, password:<p>)\n");  
   return NULL;
 }
 
 bzero(pwd, sizeof(pwd));
 strncpy(pwd, pass, sizeof(pwd) - 1);
 for(i=0;i<sizeof(pwd);i++)pwd[i] = toupper(pwd[i]);
 
 E_P16(pwd, p16);
 
 
 retc = alloc_tree_cell(0, NULL);
 retc->type = CONST_DATA;
 retc->size = 16;
 retc->x.str_val = strndup(p16, 16);
 return retc;
} 

/* Does both the NTLMv2 owfs of a user's password */
tree_cell * nasl_ntv2_owf_gen(lex_ctxt * lexic)
{
  char *owf_in = get_str_var_by_name(lexic, "owf");
  int  owf_in_len = get_var_size_by_name(lexic, "owf");
  char *user_in = get_str_var_by_name(lexic, "login");
  int  user_in_len = get_var_size_by_name(lexic, "login");
  char *domain_in = get_str_var_by_name(lexic, "domain");
  int  domain_len = get_var_size_by_name(lexic, "domain");
  char *src_user, *src_domain;
  smb_ucs2_t *user, *dst_user, val_user;
  smb_ucs2_t *domain, *dst_domain, val_domain;
  int i;	
  size_t user_byte_len;
  size_t domain_byte_len;
  tree_cell * retc;
  char * kr_buf;
  HMACMD5Context ctx;

  if(owf_in_len<0 || owf_in == NULL || user_in_len<0 || user_in == NULL || domain_len<0 || domain_in==NULL)
  {
	nasl_perror(lexic, "Syntax : ntv2_owf_gen(owf:<o>, login:<l>, domain:<d>)\n");  
	return NULL;
  }

  assert(owf_in_len==16);
  
  user_byte_len=sizeof(smb_ucs2_t)*(strlen(user_in)+1);
  user = emalloc(user_byte_len);
  dst_user = user;
  src_user = user_in;
  for(i = 0 ; i < user_in_len ; i ++)
  {
  	val_user = *src_user;
  	*dst_user = val_user;
  	dst_user ++;
  	src_user ++;
  	if(val_user == 0)
  		break;
  }
  	
  domain_byte_len=sizeof(smb_ucs2_t)*(strlen(domain_in)+1);
  domain = emalloc(domain_byte_len);
  dst_domain = domain;
  src_domain = domain_in;
  for(i = 0 ; i < domain_len ; i ++)
  {
  	val_domain = *src_domain;
	*dst_domain = val_domain;
	
  	dst_domain ++;
  	src_domain ++;
  	if(val_domain == 0)
  		break;
  }
  
  strupper_w(user);
  strupper_w(domain);
  
  assert(user_byte_len >= 2);
  assert(domain_byte_len >= 2);
  
  /* We don't want null termination */
  user_byte_len = user_byte_len - 2;
  domain_byte_len = domain_byte_len - 2;

  kr_buf=emalloc(16);
	
  hmac_md5_init_limK_to_64(owf_in, 16, &ctx);
  hmac_md5_update((const unsigned char *)user, user_byte_len, &ctx);
  hmac_md5_update((const unsigned char *)domain, domain_byte_len, &ctx);
  hmac_md5_final(kr_buf, &ctx);
  
  efree(&user);
  efree(&domain);
  
  retc = alloc_tree_cell(0, NULL);
  retc->type = CONST_DATA;
  retc->size  = 16;
  retc->x.str_val = kr_buf;
  
  return retc;
}

tree_cell * nasl_ntlmv2_hash(lex_ctxt * lexic)
{
  char * server_chal = get_str_var_by_name(lexic, "cryptkey");
  int sc_len = get_var_size_by_name(lexic, "cryptkey");
  char * ntlm_v2_hash = get_str_var_by_name(lexic, "passhash");
  int hash_len  = get_var_size_by_name(lexic, "passhash");
  int client_chal_length = get_int_var_by_name(lexic, "length", -1);
  tree_cell * retc;
  unsigned char ntlmv2_response[16];
  unsigned char* ntlmv2_client_data=NULL;
  unsigned char* final_response;
  int i;

  if(sc_len<0 || server_chal == NULL || hash_len<0 || ntlm_v2_hash == NULL || client_chal_length<0)
  {
	nasl_perror(lexic, "Syntax : ntlmv2_hash(cryptkey:<c>, passhash:<p>, length:<l>)\n");  
	return NULL;
  }
	
  /* NTLMv2 */
  
  /* We also get to specify some random data */
  ntlmv2_client_data = emalloc(client_chal_length);
  for(i=0;i<client_chal_length;i++)
  	ntlmv2_client_data[i] = rand() % 256;
	
  

  assert(hash_len==16);	
  /* Given that data, and the challenge from the server, generate a response */
  SMBOWFencrypt_ntv2(ntlm_v2_hash, server_chal, 8, ntlmv2_client_data, client_chal_length, ntlmv2_response);
  	
  /* put it into nt_response, for the code below to put into the packet */
  final_response = emalloc(client_chal_length + sizeof(ntlmv2_response));
  memcpy(final_response, ntlmv2_response, sizeof(ntlmv2_response));
  /* after the first 16 bytes is the random data we generated above, so the server can verify us with it */
  memcpy(final_response + sizeof(ntlmv2_response), ntlmv2_client_data, client_chal_length);
  
  efree(&ntlmv2_client_data);
  
  retc = alloc_tree_cell(0, NULL);
  retc->type = CONST_DATA;
  retc->size  = client_chal_length + sizeof(ntlmv2_response);
  retc->x.str_val = final_response;
  
  return retc;
}

