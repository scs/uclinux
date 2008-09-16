/* small demo app that just includes a cipher/hash/prng */
#include <tomcrypt.h>

int main(void)
{
   register_cipher(&rijndael_enc_desc);
   register_prng(&yarrow_desc);
   register_hash(&sha256_desc);
   return 0;
}

/* $Source: /cvs/libtom/libtomcrypt/demos/small.c,v $ */
/* $Revision: 5081 $ */
/* $Date: 2007-03-17 05:47:36 +0800 (Sat, 17 Mar 2007) $ */
