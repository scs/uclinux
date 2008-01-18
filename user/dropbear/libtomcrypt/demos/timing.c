#include <tomcrypt_test.h>

int main(void)
{

init_timer();
reg_algs();

#ifdef USE_LTM
   ltc_mp = ltm_desc;
#elif defined(USE_TFM)
   ltc_mp = tfm_desc;
#elif defined(USE_GMP)
   ltc_mp = gmp_desc;
#else
   extern ltc_math_descriptor EXT_MATH_LIB;
   ltc_mp = EXT_MATH_LIB;
#endif

time_keysched();
time_cipher();
time_cipher2();
time_cipher3();
time_cipher4();
time_hash();
time_macs();
time_encmacs();
time_prng();
time_mult();
time_sqr();
time_rsa();
time_ecc();
#ifdef USE_LTM
time_katja();
#endif
return EXIT_SUCCESS;

}

/* $Source: /cvs/libtom/libtomcrypt/demos/timing.c,v $ */
/* $Revision: 5081 $ */
/* $Date: 2007-03-16 22:47:36 +0100 (Fri, 16 Mar 2007) $ */
