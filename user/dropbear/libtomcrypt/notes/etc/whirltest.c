#include <stdio.h>

int main(void)
{
   char buf[4096];
   int x;
   
   while (fgets(buf, sizeof(buf)-2, stdin) != NULL) {
        for (x = 0; x < 128; ) {
            printf("0x%c%c, ", buf[x], buf[x+1]);
            if (!((x += 2) & 31)) printf("\n");
        }
   }
}


/* $Source: /cvs/libtom/libtomcrypt/notes/etc/whirltest.c,v $ */
/* $Revision: 5081 $ */
/* $Date: 2007-03-17 05:47:36 +0800 (Sat, 17 Mar 2007) $ */
