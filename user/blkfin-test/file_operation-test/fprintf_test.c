#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "TestPrint.h"

int main (int argc, char *argv[])
{
   print_init();
     int i          = 100;
     FILE *fp3;
     unsigned int u = 250;
     float f        = 12.5;
     double d       = 2.897653;
     char ch        = 'A';
     char ary[]     = "Array string";
     char *str      = "justify";
     char *p;
     p = ary;
     
     if ((fp3=fopen("w.log","w"))==NULL)
        printf("FAIL: The test file w.log is not getting opened");

     // The user will see this text when doing cat w.log
     fprintf (fp3,"PASS: opening and writing in w mode works\n");	

     fprintf (fp3,"Integer i = %d\n", i);
     fprintf (fp3,"Unsigned u = %d\n", u);
     fprintf (fp3,"Float f = %f\n", f);
     fprintf (fp3,"Double d = %.2lf\n", d);
     fprintf (fp3,"Scientific notation d = %e\n", d);
     fprintf (fp3,"Char ch = %c\n", ch);
     fprintf (fp3,"Array string is: %s\n", ary);
     fprintf (fp3,"Address of ary is: %p\n", p);

     fprintf (fp3,"Left %s\n", str);
     fprintf (fp3,"Right %20s\n",str);

     fprintf (fp3,"%-*s %s\n",20,"%-*s %s","test string");
     fprintf (fp3,"%*s %s\n",20,"%*s %s","test string");
     fprintf (stdout,"Integer i = %d\n", i);
     fprintf (stdout,"Unsigned u = %d\n", u);
     fprintf (stdout,"Float f = %f\n", f);
     fprintf (stdout,"Double d = %.2lf\n", d);
     fprintf (stdout,"Scientific notation d = %e\n", d);
     fprintf (stdout,"Char ch = %c\n", ch);
     fprintf (stdout,"Array string is: %s\n", ary);
     fprintf (stdout,"Address of ary is: %p\n", p);

     fprintf (stdout,"Left %s\n", str);
     fprintf (stdout,"Right %20s\n",str);

     fprintf (stdout,"%-*s %s\n",20,"%-*s %s","test string");
     fprintf (stdout,"%*s %s\n",20,"%*s %s","test string");

  print_end();
     return 0;
}
