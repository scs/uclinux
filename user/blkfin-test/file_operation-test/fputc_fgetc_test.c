#include <stdio.h>
#include <stdlib.h>
#include "TestPrint.h"

int main (int argc, char *argv[])
{
     FILE *fptr;
     char *str = "Test string";
     char *file = "temp.txt";
     char buff[255];
     int ch;
     print_init();
	/* For write */
     if ( (fptr = fopen(file,"w") ) == NULL )
     {
          //printf("Test case 1 Failed : Cann't open temp.txt for 'w'\n");
	 print_fail();
	 fprintf(fp,"FAIL 1 : Cann't open temp.txt for 'w'\n");
         fprintf(fp1,"FAIL 1 : Cann't open temp.txt for 'w'\n");
	 fprintf(stdout,"FAIL 1 : Cann't open temp.txt for 'w'\n");
	 print_end();
	 exit(1);
     }

     fputs(str,fptr);
     fclose(fptr);

	/* For read */
     if((fptr = fopen(file,"r")) == NULL)
     {
         print_fail();
	 fprintf(fp,"FAIL 2 : Cann't open temp.txt for 'w'\n");
         fprintf(fp1,"FAIL 2 : Cann't open temp.txt for 'w'\n");
	 fprintf(stdout,"FAIL 2 : Cann't open temp.txt for 'w'\n");
	 print_end();
         //printf("Test case 2 Failed : Cann't open temp.txt for 'r'\n");
         exit(1);
     }
	
     while ( ( ch = fgetc(fptr)) != EOF )
         fputc(ch,stdout);
     fputc('\n',stdout);
 
     fclose(fptr);

	/* For read-write */

print_end();
     remove(file);

     return 0;
}
