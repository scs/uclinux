#include <stdio.h>
#include "TestPrint.h"

int main (int argc, char *argv[])
{
     FILE *fp3;
     char *msg = "Testing rewind function";
     long lon;
     char buff[1024];
     print_init();
      
     fp3 = fopen("test.txt","w");

     fputs(msg, fp3);

     fclose(fp3);

     fp3 = fopen("test.txt","r");

     lon = ftell(fp3);
     fprintf (fp,"INFO: After opening file position = %lu\n",lon);
     fprintf (stdout,"INFO: After opening file position = %lu\n",lon);

     /* read 'Testing ' */
     fgets(buff,9,fp3);
     fputs(buff,stdout);
     puts("");
         
     lon = ftell(fp3);
     fprintf (fp,"INFO: After reading 8 char position =  %lu\n",lon);
     fprintf (stdout,"INFO: After reading 8 char position =  %lu\n",lon);
     
     /* read next 5 char */
     fgets(buff,7,fp3);
     fputs(buff,stdout);
     puts("");
     
     lon = ftell(fp3);
     fprintf (fp,"INFO: Reading next 6 char, position = %lu\n",lon);
     fprintf (stdout,"INFO: Reading next 6 char, position = %lu\n",lon);

     /* puts pointer to the very beginning of the file */
     rewind(fp3);

     lon = ftell(fp3);
     
     if(ftell(fp3) == 0 ) {
	print_pass();
	fprintf (fp,"PASS: After rewind position = %lu\n",lon);
	fprintf (stdout,"PASS: After rewind position = %lu\n",lon);
     } else {
	print_fail();
	fprintf(fp,"FAIL: The rewind function is not working");
	fprintf(stdout,"FAIL: The rewind function is not working");
	fprintf(fp1,"FAIL: The rewind function is not working");
	}
     /* reads hole message from file */
     fgets (buff, strlen(msg)+1 ,fp3);
     fputs (buff,stdout);
     puts("");

     lon = ftell(fp3);

     if(ftell(fp3) == 23) {
	print_pass();
	fprintf (fp,"PASS: After reading whole file position = %lu\n",lon);
	fprintf (stdout,"PASS: After reading whole file position = %lu\n",lon);
     } else {
	print_fail();
	fprintf(fp,"FAIL: The rewind function is not working");
	fprintf(fp1,"FAIL: The rewind function is not working");
	fprintf(stdout,"FAIL: The rewind function is not working");
	}
	
     print_end();
     fclose(fp3);
     return 0;
}
