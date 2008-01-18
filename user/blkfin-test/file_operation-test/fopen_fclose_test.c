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
	/* For write */
     if ( (fptr = fopen(file,"w") ) == NULL )
     {
	
    	 print_init();
	 print_fail();
         fprintf(fp1,"FAIL 1 : Cann't open temp.txt for 'w'\n");
         fprintf(fp,"FAIL 1 : Cann't open temp.txt for 'w'\n");
	 fprintf(stdout,"FAIL 1 : Cann't open temp.txt for 'w'\n");
         print_end();
         exit(1);
     }
     else
	{	
    	print_init();
	print_pass();	
	fprintf(fp,"PASS 1 : fopen() for 'w' successful\n");
	fprintf(stdout,"PASS 1 : fopen() for 'w' successful\n");
        print_end();
	}

     fputs(str,fptr);
     fclose(fptr);

	/* For read */
     if((fptr = fopen(file,"r")) == NULL)
     {
	 
    	print_init();
	 print_fail();
         fprintf(fp,"FAIL 2 : Cann't open temp.txt for 'r'\n");
         fprintf(fp1,"FAIL 2  : Cann't open temp.txt for 'r'\n");
	 fprintf(stdout,"FAIL 2 : Cann't open temp.txt for 'r'\n");
        print_end();
         exit(1);
     }
     else
	{
    	print_init();
	print_pass();
	fprintf(fp,"PASS 2 : fopen() for 'r' successful\n");
	fprintf(stdout,"PASS 2 : fopen() for 'r' successful\n");
	
        print_end();
	
	}
     while ( ( ch = fgetc(fptr)) != EOF )
         fputc(ch,stdout);
     fputc('\n',stdout);
 
     fclose(fptr);

	/* For read-write */
     if((fptr = fopen(file,"rw")) == NULL)
     {
    	print_init();
	print_fail();
        fprintf(fp,"FAIL 3 : Cann't open temp.txt for 'rw'\n");
        fprintf(fp1,"FAIL 3 : Cann't open temp.txt for 'rw'\n");
	fprintf(stdout,"FAIL 3 : Cann't open temp.txt for 'rw'\n");
        print_end();
        exit(1);
     }
     else
	{
    	print_init();
	print_pass();
	fprintf(fp,"PASS 3 : fopen() for 'rw' successful\n");
        fprintf(stdout,"PASS 3 : fopen() for 'rw' successful\n");
	print_end();
	}
     fclose(fptr);

	/* For append */
     if((fptr = fopen(file,"a")) == NULL)
     {
    	print_init();
	print_fail();
        fprintf(fp,"FAIL 4 : Cann't open temp.txt for 'a'\n");
        fprintf(fp1,"FAIL 4 : Cann't open temp.txt for 'a'\n");
	fprintf(stdout,"FAIL 4 : Cann't open temp.txt for 'a'\n");
        print_end();
         exit(1);
     }
     else
	{
    	print_init();
	print_pass();
	fprintf(fp,"PASS 4: fopen() for 'a' successful\n");
	fprintf(stdout,"PASS 4: : fopen() for 'a' successful\n");
        print_end();
	}
	/* close() */
     if(fclose(fptr))
	{
    	print_init();
	print_fail();
	fprintf(fp,"FAIL 5: fclose() error\n");
	fprintf(fp1,"FAIL 5 : fclose() error\n");
	fprintf(stdout,"FAIL 5: fclose() error\n");
        print_end();
	} 
    else
	{
    	print_init();
	print_pass();
	fprintf(fp,"PASS 5 : fclose() successful\n");
	fprintf(stdout,"PASS 5 : fclose() successful\n");
        print_end();
	}

     if(fread(buff, sizeof(char), 10, fptr ) == 0)
	{
    	print_init();
	print_pass();
	fprintf(fp,"PASS 6 : fread error as expected\n");
	fprintf(stdout,"PASS 6 : fread error as expected\n");
        print_end();
     	}
	else
	{
    	print_init();
	print_fail();
	fprintf(fp1,"FAIL 6 : fread read from the Closed file\n");
        fprintf(stdout,"FAIL 6 : fread read from the Closed file\n");
	print_end();
	 
	}
     remove(file);

     return 0;
}
