#include <stdio.h>
#include "TestPrint.h"


int main (int argc, char *argv[])
{
    FILE * fp3;
    fpos_t pos;
    int ch;
    print_init();
    
    
    /* open file for writing + reading */
    fp3 = fopen ("test.txt","w+");

    /* cursor position */
    fprintf (fp,"INFO :Position of cursor is %lu\n",ftell(fp3));
    fprintf (stdout,"INFO :Position of cursor is %lu\n",ftell(fp3));
	if((ftell(fp3)==0))
	 print_pass();
        else
	{
	print_fail();
	fprintf(fp1,"FAIL :ftell is failing for fgetpos\n");
	fprintf(fp,"FAIL :ftell is failing for fgetpos\n");
	fprintf(stdout,"FAIL :ftell is failing for fgetpos\n");
	}
  
    
    /* save this position */
    fgetpos (fp3, &pos);

    /* writing message to the file */
    fputs ("That is a test message",fp3);
    
    	fprintf (fp,"INFO :Position of cursor is %lu\n",ftell(fp3));
	fprintf (stdout,"INFO :Position of cursor is %lu\n",ftell(fp3));
   if(ftell(fp3) == 22)
	print_pass();
   else 
	{
	   print_fail();
	   fprintf(fp,"FAIL :ftell is failing for fgetpos\n");
	   fprintf(fp1,"FAIL :ftell is failing for fgetpos\n");
	   fprintf(stdout,"FAIL :ftell is failing for fgetpos\n");
	}
    /* put cursor to the previosly saved position */
    fsetpos (fp3, &pos);
    fprintf (fp,"INFO :Position of cursor is %lu\n",ftell(fp3));
    fprintf (stdout,"INFO :Position of cursor is %lu\n",ftell(fp3));
	if (ftell(fp3) == 0)
	print_pass();
	else
	{
		print_fail();
		fprintf(fp,"FAIL :ftell is failing for fgetpos\n");
		fprintf(fp1,"FAIL :ftell is failing for fgetpos\n");
		fprintf(stdout,"FAIL :ftell is failing for fgetpos\n");
	}
    /* change contants of file ('That' for 'This') */
    fputs ("This",fp3);

    	fprintf (fp,"INFO :Position of cursor is %lu\n",ftell(fp3));
	fprintf (stdout,"INFO :Position of cursor is %lu\n",ftell(fp3));
	if(ftell(fp3) == 4)
	print_pass();
	else
	{
	 print_fail();
	 fprintf(fp,"FAIL :ftell is failing for fgetpos");
	 fprintf(fp1,"FAIL :ftell is failing for fgetpos");
	 fprintf(stdout,"FAIL :ftell is failing for fgetpos");
	}
    /* put cursor to the position '0' */
    rewind(fp3);

    /* reading the file */
    while ( (ch = fgetc(fp3)) != EOF )
    {
        fputc(ch,stdout);
    }
    puts("\n"); 
    fclose (fp3);

    /* removing the file */
    remove("test.txt");
    print_end();
    return 0;
}
