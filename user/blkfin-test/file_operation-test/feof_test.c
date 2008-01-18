#include <stdio.h>
#include <stdlib.h>

#include "TestPrint.h"

int main (int argc, char *argv[])
{
     FILE *fp3;
     int c;
     int ret = 0;
      print_init();
   
     fp3 = fopen("eof.txt","w+");
	system("chmod 777 eof.txt");
	fprintf(fp3,"abcdefghijklmnopqrstuvwxyz");
 sleep(1);
	rewind(fp3);
     fprintf(stdout,"INFO :Initial File position  = %d\n",ftell(fp3));
     fprintf(fp,"INFO :Initial File position  = %d\n",ftell(fp3));
     //printf("Initial File position  = %d\n",ftell(fp3));
     fprintf(stdout, "INFO: Return value of feof() before calling in a loop is = %d\n",feof(fp3));
     fprintf(fp, "INFO: Return value of feof() before calling in a loop is = %d\n",feof(fp3));
     //printf("Return value of feof() before calling in a loop is = %d\n",feof(fp3));
     fprintf(fp,"INFO :Return value of feof() before calling in a loop is = %d\n",feof(fp3));
     fprintf(stdout,"INFO :Return value of feof() before calling in a loop is = %d\n",feof(fp3));

     if((ftell(fp3)==0)&&(feof(fp3)==0))
        {
	print_pass();	
	//printf ("Passed 1\n");
	fprintf (fp,"PASS 1\n");
	fprintf (stdout,"PASS 1\n");
	}
     else
        {
	fprintf(stdout,"FAIL :ftell and feof is failing\n");
	fprintf(fp,"FAIL :ftell and feof is failing\n");
	fprintf(fp1,"FAIL :ftell and feof is failing\n");
	//printf("ftell and feof is failing\n");
	//fprintf(stderr,"ftell and feof is failing\n");
	//printf("ftell and feof is failing\n");
	//printf ("Test is failed 1 \n");
	// print_fail();
	}
     while ( !(ret = feof(fp3)) )
     {
	c = getc(fp3);
     }
     // fprintf(stdout, "Final File position  = %d\n",ftell(fp3));
     //printf("Final File position  = %d\n",ftell(fp3));
     fprintf(fp,"INFO :Final File position  = %d\n",ftell(fp3));
     fprintf(stdout,"INFO :Final File position  = %d\n",ftell(fp3));
     // fprintf(stdout,"Return value of feof() after calling in a loop is = %d\n",ret);
     //printf("Return value of feof() after calling in a loop is = %d\n",ret);
     fprintf(fp,"INFO :Return value of feof() after calling in a loop is = %d\n",ret);
     fprintf(stdout,"INFO :Return value of feof() after calling in a loop is = %d\n",ret);

    if((ftell(fp3)==26)&&(feof(fp3)!= 0))
     	{
	 print_pass();
    	 //printf("Passed 2 \n");
    	 fprintf(fp,"PASS 2 \n");
    	 fprintf(stdout,"PASS 2 \n");
	}
   else
	{
	 print_fail();		
	//fprintf ("Test is failed 2 \n");
	fprintf(stdout,"FAIL :ftell and feof is failing\n");
	fprintf(fp,"FAIL : and feof is failing\n");
	//fprintf(stderr,"ftell and feof is failing\n");
	fprintf(fp1,"FAIL :ftell and feof is failing\n");
	}
     fclose(fp3);
     // print_end();
     //printf ("Test End \n");
     fprintf (fp,"INFO :Test End \n");
     fprintf (stdout,"INFO :Test End \n");
     return 0;

}
