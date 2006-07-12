#include <stdio.h>
#include <stdlib.h>
#include "TestPrint.h"

int main (int argc, char *argv[])
{
     FILE *in;
     char f_name[25],
           l_name[25],
          phone [25];
     int num;

//     system("head -1 report.dat");
//     puts("");

    print_init();	
     in = fopen("report.dat","w");
     if(in == NULL)
     {
        print_fail();
     	//printf("fopen() error : write \n");	
     	fprintf(fp,"FAIL :fopen() error : write \n");	
     	fprintf(fp1,"FAIL :fopen() error : write \n");	
     	fprintf(stdout,"FAIL :fopen() error : write \n");	
        print_end(); 
	exit(1);
     }
     fputs(" 1 Linda Bain 123-3455\n 2 Robert Smith 345-9877\n 3 Ivan Mazepa 456-9870\n",in);
     fclose(in);
	
     in = fopen("report.dat","r");
     if(in == NULL)
     {
	print_fail();
     	//printf("fopen() error : read \n");	
     	fprintf(fp,"FAIL :fopen() error : read\n");	
     	fprintf(fp1,"FAIL :fopen() error : read\n");	
     	fprintf(stdout,"FAIL :fopen() error : read\n");	
	print_end();
	exit(1);
     }
     while ( (fscanf(in,"%d%s%s%s",&num,
                 f_name,l_name,phone)) == 4 )
     {
         fprintf (stdout,"%04d  %-12s %-12s %s\n",num,
                 f_name,l_name,phone);
     }

     fclose(in);
	print_end();
     return 0;
}
