#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "TestPrint.h"
int main (int argc, char *argv[])
{
     char buff[255];
     FILE *fp;
     char *sstr = "xyzzy";
     char *str = "abcdefgxyzzy";
     int len = 0;
     print_init();
     if((fp = fopen("test.txt","w")) == NULL)
     {
	//printf(" 1 test.txt open error\n");
	print_fail();
	fprintf(fp,"FAIL 1: test.txt open error\n");
	fprintf(fp1,"FAIL 1: test.txt open error\n");
	fprintf(stdout,"FAIL 1: test.txt open error\n");
	print_end();
	exit(1);
     }

     fputs(str,fp);
     fclose(fp);
     if((fp = fopen("test.txt","r")) == NULL)
     {
	//printf("2 test.txt open error\n");
	print_fail();
	fprintf(fp,"FAIL 2: test.txt open error\n");
	fprintf(fp1,"FAIL 2: test.txt open error\n");
	fprintf(stdout,"FAIL 2: test.txt open error\n");
	print_end();
	exit(1);
     }

     fgets(buff,15,fp);
     len = strlen(buff);
     if((strcmp(buff+len-5,sstr)) == 0)
         {
	 //printf("Test Passed\n");
	 print_pass();
	 fprintf(fp,"PASS:\n");
	 fprintf(stdout,"PASS:\n");
	 }
     else
     	{
	 //printf("Test Failed\n");
	 fprintf(fp,"FAIL :Test\n");
	 fprintf(fp1,"FAIL :Test\n");
	 fprintf(stdout,"FAIL :Test\n");
	 }
     fclose(fp);
     print_end();
     return 0;
}
