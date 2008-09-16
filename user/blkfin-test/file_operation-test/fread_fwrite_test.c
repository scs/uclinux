#include <stdio.h>
#include <stdlib.h>
#include "TestPrint.h"

int main (int argc, char *argv[])
{
     FILE *ptr;
     int len;
     char buff[1024];
     char *str = "Testing string for fread and fwrite functions... PASS\n";
     print_init();
     if ( (ptr = fopen("test.txt","wb")) == NULL )
     {
	print_init();
	print_fail();
        fprintf (fp,"FAIL: Can't open for writing\n");
        fprintf (stdout,"FAIL: Can't open for writing\n");
	fprintf (fp1,"FAIL: Can't open for writing\n");
	print_end();
        exit(EXIT_FAILURE);
     }

     len = strlen(str);

     if ( fwrite(str, sizeof(char), len, ptr ) != len )
     {
	 print_init();
	 print_fail();
         fprintf(fp,"FAIL: writing to file\n");
         fprintf(stdout,"FAIL: writing to file\n");
	 fprintf(fp1,"FAIL: writing to file\n");
	 print_end();
         exit(EXIT_FAILURE);
     }
     fclose(ptr);

     if ( (ptr = fopen("test.txt","rb")) == NULL )
     {
	print_init();
	print_fail();
        fprintf (fp,"FAIL: Can't open for reading\n");
        fprintf (fp1,"FAIL: open for reading\n");
	fprintf (stdout,"FAIL: Can't open for reading\n");
	print_end();
         exit(EXIT_FAILURE);
     }

     if ( fread(buff, sizeof(char), len, ptr ) != len )
     {
	print_init();
	print_fail();
        fprintf(fp,"FAIL: reading file\n");
        fprintf(fp1,"FAIL: reading file\n");
	fprintf(stdout,"FAIL: reading file\n");
	print_end();
         exit(EXIT_FAILURE);
     }
     fclose(ptr);
     print_init();
     fputs(buff,fp);
     fputs(buff,stdout);
     print_end();
     return 0;
}
