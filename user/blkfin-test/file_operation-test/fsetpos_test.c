#include <stdio.h>
#include "TestPrint.h"

int main (int argc, char *argv[])
{
    FILE *fp3;
    fpos_t pos;
    int ch;
    print_init();

    /* open file in write-read mode */
    fp3 = fopen("test.txt","w+");

    /* write message to the file */
    fputs("first line\n",fp3);

    if(ftell(fp3) == 11) {
	print_pass();
	fprintf(fp,"PASS: cursor position is  %lu\n",ftell(fp3));
	fprintf(stdout,"PASS: cursor position is  %lu\n",ftell(fp3));

    } else {
	print_fail();
	fprintf(fp,"FAIL: The ftell is failing for fsetpos");
	fprintf(fp1,"FAIL: The ftell is failing for fsetpos");
	fprintf(stdout,"FAIL: The ftell is failing for fsetpos");
	}
   
    /* save current position */
    fgetpos(fp3,&pos);

    /* put cursor to the very beginning of file */
    rewind(fp3);

    if(ftell(fp3) == 0) {
	print_pass();
	fprintf (fp,"PASS: After rewind -  position is %lu\n",ftell(fp3));
	fprintf (stdout,"PASS: After rewind -  position is %lu\n",ftell(fp3));
    } else {
	print_fail();
        fprintf(fp,"FAIL: The ftell is failing for fsetpos");
        fprintf(fp1,"FAIL: The ftell is failing for fsetpos");
        fprintf(stdout,"FAIL :The ftell is failing for fsetpos");
        }
    /* put cursor to seved position */
    fsetpos (fp3,&pos);

    fprintf (fp,"INFO : After fsetpos - position is %lu\n",ftell(fp3));

    if(ftell(fp3) == 11) {
	print_pass();
	fprintf (fp,"PASS: After fsetpos - position is %lu\n",ftell(fp3));
	fprintf (stdout,"PASS: After fsetpos - position is %lu\n",ftell(fp3));
   } else {
	print_fail();
	fprintf(fp,"FAIL:The ftell is failing for fsetpos");
	fprintf(fp1,"FAIL: The ftell is failing for fsetpos");
	fprintf(stdout,"FAIL: The ftell is failing for fsetpos");
	}
    /* write message to the file */
    fputs("second line\n",fp3);

    if(ftell(fp3) == 23) {
	print_pass();
	fprintf (fp,"PASS: After writing - position is %lu\n",ftell(fp3));
	fprintf (stdout,"PASS: After writing - position is %lu\n",ftell(fp3));
    } else{
	print_fail();
	fprintf(fp,"FAIL: The ftell is failing for fsetpos");
	fprintf(fp1,"FAIL: The ftell is failing for fsetpos");
	fprintf(stdout,"FAIL: The ftell is failing for fsetpos");
	}
    /* save current position */
    fgetpos(fp3,&pos);

    /* put cursor to the very beginning of file */
    rewind(fp3);

    if(ftell(fp3) ==0) {
	print_pass();
	fprintf (fp,"PASS: After rewind -  position is %lu\n",ftell(fp3));
	fprintf (stdout,"PASS: After rewind -  position is %lu\n",ftell(fp3));
    } else {
	print_fail();
	fprintf(fp,"FAIL: The ftell is failing for fsetpos");
	fprintf(fp1,"FAIL: The ftell is failing for fsetpos");
	fprintf(stdout,"FAIL: The ftell is failing for fsetpos");
	}
    /* put cursor to seved position */
    fsetpos (fp3,&pos);
    
    if(ftell(fp3)==23) {
	print_pass();
	fprintf (fp,"PASS: After fsetpos - position is %lu\n",ftell(fp3));
	fprintf (stdout,"PASS: After fsetpos - position is %lu\n",ftell(fp3));
    } else {
	print_fail();
	fprintf(fp,"FAIL: The ftell is failing for fsetpos");
	fprintf(fp1,"FAIL: The ftell is failing for fsetpos");
	fprintf(stdout,"FAIL: The ftell is failing for fsetpos");
         }
    /* write message to the file */
    fputs("third line\n",fp3);

    if(ftell(fp3)==34) {
	print_pass();
	fprintf (fp,"PASS: After writing - position is %lu\n",ftell(fp3));
	fprintf (stdout,"PASS: After writing - position is %lu\n",ftell(fp3));
    } else {
	print_fail();
	fprintf(fp,"FAIL: The ftell is failing for fsetpos");
	fprintf(fp1,"FAIL: The ftell is failing for fsetpos");
	fprintf(stdout,"FAIL: The ftell is failing for fsetpos");
	}
	
    /* put cursor to the very beginning of file */
    rewind(fp3);
   
    fprintf(fp,"\nContents of file:\n");
    fprintf(stdout,"\nContents of file:\n");

    /* read file */
    while ( (ch = fgetc(fp3)) != EOF )
	{
        fputc(ch, fp);
        fputc(ch, stdout);
	}
    fclose(fp3);
    remove("test.txt");
  print_end();
    return 0;
}
