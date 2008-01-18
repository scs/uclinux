#include <stdio.h>

#include <stdlib.h>
#include "TestPrint.h"

int main (int argc, char *argv[])
{
    FILE *fp3;
    int ch;   
    print_init();
    /* w+ - after writing you can read file */
    if ( (fp3 = fopen("test.txt", "w+")) == NULL)
    { 
        fprintf(stderr,"Cann't open for writing\n");
        exit(EXIT_FAILURE);
    }
    
    /* Writes letters to the file */
    for (ch = 65; ch <= 90; ch++)
    { 
        putc(ch, fp3);
    }
    
    /* Skips 8 letters */
    fseek(fp3, 8L, SEEK_SET); 
    
    ch = getc(fp3);
    
    /* Changes the I to an @ */
    fseek(fp3, -1L, SEEK_CUR);
    fputc('@', fp3);
    
    fprintf(fp,"INFO : The first character is %c\n",ch);
    fprintf(stdout,"INFO : The first character is %c\n",ch);
    if(ch == 'I')    
          print_pass();
    else
	{
	print_fail();
	fprintf(fp,"FAIL : fseek is not working properly");
	fprintf(fp1,"FAIL :fseek is not working properly");
	fprintf(stdout,"FAIL :fseek is not working properly");
        
        }	

    /* Skips 16 letters, points to Q */
    fseek(fp3, 16L, SEEK_SET); 
    ch=getc(fp3);
    
    fprintf(fp,"INFO : The second character is %c\n",ch );
    fprintf(stdout,"INFO :The second character is %c\n",ch );
     if(ch == 'Q')    
          print_pass();
    else
	{
	print_fail();
	fprintf(fp,"FAIL : fseek is not working properly");
	fprintf(fp1,"FAIL : fseek is not working properly");
	fprintf(stdout,"FAIL : fseek is not working properly");
        
        }	

    
    /* Changes the I to an @ */
    fseek(fp3, -1L, SEEK_CUR);
    fputc('@', fp3);
    
    fclose(fp3);
	print_end();
    return;
}
