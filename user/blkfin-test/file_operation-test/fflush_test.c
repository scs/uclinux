#include <stdio.h>
#include <stdlib.h>
#include "TestPrint.h"

int main (int argc, char *argv[])
{
    print_init();
    FILE *phone_p;
    char *name[] = { "Robert Smith",
        "Linda Bain","Ivan Mazepa", NULL };
    char *phone[] = { "345-3455",
        "123-9876","987-3456", NULL };
    int i = 0;
    char buff[255];

    if ( ferror ( phone_p = fopen("phone.dat","w")) )
    {
       print_fail();
        fprintf(fp,"Cann't open for writing\n");
	fprintf(fp1,"Cann't open for writing\n");
	fprintf(stdout,"Cann't open for writing\n");
	//perror("Cann't open for writing\n");
	print_end();
        exit(EXIT_FAILURE);
    }

    for ( ; i < 3; i++ )
    {
        sprintf(buff,"%d:%s:%s\n",i+1,name[i],phone[i]);
        fputs(buff,phone_p);
	fputs(stdout,phone_p);
        fflush(phone_p);
        //  fflush(NULL) - flushes all opened stream for output
    }

    //  reopen for reading
/*    freopen ("phone.dat","r",phone_p);
    {
        while ( fgets(buff,254,phone_p) )
            fprintf(stdout,"%s",buff);
    }
*/
    fclose(phone_p);
    phone_p = fopen ("phone.dat","r");
    {
        while ( fgets(buff,254,phone_p) )
		{
            fprintf(fp,"%s",buff);
            fprintf(stdout,"%s",buff);
		}
    }
    

    fclose(phone_p);
//    remove("phone.dat");
    print_end();
    return 0;
}
