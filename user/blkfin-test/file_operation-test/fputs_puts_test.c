#include <stdio.h>

int main (int argc, char *argv[])
{
     char *str = "Test string for puts and fputs functions... PASS";

     puts(str);
     fputs(str,stdout);
     puts("\n");

     return 0;
}
