#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main (int argc, char *argv[])
{
     char buff[255];
     char *name;
     char *id;

     printf ("Enter a string (up to 24 chars): ");
     fgets  (buff,25,stdin);
     buff[strlen(buff)-1] = '\0';


     name = (char*)malloc(strlen(buff)+1);
     strcpy(name,buff);

     printf ("\nEnter another string (up to 4 chars): ");
     fgets  (buff,5,stdin);

     //id = strtod(buff,(char **)NULL);
     id = (char*)malloc(strlen(buff)+1);
     strcpy(id,buff);
     
     printf ("\nstring 1: %s\nstring 2: %s\n", name, id);

     free(name);
     
     return 0;
}
