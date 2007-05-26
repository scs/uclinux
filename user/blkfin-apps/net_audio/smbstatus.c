/*----------------------------------------------------------------------

parsehtml.c file
cgi library implementation file
Copyright (c) Mistletoe Technologies, Inc., USA.
All rights reserved

Written by Kasi for red-hat linux (version: 2.4.20-8)
-----------------------------------------------------------------------
while viewing in vi/vim editor, use ts=4
-----------------------------------------------------------------------
Inputs - HTML NAME,SCREEN ID,FROM HTML,TO HTML

----------------------------------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "cgi-pro.h"

int mount( char *url, char *user, char *passwd);
/* Functions Used */

int StringCompare(char *s, char *t);
static void cgiGetenv(char **s, char *var);
/* Query String Processing */

int ParseQueryString(char *);
char *cgiQueryString=NULL;
char *Parameter[10];
char *SourceBuffer; //Buffer of source raw data posted

//char *CurrentLanguage;

int main()
{

	int r;
	char *endptr;
	long contentlength;
	char *user=NULL, *psswd=NULL;

	const char *len1 = getenv("CONTENT_LENGTH");

	long l_content_lenght=0;

	// ----------------
	printf("%s\r\n\r\n", "Content-Type:text/html");

	printf("<html><title>NetAudio</title><LINK href=/mpd.css rel=stylesheet>\r\n");
	r = findProcess("smbmount_child");
	if(r != -1)
		printf("<center>Samba Mount found.</center>\r\n");
	else
		printf("<center>Samba Mount not found.</center>\r\n");
	printf("<center><br>Samba Status</center><br></body></html>\r\n");
	return 0;
}


int findProcess(char *aucString)
{
 int bFlag=0,iCnt,iCnt1,iCnt2;
 char aucBuff[100];
 char aucTemp[100];
 FILE *fp;
 //printf("*****Start of find Process\n*****");
 system("ps -ax > /tmp/process.tmp");
    fp = fopen("/tmp/process.tmp", "r");
    if(fp == NULL)
      {
        printf("Unable to open file\n");
        return -1;
      }
    while(fgets(aucBuff, sizeof(aucBuff), fp) != NULL)
    {
        if(strstr(aucBuff, aucString)!= NULL)
        {
            if(strstr(aucBuff, "Z") == NULL)
            {
                bFlag = 1;
                break;
            }
            else
              {
                fclose(fp);
                return -1;
              }
        }
    }
    fclose(fp);
    unlink("/tmp/process.tmp");
    if(bFlag)
    {
        iCnt = 0;
        iCnt2 = 0;
        while(aucBuff[iCnt++] == ' ');
        for(iCnt1=iCnt-1;; iCnt1++)
        {
            if(aucBuff[iCnt1] != ' ')
                aucTemp[iCnt2++] = aucBuff[iCnt1];
            else
            {
                aucTemp[iCnt2] = '\0';
                break;
            }
        }
        return (atoi(aucTemp));
    }
    else
        return -1;

}

 
