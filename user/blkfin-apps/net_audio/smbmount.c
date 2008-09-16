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

int findProcess(char *aucString);
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

	// Query String Processing

	cgiGetenv(&cgiQueryString, "QUERY_STRING"); //Get the Query String

	if(cgiQueryString != NULL)	
		r = ParseQueryString(cgiQueryString);  //Parse the QueryString and create Parameter[]


	// Posted Data Processing
	//printf("Mounting the Remote shared directory : %s\r\n", cgiQueryString);
	fprintf(stderr,"Mounting the Remote shared directory : %s\r\n", cgiQueryString);
	if(len1 != NULL)
		l_content_lenght = atol(len1);
	//if (len1 != NULL)
	if (l_content_lenght > 0)
	{
		contentlength=strtol(len1, &endptr, 10);

		/* Source buffer is allocated and the content is read from the stdin*/
		SourceBuffer = calloc(contentlength, sizeof(char));
		fread(SourceBuffer, contentlength, 1, stdin);
		//printf("SourceBuffer %s\r\n", SourceBuffer);
		user = strtok(SourceBuffer, "&");
		psswd = strtok(NULL, "&");
		
		mount(cgiQueryString, user,psswd);
	}
	else
	{ 
		//printf("<B>PP.CGI: NO POSTED DATA RECEIVED</B> <BR>");
	}

	return 0;
}

/*----------------------------------------------------------------------

Function name			:	ParseQueryString
Description				:	It parse the Query String for "," and stores each parameter in char *Parameter[]
Parameters				:	char *QS
Global variables used	:	(char *)Parameter[100]
Return type				:	int

----------------------------------------------------------------------*/

int ParseQueryString(char *QS)
{
	int loop;
	int r;
	char *cFile2;
		
	if ((r = StringCompare(QS, "")) == 0)
	{
		//printf("%s%c%c\n", "Content-Type:text/html;charset=Unicode(UTF-8)",13,10);
		//printf("Please Specify File Name to Parse");
		//r = ParseHtml("login.html");
		return 0;
	}

	Parameter[0]=strtok(QS,",");
		
	if(Parameter[0]==NULL)
	{
		printf("Not found.\n");
		exit(0);
	}

	for(loop=1;loop<10;loop++)
	{
		Parameter[loop]=strtok(NULL,",");
		if(Parameter[loop]==NULL)
			break;
	}


	return 0;

}


static void cgiGetenv(char **s, char *var){
	*s = getenv(var);
	if (!(*s)) {
		*s = "";
	}
}

int StringCompare(char *s, char *t)
{
	if (s == NULL)
	{
		return -1;
	}
	for ( ; *s == *t; s++, t++)
		if (*s == '\0')
		{
			return 0;
		}
		return *s - *t;
}
#if 0
int mount( char *url, char *user, char *passwd)
{
char str[512];
//char *str1="<html><title>NetAudio</title><LINK href=/mpd.css rel=stylesheet>\r\n<script>function hello(){document.getElementById('scrap').style.display = 'none';}</script><body onLoad=hello();>\r\n<br><center><a class=lnk href='/cgi-bin/csamba.cgi'>Check Samba Status</a></center>\r\n<div id=scrap style='position:absolute; z-index:-1000;top:1px; left:1px; width:0px; height:0px;visibility=hidden;'>\r\n</div>";
//char *str2="<center><br>Samba Mount : Done...<br></center>\r\n<br></center></body></html>";

//printf("Content-Length: %d\r\n",strlen(str1) + strlen(str2));
printf("Content-Length: %d\r\n",464);
printf("\r\n");
printf("<html><title>NetAudio</title><LINK href=/mpd.css rel=stylesheet>");

printf("<script>function hello(){document.getElementById('scrap').style.display = 'none';}</script><body onLoad=hello();>");
printf("<br><center><a class=lnk href='/cgi-bin/csamba.cgi'>Check Samba Status</a></center>");
printf("<div id=scrap style='position:absolute; z-index:-1000;top:1px; left:1px; width:0px; height:0px;visibility=hidden;'>");
printf( "</div>");
printf("</div>");

//printf("%s\r\n", str1);
if (user == NULL && passwd == NULL )
        printf("QUERY_STRING : Failed, Reload the Image");
else
{
	sprintf(str, "smbmount %s /mnt -o %s,%s", url, user, passwd);
	//printf("%s", str);
    //system("smbmount $QUERY_STRING /mnt -o $FULLUSR,$FULLPWD");
    system(str);
	printf("<center><br>Samba Mount : Done...<br></center>");
}

//printf("%s\r\n", str2);
printf("<br></center></body></html>");
return 0;
}
#endif
#if 1
int mount( char *url, char *user, char *passwd)
{
int r;
char str[512];
char *str1="<html><title>NetAudio</title><LINK href=/mpd.css rel=stylesheet>\r\n<script>function hello(){document.getElementById('scrap').style.display = 'none';}</script><body onLoad=hello();>\r\n<br><center><a class=lnk href='/cgi-bin/csamba.cgi'>Check Samba Status</a></center>\r\n<div id=scrap style='position:absolute; z-index:-1000;top:1px; left:1px; width:0px; height:0px;visibility=hidden;'>\r\n</div>";
char *str2="<center><br>Samba Mount : Done...<br></center>\r\n<br></center></body></html>";
char *str3="<center><br>Samba Mount : Failed.<br></center>\r\n<br></center></body></html>";

//printf("Content-Length: %d\r\n",strlen(str1)+strlen(str2)+strlen(str2));
printf("%s\r\n", str1);
if (user == NULL && passwd == NULL )
        printf("QUERY_STRING : Failed, Reload the Image");
else
{
	sprintf(str, "smbmount %s /mnt -o %s,%s", url, user, passwd);
    system(str);
}

r = findProcess("smbmount_child");
if(r != -1)
	printf("%s\r\n", str2);
else
	printf("%s\r\n", str3);
//printf("%s\r\n", str2);
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


#endif
