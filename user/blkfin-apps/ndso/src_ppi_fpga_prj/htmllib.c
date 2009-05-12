/* htmllib.c
 * HTML common library functions for the CGI programs. */

#include <stdio.h>
#include "htmllib.h"


void
htmlHeader (char *title)
{
  printf ("Content-type: text/html\n\n<HTML><HEAD><TITLE>%s</TITLE></HEAD>",
	  title);
}

void
htmlHeaderText (char *title)
{
  printf ("Content-type: text/plain\n\n<HEAD><TITLE>%s</TITLE></HEAD>",
	  title);
}


void
htmlHeaderRefresh ()
{
  printf ("<meta http-equiv=\"Refresh\" content=\"0\">\n");
}

void
htmlHeaderExpires (char *title)
{
  printf
    ("Content-type: text/html\n\n<HTML><HEAD><TITLE>%s</TITLE>\n<meta http-equiv=\"Expires\" CONTENT=\"0\"></HEAD>",
     title);
}

void
htmlHeaderNocache (char *title)
{
  printf
    ("Content-type: text/html\n\n<HTML><HEAD>\n<META HTTP-EQUIV=\"PRAGMA\" CONTENT=\"NO-CACHE\"><meta http-equiv=\"Expires\" CONTENT=\"-1\">\n<TITLE>%s</TITLE>\n</HEAD>",
     title);
}



void
htmlBody ()
{
  printf ("<BODY>");
}

void
htmlFooter ()
{
  printf ("</BODY></HTML>");
}

void
addTitleElement (char *title)
{
  printf ("<H1>%s</H1>", title);
}
