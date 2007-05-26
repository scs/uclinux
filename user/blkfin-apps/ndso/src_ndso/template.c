/* template.c */

#include <stdio.h>

#include "cgivars.h"
#include "htmllib.h"


#define DEBUG		1

int
template_page (char **postvars, int form_method)
{
  int i;

  addTitleElement ("Blackfin CGI Demo");

  if (form_method == POST)
    {
      for (i = 0; postvars[i]; i += 2)
	{
#if DEBUG
	  printf ("<li>DEBUG: [%s] = [%s]\n", postvars[i], postvars[i + 1]);
#endif
	}
    }


//sleep(10);

//printf("<p><img border=\"0\" src=\"images/grid1.bmp\" width=\"624\" height=\"408\"></p>");


  /* GET */
/*	printf("<FORM ACTION=\"%s\" METHOD=POST>", "/cgi_demo.cgi");
	printf("<SELECT NAME=\"port\">");
	printf("<OPTION>BF533");
	printf("<OPTION>BF535");
	printf("</SELECT>");
	printf("</TD></TR>");
	printf("<BR><INPUT TYPE=submit VALUE=\"Submit\">");
	printf("<INPUT TYPE=reset VALUE=\"Reset\">");
	printf("</FORM>");
*/
  return 0;
}
