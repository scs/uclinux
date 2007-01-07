#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10592);
 script_version ("$Revision: 1.8 $");
 script_bugtraq_id(2166);
 name["english"] = "webdriver";
 name["francais"] = "webdriver";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "The 'webdriver' cgi is installed. This CGI usually
lets anyone access the Informix databases of the hosts that run it.

*** Warning : Nessus solely relied on the presence of this CGI, it did not
*** determine if you specific version is vulnerable to that problem

Solution : remove it from /cgi-bin.

Risk factor : Serious";



 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of /cgi-bin/webdriver";
 summary["francais"] = "Vérifie la présence de /cgi-bin/webdriver";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

port = is_cgi_installed("webdriver");
if(port)security_warning(port);
