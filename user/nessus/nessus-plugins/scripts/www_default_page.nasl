#
# Written by Renaud Deraison <deraison@nessus.org>
#



if(description)
{
 script_id(11422);
 script_version ("$Revision: 1.6 $");
 
 name["english"] = "Unconfigured web server";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote web server seems to have its default welcome page set.
It probably means that this server is not used at all.

Solution : Disable this service, as you do not use it
Risk factor : Low";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if the remote web server has been configured";
 
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "General";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "httpver.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_kb_item("Services/www");
if(!port) port = 80;

if(!get_port_state(port))exit(0);

req = http_keepalive_send_recv(port:port, data:http_get(item:"/", port:port));

if(req == NULL) exit(0);


#
# Apache
# 
apache_head = "<title>Test Page for Apache Installation</title>";
apache_body = "<p>This page is here because the site administrator has changed the
configuration of this web server. Please <strong>contact the person
responsible for maintaining this server with questions.</strong>
The Apache Software Foundation, which wrote the web server software
this site administrator is using, has nothing to do with
maintaining this site and cannot help resolve configuration
issues.</p>";

if(apache_head >< req && apache_body >< req){security_warning(port);exit(0);}


apache_head = "<TITLE>Test Page for the Apache Web Server on Red Hat Linux</TITLE>";
apache_body = "This page is used to test the proper operation of the Apache Web server after";

if(apache_head >< req && apache_body >< req){security_warning(port);exit(0);}


if(egrep(pattern:"<(TITLE|title)>Test Page for .*Apache Installation on Web Site</(TITLE|title)>",
         string:req)){security_warning(port);exit(0);}



#
# IIS
#
iis_head = "<title id=titletext>Under Construction</title>";
iis_body = "The site you were trying to reach does not currently have a default page. It may be in the process of being upgraded.";

if(iis_head >< req && iis_body >< req){ security_warning(port); exit(0); }


#
# Domino 6.0
# 

domino_head = 'body text="#000000" bgcolor="#000000" style="background-image:url(/homepage.nsf/homePage.gif?OpenImageResource); background-repeat: no-repeat; ">';
domino_body = "/help/help6_client.nsf";

if(domino_head >< req && domino_body >< req){security_warning(port); exit(0); }


#
# iPlanet 6.0
# 

iplanet_head = "<TITLE>iPlanet Web Server, Enterprise Edition 6.0</TITLE>";
iplanet_body = '<FRAME NAME="banner" SRC="banner.html" SCROLLING="no">';


if(iplanet_head >< req && iplanet_body >< req){security_warning(port); exit(0); }


#
# Sambar
# 

sambar_head = "<TITLE>Sambar Server</TITLE>";
sambar_body = "<B>Pro Server Features<B>";
if(sambar_head >< req){security_warning(port); exit(0);}
