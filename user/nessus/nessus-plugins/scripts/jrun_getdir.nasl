#
# This script was written by Felix Huber <huberfelix@webtopia.de>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#
# v. 1.00 (last update 28.11.01)
#

if(description)
{
 script_id(10814);
 script_version ("$Revision: 1.8 $");
 script_bugtraq_id(3592);
 name["english"] = "Allaire JRun directory browsing vulnerability";
 script_name(english:name["english"]);

 desc["english"] = "
Allaire JRun 3.0/3.1 under a Microsoft IIS 4.0/5.0 platform has a
problem handling malformed URLs. This allows a remote user to browse
the file system under the web root (normally \inetpub\wwwroot).

Under Windows NT/2000(any service pack) and IIS 4.0/5.0:
- JRun 3.0 (all editions)
- JRun 3.1 (all editions)


Upon sending a specially formed request to the web server, containing
a '.jsp' extension makes the JRun handle the request. Example:

http://www.victim.com/%3f.jsp

This vulnerability allows anyone with remote access to the web server
to browse it and any directory within the web root.

Solution:
>From Macromedia Product Security Bulletin (MPSB01-13)
http://www.allaire.com/handlers/index.cfm?ID=22236&Method=Full

Macromedia recommends, as a best practice, turning off directory 
browsing for the JRun Default Server in the following applications: 

- Default Application (the application with '/' mapping that causes
  the security problem) 

- Demo Application 
  Also, make sure any newly created web application that uses the '/'
  mapping has directory browsing off.

The changes that need to be made in the JRun Management Console or JMC:

- JRun Default Server/Web Applications/Default User Application/File
  Settings/Directory Browsing Allowed set to FALSE.   
- JRun Default Server/Web Applications/JRun Demo/File Settings/
  Directory Browsing Allowed set to FALSE.   

Restart the servers after making the changes and the %3f.jsp request
should now return a 403 forbidden. When this bug is fixed, the request
(regardless of directory browsing setting) should return a '404 page
not found'. 

The directory browsing property is called [file.browsedirs]. Changing
the property via the JMC will cause the following changes:
JRun 3.0 will write [file.browsedirs=false] in the local.properties
file. (server-wide change)
JRun 3.1 will write [file.browsedirs=false] in the webapp.properties
of the application. 


Risk factor : Medium";


 script_description(english:desc["english"]);

 summary["english"] = "Allaire JRun directory browsing vulnerability";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);


 script_copyright(english:"This script is Copyright (C) 2001 Felix Huber");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_kb_item("Services/www");
if(!port)port = 80;
if(get_port_state(port))
{
req = http_get(item:"/%3f.jsp", port:port);
soc = http_open_socket(port);
if(soc)
{
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 if(("Index of /" >< r)||
    ("Directory Listing" >< r)){
	security_hole(port);
	exit(0);
	}

 }
}
