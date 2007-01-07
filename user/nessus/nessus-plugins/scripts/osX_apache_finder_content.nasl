#
# This script was originally written by Matt Moore <matt.moore@westpoint.ltd.uk>
# www.westpoint.ltd.uk
#
# Modified by Noam Rathaus <noamr@securiteam.com>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10773); 
 script_version ("$Revision: 1.7 $");
 script_bugtraq_id(3325);
 name["english"] = "MacOS X Finder reveals contents of Apache Web files";
 script_name(english:name["english"]);
 
 desc["english"] = "
MacOS X creates a hidden file, '.FBCIndex' in each directory that has been 
viewed with the Finder. This file contains the content of the files present 
in the directory, giving an attacker information on the HTML tags, JavaScript, 
passwords, or any other sensitive word used inside those files. 

Solution: Use a <FilesMatch> directive in httpd.conf to restrict access to 
'hidden' files:

<FilesMatch '^\.'>
Order allow, deny
Deny from all
</FilesMatch>

And restart Apache.

Risk factor : Medium

More Information: 
http://www.securiteam.com/securitynews/5LP0O005FS.html
";

 script_description(english:desc["english"]);
 
 summary["english"] = "MacOS X Finder reveals contents of Apache Web files";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2001 Matt Moore, Modified by Noam Rathaus");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "no404.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/apache");
 exit(0);
}

# Check for .FBCIndex in the root of the web site 
# Could be improved to use the output of webmirror.nasl to create a list of folders to try... 
# This is very important since most ROOT directories do not contain it! TODO

include("http_func.inc");

port = get_kb_item("Services/www");
if(!port)port = 80;
if(get_port_state(port))
{ 
 req = http_get(item:"/.FBCIndex", port:port); # Check in web root
 soc = http_open_socket(port);
 if(soc)
 {
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);

 if("Bud2" >< r) 
 	security_hole(port);
 }
}
