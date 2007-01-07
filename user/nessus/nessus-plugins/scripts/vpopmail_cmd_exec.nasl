#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11397);
 script_version ("$Revision: 1.2 $");
 script_bugtraq_id(7063);
 name["english"] = "vpopmail.php command execution";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running an old version of vpopmail.php (an extension
to squirrelmail) which allows users to execute arbitrary commands on
the remote host with the same privileges as the web server the user
is running as.

Solution : Upgrade to VPOPMail 0.98 or newer
Risk factor : Medium";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Determines the version of vpopmail.php";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_kb_item("Services/www");
if(!port)port = 80;

foreach d (make_list(cgi_dirs(), "/"))
{
  # UGLY UGLY UGLY
  req = http_get(item:string(d, "/vpopmail/README"), port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if("VPOPMail Account Administration" >< res)
  {
    if(egrep(pattern:".*Version.*0\.([0-9]|[0-8][0-9]|9[0-7])[^0-9]", string:res))
    	security_warning(port);
  }
  
}


