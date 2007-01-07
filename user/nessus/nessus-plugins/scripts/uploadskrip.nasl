#
# This script was written by John Lampe...j_lampe@bellsouth.net 
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11746);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CAN-2001-0938");
 
 
 name["english"] = "AspUpload vulnerability";
 name["francais"] = "AspUpload vulnerability";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The AspUpload software resides on this server. 

Some versions of this software are vulnerable to remote exploit.

Solution : Update the software at http://www.aspupload.com 

Risk factor : Serious";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the AspUpload software";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 John Lampe",
		francais:"Ce script est Copyright (C) 2003 John Lampe");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_kb_item("Services/www");
if(!port) port = 80;
if(!get_port_state(port))exit(0);

 
foreach dir (cgi_dirs())
{
	req = http_get(item:dir + "/Test11.asp", port:port);
	res = http_keepalive_send_recv(port:port, data:req);
	if( res == NULL ) exit(0);
	if (egrep(pattern:".*UploadScript11\.asp.*", string:r)) 
		{
			security_hole(port);
			exit(0);
		}
}
