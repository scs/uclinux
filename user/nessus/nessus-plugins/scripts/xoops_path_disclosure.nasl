# This script was written by Renaud Deraison
#
# Ref :
#  Date: 20 Mar 2003 19:58:55 -0000
#  From: "Grégory" Le Bras <gregory.lebras@security-corporation.com>
#  To: bugtraq@securityfocus.com
#  Subject: [SCSA-011] Path Disclosure Vulnerability in XOOPS
#
# This check will incidentally cover other flaws.

if(description)
{
 script_id(11439);
 script_bugtraq_id(3977, 3978, 3981, 5785, 6344, 6393);
 script_cve_id("CAN-2002-0216", "CAN-2002-0217");
 script_version ("$Revision: 1.2 $");

 
 name["english"] = "Xoops path disclosure";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running the Xoops CGI suite.

There is a flaw in this version which allows an attacker
to obtain the physical path of the remote web root by supplying
a bogus option to one of the Xoops CGI.

In addition to this, other flaws are known to exist in Xoops
(SQL injection, information disclosure about the users and so on).

You are advised to remove this CGI.

Solution : None at this time
Risk factor : Medium";




 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for Xoops";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_kb_item("Services/www");
if(!port)port = 80;
if(!get_port_state(port))exit(0);


foreach d (make_list( "", cgi_dirs()))
{
 req = http_get(item:string(d, "/index.php?xoopsOption=nessus"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if( res == NULL ) exit(0);
 
 if(egrep(pattern:".*Fatal error.* in <b>/.*", string:res)){
 	security_warning(port);
	exit(0);
 }
}
