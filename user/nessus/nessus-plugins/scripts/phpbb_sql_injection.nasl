#
# (C) Tenable Network Security
#
# 

if(description)
{
 script_id(11767);
 script_bugtraq_id(7979);
 
 script_version("$Revision: 1.1 $");
 name["english"] = "SQL injection in phpBB";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running phpBB.

There is a flaw in the remote software which may allow anyone
to inject arbitrary SQL commands, which may in turn be used to
gain administrative access on the remote host or to obtain
the MD5 hash of the password of any user.

Solution : Upgrade to the latest version of this software
Risk Factor : Serious";


 script_description(english:desc["english"]);
 
 summary["english"] = "SQL Injection";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");

function check(dir)
{
  req = http_get(item:dir + "/viewtopic.php?sid=1&topic_id='", port:port);
  buf = http_keepalive_send_recv(port:port, data:req);
  if(buf == NULL)exit(0);

  if("SELECT t.topic_id, t.topic_title, t.topic_status" >< buf) 
  	{
	security_hole(port);
	exit(0);
	}
 return(0);
}

port = get_kb_item("Services/www");
if(!port)port = 80;


foreach dir (make_list("/phpBB", "", cgi_dirs()))
{
 check(dir:dir);
}
