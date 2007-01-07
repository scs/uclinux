#
# This script is (C) Tenable Network Security
#
# ref: http://www.kernelpanik.org/docs/kernelpanik/wordpressadv.txt
#




if(description)
{
 script_id(11703);
 script_bugtraq_id(7785);
 script_version ("$Revision: 1.2 $");

 name["english"] = "WordPress code/sql injection";

 script_name(english:name["english"]);
 
 desc["english"] = "
It is possible to make the remote host include php files hosted
on a third party server using the WordPress CGI suite which is installed
(which is also vulnerable to a SQL injection attack).

An attacker may use this flaw to inject arbitrary code in the remote
host and gain a shell with the privileges of the web server or
to take the control of the remote database.

Solution : Upgrade to the latest version
Risk factor : Serious";




 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of WordPress";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security",
		francais:"Ce script est Copyright (C) 2003 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
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
if(!port) port = 80;
if(!get_port_state(port))exit(0);



function check_php_inc(loc)
{
 req = http_get(item:string(loc, "/wp-links/links.all.php?abspath=http://xxxxxxxx"),
 		port:port);			
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL )exit(0);
 if(egrep(pattern:".*http://xxxxxxxx/blog\.header\.php", string:r))
 {
 	security_hole(port);
	exit(0);
 }
}

function check_sql_inj(loc)
{
 req = http_get(item:string(loc, "/index.php?posts='"),
 		port:port);			
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL )exit(0);
 if(egrep(pattern:".*mysql_fetch_object().*", string:r))
 {
 	security_hole(port);
	exit(0);
 }
}



dirs = make_list("", cgi_dirs());


foreach dir (dirs)
{
 check_php_inc(loc:dir);
 check_sql_inj(loc:dir);
}
