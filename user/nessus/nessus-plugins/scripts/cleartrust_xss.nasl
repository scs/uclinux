#
# This script is (C) Renaud Deraison
#
#
# Ref: (no bid nor cve yet)
#  Date: Fri, 14 Mar 2003 18:42:02 -0800
#  To: bugtraq@securityfocus.com
#  Subject: @(#)Mordred Security Labs - RSA ClearTrust Cross Site Scripting issues 
#  From: sir.mordred@hushmail.com



if(description)
{
 script_id(11399);
 script_version ("$Revision: 1.6 $");
 script_bugtraq_id(7108);
 

 name["english"] = "ClearTrust XSS";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote ClearTrust server is vulnerable to cross-site scripting,
when requesting the script ct_login.asp with improper arguments,
as in :

GET /cleartrust/ct_logon.asp?CTLoginErrorMsg=<script>alert(1)</script>


Solution : None at this time
Risk factor : Medium";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for ClearTrust XSS";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);

 script_dependencie("find_service.nes", "http_version.nasl", "cross_site_scripting.nasl");
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
if(!get_port_state(port))exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

foreach d (make_list("", cgi_dirs()))
{
req = http_get(item:string(d, "/cleartrust/ct_login.asp?CTLoginErrorMsg=<script>alert(1)</script>"), port:port);
res = http_keepalive_send_recv(port:port, data:req);

if ( res == NULL ) exit (0);
if(!ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 ", string:res))exit(0);

if("<script>alert(1)</script>" >< res ) {
 security_warning(port);
 exit(0);
}
}
