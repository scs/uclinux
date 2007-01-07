#
# (C) Tenable Network Security
#
# 
#
# Ref: 
#  Date: 18 Jun 2003 16:33:36 -0000
#  Message-ID: <20030618163336.11333.qmail@www.securityfocus.com>
#  From: Lorenzo Manuel Hernandez Garcia-Hierro <security@lorenzohgh.com>
#  To: bugtraq@securityfocus.com  
#  Subject: phpMyAdmin XSS Vulnerabilities, Transversal Directory Attack ,
#   Information Encoding Weakness and Path Disclosures
#

if(description)
{
 script_id(11761);
 script_bugtraq_id(7965, 7964, 7963, 7962);
 script_version ("$Revision: 1.6 $");
 name["english"] = "phpMyAdmin multiple flaws";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of phpMyAdmin which is vulnerable to 
several flaws :

 - It may be tricked into disclosing the physical path of the remote PHP
   installation
   
 - It is vulnerable to Cross-Site scripting, which may allow an attacker
   to steal the cookies of your users
   
 - It is vulnerable to a flaw which may allow an attacker to list the
   content of arbitrary directories on the remote server.
   
 
An attacker may use these flaws to gain more knowledge about the remote
host and therefore set up more complex attacks against it.


Solution : None at this time.
Risk Factor : Medium";




 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of phpMyAdmin";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
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


function check(dir)
{
 req = http_get(item:string(dir, "/db_details_importdocsql.php?submit_show=true&do=import&docpath=../../../../../../../../../../etc"),
 		port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL ) exit(0);
 if("Ignoring file passwd" >< r)
   {
 	security_warning(port);
	exit(0);
   }
}




foreach dir (make_list("/phpMyAdmin", cgi_dirs()))
{
 check(dir:dir);
}

