#
# (C) Tenable Network Security
#


if (description)
{
 script_id(11639);
 script_bugtraq_id(6996);
 script_version ("$Revision: 1.1 $");

 script_name(english:"Web-ERP Configuration File Remote Access");
 desc["english"] = "
The remote host is using WEB-ERP, an accounting project.

There is a flaw in the version used which lets any attacker
download the configuration file (logicworks.ini) which contains
the username and password of the database.

Solution : Upgrade to Web-ERP 0.1.5 or newer, delete logicworks.ini
Risk Factor : Medium";


 script_description(english:desc["english"]);
 script_summary(english:"Determines if Web-ERP is installed");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");



port = get_kb_item("Services/www");
if (!port) port = 80;
if(!get_port_state(port))exit(0);


dir = make_list("", cgi_dirs());
		

foreach d (dir)
{
 req = http_get(item:d + "/logicworks.ini", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if( res == NULL ) exit(0);
 if("$CompanyName" >< res && "WEB-ERP" >< res )
 	{
    	security_warning(port);
	exit(0);
	}
}
