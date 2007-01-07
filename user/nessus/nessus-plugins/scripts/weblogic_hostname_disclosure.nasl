#
# This script was written by Renaud Deraison
#

if(description)
{
 script_id(11606);
 script_version ("$Revision: 1.1 $");
 script_bugtraq_id(7257);
 name["english"] = "WebLogic Server hostname disclosure";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote WebLogic server discloses its NetBIOS host name when it is
issued a request generating a redirection.

An attacker may use this information to better prepare
other attacks against this host.

Solution : None
Risk Factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Make a request like GET . \r\n\r\n";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Misc.";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");

port = get_kb_item("Services/www");
if(!port)port = 80;
if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);
send(socket:soc, data:string("GET . HTTP/1.0\r\n\r\n"));
r = http_recv(socket:soc);

if(!strlen(r))exit(0);

if("WebLogic" >< r)
{ 
 loc =egrep(string:r, pattern:"^Location");
 if(!loc)exit(0);
 name = ereg_replace(pattern:"^Location: http://([^/]*)/.*",
 		     replace:"\1",
		     string:loc);
 
 if(get_host_name() == name)exit(0);
 if(get_host_ip() == name)exit(0);
 
 report = "
The remote WebLogic server discloses its NetBIOS host name when it is
issued a request generating a redirection.

We determined that the remote host name is : '" + name + "'

An attacker may use this information to better prepare
other attacks against this host.

Solution : None
Risk Factor : Low";	      
security_warning(port:port, data:report);
}
