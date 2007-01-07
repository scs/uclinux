#
# This script was written by Vincent Renardias <vincent@strongholdnet.com>
#
# Licence : GPL v2
#

if(description)
{
 script_id(10677);
 script_version ("$Revision: 1.10 $");
 name["english"] = "Apache /server-status accessible";
 name["francais"] = "Apache /server-status accessible";
 
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
Requesting the URI /server-status gives information about
the currently running Apache.

Risk factor : Low
Solution : 
If you don't use this feature, comment the appropriate section in
your httpd.conf file. If you really need it, limit its access to
the administrator's machine.";

 script_description(english:desc["english"]);
 
 summary["english"] = "Makes a request like http://www.example.com/server-status";
 summary["francais"] = "Fait une requête du type http://www.example.com/server-status";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2001 StrongHoldNet",
		francais:"Ce script est Copyright (C) 2001 StrongHoldNet");
 family["english"] = "Misc.";
 family["francais"] = "Divers";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/apache");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_kb_item("Services/www");
str = "Apache Server Status";
if(!port) port = 80;
if(get_port_state(port))
{
 soc = http_open_socket(port);
 if(soc)
 {
  buffer = http_get(item:"/server-status", port:port);
  send(socket:soc, data:buffer);
  data = http_recv(socket:soc);
  if( str >< data )
  {
   security_warning(port);
  }
  http_close_socket(soc);
 }
}
