#
# Copyright 2001 by Noam Rathaus <noamr@securiteam.com>
#
# See the Nessus Scripts License for details
#
#

if(description)
{
 script_id(10738);
 script_version ("$Revision: 1.9 $");
 name["english"] = "Oracle Web Administration Server Detection";
 script_name(english:name["english"]);

 desc["english"] = "We detected the remote web server as an Oracle 
Administration web server. This web server enables attackers to configure 
your Oracle Database server if they gain access to a valid authentication 
username and password.

Solution: Disable the Oracle Administration web server if it is unnecessary, 
or block the web server's port number on your Firewall.

Risk factor : Low";

 script_description(english:desc["english"]);

 summary["english"] = "Oracle Web Administration Server Detect";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2001 SecuriTeam");
 family["english"] = "General";
 script_family(english:family["english"]);

 script_dependencie("find_service.nes");
 script_require_ports("Services/www", 8888);
 exit(0);
}

#
# The script code starts here
#

 include("http_func.inc");
 include("misc_func.inc");
 
 ports = add_port_in_list(list:get_kb_list("Services/www"), port:8888);
 
 foreach port (ports)
 {
 soc = http_open_socket(port);
 if(soc)
 {
  req = http_get(item:"/", port:port);
  send(socket:soc, data:req);
  buf = http_recv(socket:soc);

  #display(buf);
  if (("401 Unauthorized" >< buf) && ("Oracle_Web_Listener" >< buf) && ("WWW-Authenticate: Basic Realm=" >< buf))
  {
   security_warning(port:port);
  }
  http_close_socket(soc);
 }
}

