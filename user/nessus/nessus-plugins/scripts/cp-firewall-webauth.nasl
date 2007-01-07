# This script was written by Yoav Goldberg <yoavg@securiteam.com>

#
# Body of a script
#
if(description)
{
 script_id(10676);
 script_version ("$Revision: 1.9 $");
script_name(english:"CheckPoint Firewall-1 Web Authentication Detection");
 script_description(english:"
A Firewall-1 web server is running on this port and serves web authentication
requests.


This service allows remote attackers to gather usernames and passwords 
through a brute force attack.

Older versions of the Firewall-1 product allowed verifying usernames 
prior to checking their passwords, allowing attackers to easily
bruteforce a valid list of usernames.

Solution : if you do not use this service, disable it
Risk factor : Low");
 script_summary(english:"The remote CheckPoint Firewall-1 can be authenticated with via a web interface");
 script_category(ACT_GATHER_INFO);
 script_family(english:"Firewalls");
 script_copyright(english:"This script is Copyright (C) 2001 SecuriTeam");

 script_dependencies("find_service.nes", "httpver.nasl");
 script_require_ports("Services/www", 900);
 exit(0);
}

#
# Actual script starts here
#
include("http_func.inc");
include("misc_func.inc");

quote = raw_string(0x22);

strcheck1 = string("Authentication Form");
strcheck2 = string("Client Authentication Remote");
strcheck3 = string("FireWall-1 message");


ports = add_port_in_list(list:get_kb_list("Services/www"), port:900);


foreach port (ports)
{
 soc = http_open_socket(port);
 if(soc)
 {
  buf = http_get(item:"/", port:port);
  send(socket:soc, data:buf);
  re = http_recv(socket:soc);
  http_close_socket(soc);
  if((strcheck3 >< re) && (strcheck2 >< re) && (strcheck1 >< re))
	{
	security_warning(port);
	}
 }
}
