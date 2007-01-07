# This script was written by Yoav Goldberg <yoavg@securiteam.com>


# (rd: description re-phrased)


#
# Body of a script
#
if(description)
{
 script_id(10675);
 script_version ("$Revision: 1.6 $");
 script_name(english:"CheckPoint Firewall-1 Telnet Authentication Detection");
 script_description(english:"
A Firewall-1 Client Authentication Server is running on this port.

Such an element allows an intruder to attempt to log into
the remote network or to gather a list of valid user names
by a brute-force attack.

Solution : if you do not use this service, disable it.
Risk factor : Low");

 script_summary(english:"The remote CheckPoint Firewall-1 can be accessed via a telnet interface");
 script_category(ACT_GATHER_INFO);
 script_family(english:"Firewalls");
 script_copyright(english:"This script is Copyright (C) 2001 SecuriTeam");
 script_dependencies("find_service.nes");
 script_require_ports(259);
 exit(0);
}

#
# Actual script starts here
#
include("telnet_func.inc");

port = 259;
if(get_port_state(259))
{
 data = get_telnet_banner(port: 259);
 if(data)
 {
  if("Check Point FireWall-1 Client Authentication Server running on" >< data)
  	security_warning(259);
 }
}
 
