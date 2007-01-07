if(description)
{
 script_id(10876);
 script_version("$Revision: 1.2 $");
 name["english"] = "Delta UPS Daemon Detection";
 script_name(english:name["english"]);

 desc["english"] = "
The Delta UPS Daemon is running on this server.

This UPS (see: http://www.deltaww.com/) provides a daemon that shows 
sensitive information, including:
 OS type and version
 Internal network addresses
 Internal numbers used for pager
 Encrypted password
 Latest event log of the machine

Solution : Block access to the Delta UPS's daemon on this port
Risk factor : Medium";

 script_description(english:desc["english"]);

 summary["english"] = "Delta UPS Daemon Detection";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2002 SecurITeam");
 family["english"] = "General";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/deltaups", 2710);
 exit(0);
}

# Check starts here

function check(req)
{
 soc = open_sock_tcp(port);
 if(soc)
 {

  send(socket:soc, data:req);
  buf = recv(socket:soc, length:4096);

  close(soc);

  if (("DeltaUPS" >< buf) || ("NET01" >< buf) || ("STS00" >< buf) || ("ATZ" >< buf) || ("ATDT" >< buf))
  {
        security_hole(port:port);
        return(1);
  }
 }
 return(0);
}

port = get_kb_item("Services/deltaups");
if(!port)port = 2710;
cginameandpath[0] = string("\n");
cginameandpath[1] = "";

i = 0;
if(get_port_state(port))
{
 for (i = 0; cginameandpath[i]; i = i + 1)
 {
  url = cginameandpath[i];
  if(check(req:url))exit(0);
 }
}
