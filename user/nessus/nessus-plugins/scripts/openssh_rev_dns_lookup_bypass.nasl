#
# (C) Tenable Network Security
#
#

if(description)
{
 script_id(11712);
 script_bugtraq_id(7831);
 script_cve_id("CAN-2003-0386");
 script_version ("$Revision: 1.4 $");
 
 
 
 name["english"] = "OpenSSH Reverse DNS Lookup bypass";
 script_name(english:name["english"]);
 
 desc["english"] = "
You are running OpenSSH-portable 3.6.1 or older.

There is a flaw in this version which may allow an attacker to
bypass the access controls set by the administrator of this server.

OpenSSH features a mechanism which can restrict the list of
hosts a given user can log from by specifying a pattern
in the user key file (ie: *.mynetwork.com would let a user
connect only from the local network).

However there is a flaw in the way OpenSSH does reverse DNS lookups.
If an attacker configures his DNS server to send a numeric IP address
when a reverse lookup is performed, he may be able to circumvent
this mechanism.

Solution : Upgrade to OpenSSH 3.6.2 when it comes out
Risk Factor : Low";
	
	

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the remote SSH version";
 summary["francais"] = "Vérifie la version de SSH";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security",
		francais:"Ce script est Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Misc.";

 script_family(english:family["english"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/ssh", 22);
 exit(0);
}

#
# The script code starts here
#


port = get_kb_item("Services/ssh");
if(!port)port = 22;

key = string("ssh/banner/", port);
banner = get_kb_item(key);


if(!banner)
{
  if(get_port_state(port))
  {
    soc = open_sock_tcp(port);
    if(!soc)exit(0);
    banner = recv_line(socket:soc, length:1024);
    banner = tolower(banner);
    close(soc);
  }
}

if(!banner)exit(0);

banner = banner - string("\r\n");

banner = tolower(banner);
if("openssh" >< banner)
{
 if(ereg(pattern:".*openssh[-_]((1\..*)|(2\..*)|(3\.([0-5][^0-9]|6(\.[01])?$)))", string:banner))
	security_warning(port);
}
