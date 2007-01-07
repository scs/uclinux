#
# This script was written by Paul Johnston of Westpoint Ltd <paul@westpoint.ltd.uk>
#
# See the Nessus Scripts License for details
#

if(description)
{
  script_id(11195);
  script_version ("$Revision: 1.3 $");
  script_cve_id("CAN-2002-1357", "CAN-2002-1358", "CAN-2002-1359", "CAN-2002-1360");

  name["english"] = "SSH Multiple Vulns";
  script_name(english:name["english"]);

  desc["english"] = "
 According to its banner, the remote SSH server is vulnerable to one or 
 more of the following vulnerabilities:

CAN-2002-1357 (incorrect length)
CAN-2002-1358 (lists with empty elements/empty strings)
CAN-2002-1359 (large packets and large fields)
CAN-2002-1360 (string fields with zeros)

Some of these vulnerabilities may allow remote attackers to execute 
arbitrary code with the privileges of the SSH process, usually root.

Solution : Upgrade your SSH server to an unaffected version

Risk factor : High";

  script_description(english:desc["english"]);

  summary["english"] = "SSH Multiple Vulnerabilities 16/12/2002";
  script_summary(english:summary["english"]);

  script_category(ACT_GATHER_INFO); 
  script_copyright(english:"This script is Copyright (C) 2002 Paul Johnston, Westpoint Ltd");
  script_family(english:"Gain root remotely");
  script_require_ports("Services/ssh", 22);
  script_dependencie("find_service.nes");

  exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/ssh");
if (!port) port = 22;

key = string("ssh/banner/", port);
banner = get_kb_item(key);
if(!banner)
{
  if(get_port_state(port))
  {
    soc = open_sock_tcp(port);
    if(soc)
    { 
      banner = recv_line(socket:soc, length:255);
      close(soc);
    }
  }
}
if(!banner) exit(0);

#
# SSH-2.0-3.2.0 F-Secure SSH Windows NT Server
# versions up to 3.1.* affected
#
if(ereg(pattern:"^SSH-2.0-([12]\..*|3\.[01]\..*) F-Secure SSH", string:banner, icase:TRUE))
{ 
  security_hole(port);
}

#
# SSH-2.0-3.2.0 SSH Secure Shell Windows NT Server
# versions up to 3.1.* affected
#
if(ereg(pattern:"^SSH-2.0-([12]\..*|3\.[01]\..*) SSH Secure Shell", string:banner, icase:TRUE))
{ 
  security_hole(port);
}

#
# SSH-1.99-Pragma SecureShell 3.0
# versions up to 2.* affected
#
if(ereg(pattern:"^SSH-1.99-Pragma SecureShell ([12]\..*)", string:banner, icase:TRUE))
{ 
  security_hole(port);
}
