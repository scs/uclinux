#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL
#
# Note: this script is not very useful because mldonkey only allows
# connections from localhost by default


if(description)
{
  script_id(11124);
  script_version ("$Revision: 1.7 $");
 
  script_name(english:"mldonkey telnet");
 
  desc["english"] = "
mldonkey telnet interface might be running on this port. 
This peer to peer software is used to share files.
1. This may be illegal.
2. You may have access to confidential files
3. It may eat too much bandwidth


Solution: disable it

Risk factor : Medium";

  script_description(english:desc["english"]);
 
  summary["english"] = "Detect mldonkey telnet interface";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi");
  family["english"] = "Peer-To-Peer File Sharing";
  script_family(english:family["english"]);
  script_dependencie("find_service.nes");
  #script_require_ports("Services/unknown", 4000);
  script_require_ports(4000);

  exit(0);
}

include("misc_func.inc");

#port = get_kb_item("Services/unknown");
#if (! port) port = 4000;
port = 4000;

if (known_service(port: port)) exit(0);
if (! get_port_state(port)) exit(0);

r = get_unknown_banner(port: port, dontfetch:0);

if(!r)exit(0);
# soc = open_sock_tcp(port);
# if (!soc) exit(0);
# r = recv(socket: soc, length: 36);

if ("Welcome on mldonkey command-line" >< r)
{
 security_warning(port);
 register_service(port: port, proto: "mldonkey-telnet");
}
