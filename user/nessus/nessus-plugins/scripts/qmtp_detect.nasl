#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL
#


if(description)
{
  script_id(11134);
  script_version ("$Revision: 1.2 $");
 
  script_name(english:"QMTP");
 
  desc["english"] = "
For your information, a QMTP server is running on this port.
QMTP is a proposed replacement of SMTP by D.J. Bernstein.

** Note that Nessus only runs SMTP tests currently.

Risk factor : None";

  script_description(english:desc["english"]);
 
  summary["english"] = "Detect QMTP servers";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi");
  script_family(english:"Misc.", francais:"Divers");
  script_dependencie("find_service.nes");
  script_require_ports(209);

  exit(0);
}

####

include("misc_func.inc");

#port = get_kb_item("Services/unknown");
#if (! port) port = 209;
port = 209;

#if (known_service(port: port)) exit(0);
if (! get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if (! soc) exit(0);

msg = string(	"132:\n", 
		"Message-ID: <1234567890.666.nessus@example.org>\n",
		"From: nessus@example.org\n",
		"To: postmaster@example.com\n",
		"Nessus is probing this server.\n",
		",18:nessus@example.org,26:22:postmaster@example.com,,");

send(socket: soc, data: msg);
r = recv(socket: soc, length: 10);

if (ereg(pattern: "^[1-9][0-9]*:[KZD]", string: r))
{
  security_note(port);
  register_service(port: port, proto: "QMTP");
}

close(soc);

