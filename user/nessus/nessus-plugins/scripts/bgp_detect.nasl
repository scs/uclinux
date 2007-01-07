# This plugin was written by Michel Arboi <arboi@alussinan.org>
# It is released under the GNU Public Licence (GPLv2)
#
# See RFC 1771
#

if(description)
{
  script_id(11907);
  script_version ("$Revision: 1.1 $");

  name["english"] = "BGP detection";
  script_name(english:name["english"]);
 
  desc["english"] = "
This machine is running BGP.

Risk factor : Low";

  script_description(english:desc["english"]);
 
  summary["english"] = "Sends a BGP Hello packet";
  script_summary(english:summary["english"]);
  script_category(ACT_GATHER_INFO); 
  script_copyright(english:"This script is Copyright (C) 2003 Michel Arboi");
  family["english"] = "Misc.";
  family["francais"] = "Divers";
  script_family(english:family["english"], francais:family["francais"]);
  exit(0);
}

##include("dump.inc");
include("misc_func.inc");

port = 179;
if (! get_port_state(port)) exit(0);
soc = open_sock_tcp(port);
if (! soc) exit(0);

s = this_host();
v = eregmatch(pattern: "^([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9])+$", string: s);
if (isnull(v)) exit(0);
for (i = 1; i <=4; i++) a[i] = int(v[i]);

r = '\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF'; # Marker
r += raw_string(0, 45,	# Length
		1,	# Open message
		4, 	# Version
		rand() % 256, rand() % 256,	# My AS
		0, 180,	# Hold time
		a[1], a[2], a[3], a[4],	# BGP identifier
		0, 	# Optional parameter length
		2, 6, 1, 4, 0, 1, 0, 1,
		2, 2, 80, 0,
		2, 2, 2, 0	);

send(socket: soc, data: r);

r = recv(socket: soc, length: 16, min: 16);

for (i = 0; i < 16; i ++)
  if (ord(r[i]) != 0xFF)
    break;
if (i < 16) exit(0);		# Bad marker

r = recv(socket: soc, length: 2, min: 2);
len = ord(r[0]) * 256 + ord(r[1]);
len -= 18;
if (len <= 0) exit(0);
r = recv(socket: soc, length: len, min: len);
##dump(ddata: r, dtitle: "BGP");
type = ord(r[0]);

if (type == 1)	# Hello
{
  ver = ord(r[1]);
  as = 256 * ord(r[2]) + ord(r[3]);
  ht = 256 * ord(r[4]) + ord(r[5]);	# Hold time
}
#else if (type == 3)	# Notification - may be error

register_service(port: port, proto: "bgp");
security_note(port);

