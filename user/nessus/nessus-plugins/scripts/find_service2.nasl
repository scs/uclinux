#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# It is released under the GNU Public Licence
#
# References:
# From: SecuriTeam <support@securiteam.com>
# Subject: [EXPL] Remote BZFlag Server DoS
# To: list@securiteam.com
# Date: 21 May 2003 18:22:14 +0200
#

if(description)
{
 script_id(11153);
 script_version ("$Revision: 1.40 $");
 
 name["english"] = "Identifies unknown services with 'HELP'";
 name["francais"] = "Identifie les services inconnus avec 'HELP'";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
This plugin is a complement of find_service.nes
It sends a HELP request to the remaining unknown services
and tries to identify them.

Risk factor : Low";


 desc["francais"] = "
Ce plugin est un complément de find_service.nes
Il envoie une requête HELP aux services qui restent inconnus et
essaie de les identifier.

Facteur de risque : Faible";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Sends 'HELP' to unknown services and look at the answer";
 summary["francais"] = "Envoie 'HELP' aux services inconnus et observe la réponse";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO); 
 script_timeout(0);
 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi",
		francais:"Ce script est Copyright (C) 2002 Michel Arboi");
 family["english"] = "Misc.";
 family["francais"] = "Divers";

 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "rpcinfo.nasl", "dcetest.nasl");
 script_require_ports("Services/unknown");
 exit(0);
}

#
include("misc_func.inc");

port = get_kb_item("Services/unknown");
if (! port) exit(0);
if (! get_port_state(port)) exit(0);
if (known_service(port: port)) exit(0);

r0 = get_unknown_banner(port: port, dontfetch: 1);
# Check only mute services?
# if (r0) exit(0);

soc = open_sock_tcp(port);
if (! soc) exit(0);

send(socket: soc, data: string("HELP\r\n"));
r = recv(socket:soc, length:4096);
close(soc);
if (!r)
{
  # Mute service
  # security_note(port: port, data: "A mute service is running on this port");
  exit(0);
}

# BZFlag Server (a game on SGI)
if (r =~ '^BZFS')
{
 register_service(port:port, proto:"bzfs");
 security_note(port:port, data:"A BZFlag game server seems to be running on this port");
 exit(0);
}

# (Solaris) lpd server
if(ereg(pattern: "^Invalid protocol request.*:HHELP.*", string:r))
{
 register_service(port:port, proto:"lpd");
 security_note(port:port, data:"An LPD server seems to be running on this port");
 exit(0);
}

if(ereg(pattern:"^login: Password: $", string:r))
{
 register_service(port:port, proto:"uucp");
 security_note(port:port, data:"An UUCP daemon seems to be running on this port");
 exit(0);
}

# IRC server
if (ereg(pattern: "^:.* 451 .*:", string:r))
{
  register_service(port: port, proto: "irc");
  security_note(port: port, data: "An IRC server seems to be running on this port");
  exit(0);
}

if(ereg(pattern:"^(Mon|Tue|Wed|Thu|Fri|Sat|Sun|Lun|Mar|Mer|Jeu|Ven|Sam|Dim) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|D[eé]c|F[eé]v|Avr|Mai|Ao[uû]) *([0-9]|[1-3][0-9]) [0-9]+:[0-9]+:[0-9]+( *[ap]m)?( +[A-Z]+)? [1-2][0-9][0-9][0-9].?.?$",
        string:r) ||
   ereg(pattern:"^[0-9][0-9] +(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|D[eé]c|F[eé]v|Avr|Mai|Ao[uû]) +[1-2][0-9][0-9][0-9] +[0-9]+:[0-9]+:[0-9]+( *[ap]m)? [A-Z0-9]+.?.?$", string:r, icase: 1))
{
 register_service(port:port, proto: "daytime");
 exit(0);
}

if (egrep(pattern: "^[A-Za-z. -]+\([0-9-]+\)", string: r))
{
  register_service(port:port, proto: "qotd");
  security_note(port: port, data: "qotd seems to be running on this port");
  exit(0);
}


# Another flavor of daytime
if(ereg(pattern:"^(Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday), (January|February|March|April|May|June|July|August|September|October|November|December) ([0-9]|[1-3][0-9]), [1-2][0-9][0-9][0-9] .*", string:r))
{
  register_service(port:port, proto:"daytime");
  exit(0);
}

# MS flavor of daytime
if(ereg(pattern:"^[0-9][0-9]?:[0-9][0-9]:[0-9][0-9] [AP]M [0-9][0-9]?/[0-9][0-9]?/[0-2][0-9][0-9][0-9].*$", string:r))
{
 register_service(port:port, proto:"daytime");
 exit (0);
}

# Banner:
# HP OpenView OmniBack II A.03.10:INET, internal build 325, built on Mon Aug 23 15:50:58 1999. 
if (match(string: r, pattern: "HP OpenView OmniBack II*"))
{
  register_service(port: port, proto: "omniback");
  security_note(port: port, data: "HP Omniback seems to be running on this port");
  exit(0);
}

# Veritas Netbackup
if (r =~ '^1000 +2\n43\nunexpected message received')
{
  register_service(port: port, proto: "netbackup");
  security_note(port: port, data: "Veritas Netbackup seems to be running on this port");
  exit(0);
}

# BMC Patrol
if (r == "SDPACK")
{
  register_service(port: port, proto: "bmc-perf-sd");
  security_note(port: port, data: "BMC Perform Service Daemon seems to be running on this port");
  exit(0);
}

# SNPP
if (r =~ '^220 .* SNPP ' || egrep(string: r, pattern: '^214 .*PAGE'))
{
  register_service(port: port, proto: "snpp");
  security_note(port: port, data: "A SNPP server seems to be running on this port");
  exit(0);
}

# HylaFax FTP
if (egrep(string: r, pattern: '^214-? ') && 'MDMFMT' >< r)
{
  register_service(port: port, proto: "hylafax-ftp");
  security_note(port: port, data: "A HylaFax server seems to be running on this port");
  exit(0);
}

# IRCn
if (strlen(r) == 2048 && r =~ '^[ ,;:.@$#%+HMX\n-]+$' && '-;;=' >< r &&
	'.;M####+' >< r && '.+ .%########' >< r && ':%.%#########@' >< r)
{
  register_service(port: port, proto: 'IRCn-finger');
  security_note(port: port, data: "IRCn finger service seems to be running on this port");
  exit(0);
}

if ("Melange Chat Server" >< r)
{
  register_service(port: port, proto: 'melange-chat');
  security_note(port: port, data: "Melange Chat Server is running on this port");
  exit(0);
}

# If you do not want to "double check", uncomment the next two lines
# if (! r0) set_unknown_banner(port: port, banner: r);
# exit(0);

########################################################################
# All the following services should already have been identified by    #
# find_service.nes; anyway, we double check in case it failed...       #
########################################################################

# SOCKS5
if (ord(r[0]) == 5 && ord(r[1]) <= 8 && ord(r[2]) == 0 && ord(r[3]) <= 4)
{
  register_service(port: port, proto: "socks5");
  security_note(port: port, data: "A SOCKS5 server seems to be running on this port");
}

# SOCKS4
if (ord(r[0]) == 0 && ord(r[1]) >= 90 && ord(r[1]) <= 93)
{
  register_service(port: port, proto: "socks4");
  security_note(port: port, data: "A SOCKS4 server seems to be running on this port");
}

# FTP - note that SMTP & SNPP also return 220 & 214 codes
if (egrep(pattern:"^220 .*FTP", string:r, icase: 1) ||
    egrep(pattern:"^214-? .*FTP", string: r, icase: 1))
{
  banner = egrep(pattern:"^2[01][04]-? ", string: r);
  k = string("ftp/banner/", port);
  set_kb_item(name: k, value: banner);
  register_service(port: port, proto: "ftp");
  security_note(port: port, data: "A FTP server seems to be running on this port");
  exit(0);
}

# SMTP
if (egrep(pattern:"^220( |-).*(SMTP|mail)", string:r, icase: 1) ||
    egrep(pattern:"^214-? .*(HELO|MAIL|RCPT|DATA|VRFY|EXPN)", string: r))
{
  banner = egrep(pattern:"^2[01][04]-? ", string: r);
  k = string("smtp/banner/", port);
  set_kb_item(name: k, value: banner);
  register_service(port: port, proto: "smtp");
  security_note(port: port, data: "A SMTP server seems to be running on this port");
  exit(0);
}

# NNTP
if (egrep(pattern: "^200 .*(NNTP|NNRP)", string: r) ||
    egrep(pattern: "^100 .*commands", string: r, icase: 1))
{
  banner = egrep(pattern:"^200 ", string: r);
  if (banner)
  {
    k = string("nntp/banner/", port);
    set_kb_item(name: k, value: banner);
  }
  register_service(port: port, proto: "nntp");
  security_note(port: port, data: "A NNTP server seems to be running on this port");
  exit(0);
}

# SSH
banner = egrep(pattern: "^SSH-", string: r);
if (banner)
{
  k = string("ssh/banner/", port);
  set_kb_item(name: k, value: banner);
  register_service(port: port, proto: "ssh");
  security_note(port: port, data: "A SSH server seems to be running on this port");
  exit(0);
}

# Auth
if (ereg(string: r, pattern:"^0 *, *0 *: * ERROR *:"))
{
  register_service(port: port, proto: "auth");
  security_note(port: port, data: "An Auth/ident server seems to be running on this port");
  exit(0);
}

# Finger
if ((egrep(string: r, pattern: "HELP: no such user", icase: 1)) ||
    (egrep(string :r, pattern: ".*Line.*User.*Host", icase:1)) ||
    (egrep(string:r, pattern:".*Login.*Name.*TTY", icase:1)))
{
  register_service(port: port, proto: "finger");
  security_note(port: port, data: "A finger server seems to be running on this port");
  exit(0);
}


# sunRay Server - thanks to kent@unit.liu.se (Kent Engström)
if("ERR/InvalidCommand" >< r) 
{
 register_service(port:port, proto:"sunraySessionMgr");
 security_note(port:port, data:"sunraySessionMgr server is running on this port");
 exit(0);
}
  
# HTTP

if (("501 Method Not Implemented" >< r) || (ereg(string: r, pattern: "^HTTP/1\.[01]")) || "action requested by the browser" >< r)
{
  register_service(port: port, proto: "www");
  security_note(port: port, data: "A web server seems to be running on this port");
  exit(0);
}

# BitTorrent - no need to send anything to get the banner, in fact
if (r =~ "^BitTorrent protocol")
{
  register_service(port: port, proto: "BitTorrent");
  security_note(port: port, data: "A BitTorrent server seems to be running on this port");
  exit(0);
}

########################################################################
#             Unidentified service                                     #
########################################################################

if (! r0) set_unknown_banner(port: port, banner: r);
