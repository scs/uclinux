#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL
#
# This script only checks if ports 4661-4663 are open. 
# The protocol is not documented, AFAIK. It was probably 'reverse engineered'
# for mldonkey (do you read OCAML?)
# I sniffed a eDonkey connection, but could not reproduce it. 
# There is some information on http://hitech.dk/donkeyprotocol.html
# but I could not use it.



if(description)
{
  script_id(11022);
  script_version ("$Revision: 1.10 $");
 
  script_name(english:"eDonkey detection");
 
  desc["english"] = "
eDonkey might be running on this port. This peer to peer software
is used to share files.
1. This may be illegal.
2. You may have access to confidential files
3. It may eat too much bandwidth


Solution: disable it

Risk factor : Medium";

  script_description(english:desc["english"]);
 
  summary["english"] = "Detect eDonkey";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi");
  family["english"] = "Peer-To-Peer File Sharing";
  script_family(english:family["english"]);
  script_dependencie("find_service.nes");
  script_require_ports(4661, 4662, 4663);

  exit(0);
}

include("misc_func.inc");

for (port = 4661; port <= 4663; port = port + 1)
{
 if(get_port_state(port))
 {
 	kb = known_service(port:port);
	if(!kb || kb == "edonkey")
	{
	 soc = open_sock_tcp(port);
	 if(soc)
	 {
		# display(string("Open port = ", port, "\n"));
		security_warning(port);
		close(soc);
	 } 
	}
 }
}

# Looking for the mlDonkey web or telnet interface is useless:
# it only answers on localhost

exit(0);

