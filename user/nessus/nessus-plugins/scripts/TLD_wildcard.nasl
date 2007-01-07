# This script was written by Michel Arboi <arboi@alussinan.org>
#
# Released under GPLv2
#
# Known top level domain wildcards, from 
# http://www.imperialviolet.org/dnsfix.html
#
# .COM and .NET	64.94.110.11 (and possibly others in AS30060)	
# .NU	64.55.105.9 212.181.91.6
# .TK	195.20.32.83 195.20.32.86
# .CC	206.253.214.102
# .MP	202.128.12.163
# .AC	194.205.62.122
# .CC	194.205.62.122 (206.253.214.102 also reported, but cannot confirm)
# .CX	219.88.106.80
# .MUSEUM	195.7.77.20
# .PH	203.119.4.6
# .SH	194.205.62.62
# .TM	194.205.62.42 (194.205.62.62 also reported, but cannot confirm)
# .WS	216.35.187.246
# 
####
#
# I also found that:
# .PW redirects to wfb.dnsvr.com = 216.98.141.250 or 65.125.231.178
# .TD   146.101.245.154
# 

if(description)
{
 script_id(11840);
 script_version ("$Revision: 1.1 $");
 name["english"] = "Exclude toplevel domain wildcard host";
 script_name(english:name["english"]);

 desc["english"] = "
The host you were trying to scan is blacklisted: its address is known to
be returned by a wildcard on some top level domains.
You probably mistyped its name.

Risk factor : None";

 script_description(english:desc["english"]);

 summary["english"] = "Exclude some IPs from scan";
 script_summary(english:summary["english"]);

 script_category(ACT_SCANNER);


 script_copyright(english:"This script is Copyright (C) 2003 by Michel Arboi");
 family["english"] = "Port scanners";
 script_family(english:family["english"]);
 exit(0);
}

#
excluded["64.94.110.11"] = 1;
excluded["64.55.105.9"] = 1;
excluded["212.181.91.6"] = 1;
excluded["195.20.32.83"] = 1;
excluded["195.20.32.86"] = 1;
excluded["206.253.214.102"] = 1;
excluded["202.128.12.163"] = 1;
excluded["194.205.62.122"] = 1;
excluded["219.88.106.80"] = 1;
excluded["195.7.77.20"] = 1;
excluded["203.119.4.6"] = 1;
excluded["194.205.62.62"] = 1;
excluded["194.205.62.42"] = 1;
excluded["216.35.187.246"] = 1;
#
excluded["216.98.141.250"] = 1;
excluded["65.125.231.178"] = 1;
excluded["146.101.245.154"] = 1;


target = get_host_ip();

if (excluded[target])
{
 ##display(target, " is in IP blacklist\n");
 set_kb_item(name: "Host/dead", value: TRUE);
 security_note(port: 0);
 exit(0);
}

exit(0);
# We do not test if Verisign "snubby mail rejector" is running on the
# machine, as it may be used elsewhere

soc = open_sock_tcp(25);
if (!soc) exit(0);
r = recv(socket: soc, length: 256);
if (r =~ '^220 +.*Snubby Mail Rejector')
{
  ##display(target, " looks like Verisign snubby mail server\n");
  set_kb_item(name: "Host/dead", value: TRUE);
  security_note(port: 0);
}

close(soc);
