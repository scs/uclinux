#
#
# ping code taken from mssql_ping by H D Moore
#
#
# MS02-061 supercedes MS02-020, MS02-038, MS02-039, MS02-043 and MS02-056
#
# BID xref by Erik Anderson <eanders@carmichaelsecurity.com>
# 
# Other CVEs: CAN-2002-0729, CAN-2002-0650
#
if(description)
{
 script_id(11214);
 script_cve_id("CAN-2002-1137", "CAN-2002-1138", 
 	       "CAN-2002-0649", "CVE-2002-0650", 
	       "CAN-2002-1145", "CAN-2002-0644",
	       "CAN-2002-0645", "CAN-2002-0721");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-A-0001");
 script_bugtraq_id(5310, 5311);
 script_version ("$Revision: 1.18 $");
 name["english"] = "Microsoft's SQL Overflows";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host MS SQL server is vulnerable to several overflows which could 
be exploited by an attacker to gain SYSTEM access on that host.

Note that a worm (sapphire) is exploiting this vulnerability in the wild.

Solution : http://www.microsoft.com/technet/security/bulletin/ms02-061.asp
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Microsoft's SQL UDP Info Query";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 exit(0);
}

#
# The script code starts here
#


function sql_ping()
{
 req = raw_string(0x02);
 if(!get_udp_port_state(1434))exit(0);
 soc = open_sock_udp(1434);


 if(soc)
 {
	send(socket:soc, data:req);
	r  = recv(socket:soc, length:4096);
	close(soc);
	return(r);
 }
}



r = sql_ping();
if(strlen(r) > 0)
 {
  soc = open_sock_udp(1434);
  send(socket:soc, data:raw_string(0x0A));
  r = recv(socket:soc, length:1);
  if(strlen(r) > 0 && ord(r[0]) == 0x0A)security_hole(port:1434, proto:"udp");
 }
exit(0);



