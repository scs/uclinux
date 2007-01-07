#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11755);
 script_bugtraq_id(7950, 7946);
 script_cve_id("CAN-2001-0826");
 
 script_version ("$Revision: 1.2 $");
 
 name["english"] = "CesarFTP multiple overflows";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running CesarFTP, a FTP server for
Windows systems.

There are multiple flaws in this version of CesarFTP which
may allow an attcker to execute arbitrary code on this host,
or simply to disable this server remotely.

Solution : Disable this service, upgrade to version 0.99h or newer
Risk Factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "CesarFTP overflows";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Gain a shell remotely";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;

if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);

banner = ftp_recv_line(socket:soc);


 if(egrep(pattern:"^220 CesarFTP 0\.([0-8]|9[0-8]|99[a-g])", string:banner))
 {
  security_hole(port);
 }

ftp_close(socket:soc);

exit(0);

#
# The following code freezes the GUI, but does not
# crash the FTP daemon
# 
send(socket:soc, data:'USER !@#$%^&*()_\r\n');
r = ftp_recv_line(socket:soc);
display(r);
send(socket:soc, data:'USER ' + crap(256) + '\r\n');
r = ftp_recv_line(socket:soc);
display(r);
