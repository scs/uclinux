# This script was written by Yoav Goldberg <yoavg@securiteam.com>

# (slightly modified by rd)

#
# Body of a script
#
if(description)
{
 script_id(10694);
 script_cve_id("CAN-2001-0767");
 script_bugtraq_id(2789);
 script_version ("$Revision: 1.10 $");
 script_name(english:"GuildFTPd Directory Traversal");
 
 desc = "
Version 0.97 of GuildFTPd was detected. A security vulnerability in
this product allows anyone with a valid FTP login to read arbitrary 
files on the system.

Solution: Upgrade your FTP server.
More Information : http://www.securiteam.com/windowsntfocus/5CP0S2A4AU.html

Risk factor : High";

 script_description(english:desc);

 script_summary(english:"Detects the presence of GuildFTPd version 0.97");
 script_category(ACT_GATHER_INFO);
 script_family(english:"FTP");
 script_copyright(english:"This script is Copyright (C) 2001 SecuriTeam");
 script_dependencies("find_service.nes");
 script_require_ports("Services/ftp", 21);

 exit(0);
}

#
# Actual script starts here
#

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;


banner = get_ftp_banner(port:port);
if(!banner)exit(0);

if ("GuildFTPD FTP" >< banner) 
{
if ("Version 0.97" >< banner)
 {
  security_hole(port);
 }
}

