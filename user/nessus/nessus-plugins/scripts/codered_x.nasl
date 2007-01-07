#
# Copyright 2001 by Noam Rathaus <noamr@securiteam.com>
#
# See the Nessus Scripts License for details
#
#

if(description)
{
 script_id(10713); 
 script_version ("$Revision: 1.19 $");
 script_bugtraq_id(2880);
 script_cve_id("CVE-2001-0500");

 name["english"] = "CodeRed version X detection";
 script_name(english:name["english"]);

 desc["english"] = "Your machine is infected with the 'Code Red' worm. Your Windows system seems to be compromised.

Solution:
1) Remove the file root.exe from both directories:
\inetpub\scripts

and

\program files\common files\system\msadc

2) Install an updated antivirus program (this will remove the Explorer.exe Trojan)
3) Set SFCDisable in hklm\software\microsoft\windows nt\currentversion\winlogon to: 0
4) Remove the two newly created virtual directories: C and D (Created by the Trojan)
5) Make sure no other files have been modified.

It is recommended that hosts that have been compromised by Code Red X would reinstall the operating system from scratch and patch it accordingly.

Risk factor : High

Additional information:
http://www.securiteam.com/securitynews/5GP0V004UQ.html
http://www.securiteam.com/windowsntfocus/5WP0L004US.html
http://www.cert.org/advisories/CA-2001-11.html
http://www.microsoft.com/technet/treeview/default.asp?url=/technet/itsolutions/security/tools/redfix.asp

";

 script_description(english:desc["english"]);

 summary["english"] = "CodeRed version X detection";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2001 SecuriTeam");
 family["english"] = "Backdoors";
 script_family(english:family["english"]);

 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/iis");
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");

port = get_kb_item("Services/www");
if (!port) port = 80;
if(!get_port_state(port))exit(0);

soc = http_open_socket(port);
if(soc)
{
 req = http_get(item:"/scripts/root.exe?/c+dir+c:\+/OG", port:port);
 send(socket:soc, data:req);
 buf = http_recv(socket:soc);
 http_close_socket(soc);

 pat1 = "<DIR>";
 pat2 = "Directory of C";
 
 if ( ("This program cannot be run in DOS mode" >< buf) || (pat1 >< buf) || (pat2 >< buf) )
 {
  security_hole(port);
  exit(0);
 }
 else
 {
  soc = http_open_socket(port);
  req = http_get(item:"/c/winnt/system32/cmd.exe?/c+dir+c:\+/OG", port:port);
  send(socket:soc, data:req);

  buf = http_recv(socket:soc);
  http_close_socket(soc);

  if (("This program cannot be run in DOS mode" >< buf) || (pat1 >< buf) || (pat2 >< buf) )
  {
   security_hole(port);
   exit(0);
  }
 }
}

