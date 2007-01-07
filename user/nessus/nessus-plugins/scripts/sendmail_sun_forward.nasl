#
# This script was written by Renaud Deraison
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11364);
 script_bugtraq_id(7033);
 script_version("$Revision: 1.4 $");
 
 name["english"] = "Sendmail Forward File Privilege Escalation Vulnerability";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote sendmail server, according to its version number,
may be vulnerable to a local privilege escalation vulnerability
when using forward files.

*** Sun did not increase the version number of their sendmail
*** when patching Solaris 7 and 8, so this might be a false
*** positive on these platforms.

An attacker may set up a special .forward file in his
home and send a mail to himself, which will trick sendmail
and will allow him to execute arbitrary commands with
root privileges.

Risk factor : High (local) / None (remote)";
	
 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the version number"; 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 
 family["english"] = "SMTP problems";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "smtpserver_detect.nasl", "nmap_osfingerprint.nes");
 script_require_ports("Services/smtp", 25);
 script_require_keys("SMTP/sendmail");
 exit(0);
}

#
# The script code starts here
#

include("smtp_func.inc");

port = get_kb_item("Services/smtp");
if(!port) port = 25;

banner = get_smtp_banner(port:port);
if(banner)
{
  os = get_kb_item("Host/OS");
  if(("Solaris 2.6" >< os) ||
     ("Solaris 7" >< os)   ||
     ("Solaris 8" >< os))
  { 
     if(egrep(pattern:".*Sendmail ((5\.79.*|5\.[89].*|[67]\..*|8\.[0-9]\..*|8\.10\..*|8\.11\.[0-5])\+Sun/|SMI-[0-8]\.).*", string:banner, icase:TRUE))
 	security_hole(port);
  }
  else if(!os || "Solaris 9" >< os)
  {
   if(egrep(pattern:".*Sendmail (5\.79.*|5\.[89].*|[67]\..*|8\.[0-9]\..*|8\.1[0-1]\..*|8\.12\.[0-7])\+Sun/.*", string:banner, icase:TRUE))
 	security_hole(port);
  }

}
