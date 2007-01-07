#
# (C) Tenable Network Security
#
# Ref: http://www.microsoft.com/technet/security/bulletin/ms03-035.asp

if(description)
{
 script_id(11831);
 script_cve_id("CAN-2003-0664", "CAN-1999-0354");
 script_bugtraq_id(8533);
 
 script_version("$Revision: 1.2 $");

 name["english"] = "Word Macros may run automatically";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of Microsoft Word which is
subject to a flaw in the way it handles the execution of macro commands.

An attacker may use this to execute arbitrary code on this host.

To succeed, the attacker would have to send a rogue word
file to the owner of this computer and have it open it. Then the
macros contained in the word file would bypass the security model
of word, and would be executed.

Solution : See http://www.microsoft.com/technet/security/bulletin/ms03-035.asp
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of WinWord.exe";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("smb_nt_ms02-031.nasl");
 script_require_keys("SMB/Office/Word/Version");
 exit(0);
}

v = get_kb_item("SMB/Office/Word/Version");
if(!v)exit(0);
if(ereg(pattern:"10\..*", string:v))
  {
  # Word 2002 - updated in 10.0.5522.0
  middle =  ereg_replace(pattern:"10\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
  if(middle != v && int(middle) < 5522)security_hole(port);
  }
else if(ereg(pattern:"9\..*", string:v))
{
 # Word 2000 - fixed in 9.00.00.7924
 sub =  ereg_replace(pattern:"9\.00?\.00?\.\([0-9]*\)$", string:v, replace:"\1");
 if(sub != v && int(sub) < 7924)security_hole(port);
}
else if(ereg(pattern:"9\..*", string:v))
{
 # Word 97 - fixed in 8.0.0.8125
 sub =  ereg_replace(pattern:"8\.00?\.00?\.\([0-9]*\)$", string:v, replace:"\1");
 if(sub != v && int(sub) < 8125)security_hole(port);
}
