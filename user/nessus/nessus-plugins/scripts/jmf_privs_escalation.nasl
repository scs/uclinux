#
# (C) Tenable Network Security
#
# See the Nessus Scripts License for details
#
# Ref: http://sunsolve.sun.com/pub-cgi/retrieve.pl?doc=fsalert%2F54760&zone_32=category%3Asecurity

if(description)
{
 script_id(11635);
 
 script_version("$Revision: 1.1 $");

 name["english"] = "Java Media Framework (JMF) Vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using Sun Microsystems's Java Media Framework (JMF).

There is a bug in the version installed which may allow an untrusted
applet to crash the Java Virtual Machine it is being run on, or even
to gain unauthorized privileges.

An attacker could exploit this flaw to execute arbitrary code on
this host. To exploit this flaw, the attacker would need to 
send a rogue java applet to a user of the remote host and have
him execute it (since Java applets are running in a sandbox,
a user may probably feel safe executing it). 


Solution : Upgrade to JMF 2.1.1e or newer
Risk : Medium";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of JMF";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl","smb_registry_access.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password",
		     "SMB/WindowsVersion",
		     "SMB/registry_access");

 script_require_ports(139, 445);
 exit(0);
}


include("smb_nt.inc");


version = registry_get_sz(key:"SOFTWARE\Sun Microsystems, Inc.\JMF", item:"LatestVersion");
if(!version)
{
 exit(0);
}
else if(ereg(pattern:"2\.1\.1($|[a-d])$", string:version))security_warning(port);
