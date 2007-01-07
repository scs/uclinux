#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added link to the Microsoft Knowledgebase
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10412);
 script_version ("$Revision: 1.11 $");
 
 name["english"] = "SMB Registry : Autologon";
 name["francais"] = "Base de registres: Autologon";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
 This script determines whether the autologon feature
 is enabled. This feature allows an intruder to log
 into the remote host as DefaultUserName with the
 password DefaultPassword.


 Solution : Delete the keys AutoAdminLogon and DefaultPassword
 under HKLM\SOFTWARE\Microsoft\Window NT\CurrentVersion\Winlogon

 Reference : http://www.microsoft.com/windows2000/techinfo/reskit/en-us/regentry/12315.asp

 Risk factor : High
";


 desc["francais"] = "

 Ce script determines si la fonctionnalité 'autologon' est 
 activée sur le NT distant. Celle-ci permet à un pirate
 de se logguer sur la machine en tant que DefaultUserName
 avec le mot de pass DefaultPassword.

 Solution : supprimez les clés AutoAdminLogon et DefaultPassword
 sous HKLM\SOFTWARE\Microsoft\Window NT\CurrentVersion\Winlogon

 Facteur de risque : Elevé";

 script_description(english:desc["english"],
 		    francais:desc["francais"]);
 
 summary["english"] = "Determines if the autologon feature is installed";
 summary["francais"] = "Détermine si la fonctionalité autologon est activée";
 script_summary(english:summary["english"],
 		francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl", "smb_registry_access.nasl");
 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password", "SMB/registry_access");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_nt.inc");

port = get_kb_item("SMB/transport");
if(!port)port = 139;

port = get_kb_item("SMB/transport");
if(!port)port = 139;


access = get_kb_item("SMB/registry_access");
if(!access)exit(0);
#---------------------------------------------------------------------#
# Here is our main()                                                  #
#---------------------------------------------------------------------#



key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
item1 = "DefaultUserName";
item2 = "DefaultPassword";

user = registry_get_sz(key:key, item:item1);
pass = registry_get_sz(key:key, item:item2);

if(user && pass)
{
  rep = "The autologon is enabled on this host." + string("\n") +
        "This allows an attacker to access it as " + user + "/" + pass +
	string("\n\n") +
	string("Solution : using regedt32, delete the items AutoAdminLogon and DefaultPassword\n") + "under HKLM\SOFTWARE\Microsoft\Window NT\CurrentVersion\Winlogon" + string("\nRisk factor : High");
 security_hole(port:port, data:rep);
}
