#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10401);
 script_version ("$Revision: 1.22 $");
 script_cve_id("CAN-1999-0662");
 name["english"] = "SMB Registry : NT4 Service Pack version";
 name["francais"] = "Obtention du numéro du service pack de NT4 par SMB";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "

This script reads the registry
key HKLM\SOFTWARE\Microsoft\Windows NT\CSDVersion
to determine the Service Pack the host is running.

Sensitive servers should always run the latest service
pack for security reasons.

Risk factor : Serious / Low
";


 desc["francais"] = "

Ce script lit la clé de la base de registre 
HKLM\SOFTWARE\Microsoft\Windows NT\CSDVersion
pour obtenir la version du Service Pack qui
tourne. 

Les serveurs sensibles devraient toujours
tourner sous les derniers SP.

Facteur de risque : Faible / Moyen";


 script_description(english:desc["english"],
 		    francais:desc["francais"]);
 
 summary["english"] = "Determines the remote SP";
 summary["francais"] = "Détermine le service pack installé";
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
access = get_kb_item("SMB/registry_access");
if(!access)exit(0);

port = get_kb_item("SMB/transport");
if(!port)port = 139;
#---------------------------------------------------------------------#
# Here is our main()                                                  #
#---------------------------------------------------------------------#



key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion";
item = "CurrentVersion";
value = registry_get_sz(key:key, item:item);
if(!get_kb_item("SMB/WindowsVersion") && value)
	set_kb_item(name:"SMB/WindowsVersion", value:value);


if(value == "4.0")
{
item = "CSDVersion";
value = registry_get_sz(key:key, item:item);
if(value)
{
 set_kb_item(name:"SMB/WinNT4/ServicePack", value:value);
 if(ereg(string:value, pattern:"^Service Pack [1-5]$"))
  {
  report = string("The remote WindowsNT is running ", value, "\n",
  	  "You should apply the Service Pack 6a to be up-to-date\n",
	  "Risk factor : High");
  security_hole(data:report, port:port);
  }
 }
}
