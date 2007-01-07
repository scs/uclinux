#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10531);
 script_version ("$Revision: 1.24 $");
 script_cve_id("CAN-1999-0662");
 script_bugtraq_id(7930, 8090, 8128, 8154);
 name["english"] = "SMB Registry : Win2k Service Pack version";
 name["francais"] = "Obtention du numéro du service pack de Win2k par SMB";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "

This script reads the registry
key HKLM\SOFTWARE\Microsoft\Windows NT\CSDVersion
to determine the Service Pack the host is running.

Sensitive servers should always run the latest service
pack for security reasons.

Risk factor : Medium 
";


 desc["francais"] = "

Ce script lit la clé de la base de registre 
HKLM\SOFTWARE\Microsoft\Windows NT\CSDVersion
pour obtenir la version du Service Pack qui
tourne. 

Les serveurs sensibles devraient toujours
tourner sous les derniers SP.

Facteur de risque : Moyen";


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
if(!get_kb_item("SMB/WindowsVersion") && value)set_kb_item(name:"SMB/WindowsVersion",value:value);

if(value == "5.0")
{
 item = "CSDVersion";
 value = registry_get_sz(key:key, item:item);
 if(value)set_kb_item(name:"SMB/Win2K/ServicePack", value:value);

 if((!value)||
   (ereg(pattern:"Service Pack [123]",string:value)))
 {
  report = string(
"The remote Windows 2000 does not have the Service Pack 4 applied.\n",
"(it uses ", value, " instead)\n",
"You should apply it to be up-to-date\n",
"Risk factor : High\n",
"Solution : go to http://www.microsoft.com/windows2000/downloads/");
  security_hole(data:report, port:port);
  exit(0);
 }
 else
  {
    report = string("The remote Windows 2000 system has ",value," applied.\n");
 }
}
