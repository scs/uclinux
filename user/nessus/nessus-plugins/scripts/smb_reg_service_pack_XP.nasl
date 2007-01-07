#
# This script was written by Georges Dagousset <georges.dagousset@alert4web.com>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11119);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CAN-1999-0662");
 name["english"] = "SMB Registry : XP Service Pack version";
 name["francais"] = "Obtention du numéro du service pack de XP par SMB";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "

This script reads the registry
key HKLM\SOFTWARE\Microsoft\Windows NT\CSDVersion
to determine the Service Pack the host is running.

Sensitive servers should always run the latest service
pack for security reasons.

Risk factor : High 
";


 desc["francais"] = "

Ce script lit la clé de la base de registre 
HKLM\SOFTWARE\Microsoft\Windows NT\CSDVersion
pour obtenir la version du Service Pack qui
tourne. 

Les serveurs sensibles devraient toujours
tourner sous les derniers SP.

Facteur de risque : Elevé";


 script_description(english:desc["english"],
 		    francais:desc["francais"]);
 
 summary["english"] = "Determines the remote SP";
 summary["francais"] = "Détermine le service pack installé";
 script_summary(english:summary["english"],
 		francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 Alert4Web.com");
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
if(!get_kb_item("SMB/WindowsVersion") && value )
	set_kb_item(name:"SMB/WindowsVersion",value:value);

if(value == "5.1")
{
 item = "CSDVersion";
 value = registry_get_sz(key:key, item:item);
 if(value)set_kb_item(name:"SMB/XP/ServicePack", value:value);

 if(!value)
 {
  report = string(
"The remote Windows XP does not have the Service Pack 1 applied.\n",
"You should apply it to be up-to-date\n",
"Risk factor : High\n",
"Solution : go to http://www.microsoft.com/windowsxp/");
  security_hole(data:report, port:port);
  exit(0);
 }
 else
  {
    report = string("The remote Windows XP system has ",value," applied.\n");
    security_note(data:report, port:port);
 }
}
