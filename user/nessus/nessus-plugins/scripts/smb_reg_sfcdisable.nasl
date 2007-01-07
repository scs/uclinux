#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added link to the Bugtraq message archive and Microsoft Knowledgebase
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10449);
 script_version ("$Revision: 1.13 $");
 
 name["english"] = "SMB Registry : value of SFCDisable";
 name["francais"] = "Valeur de SFCDisable par SMB";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "

The registry key 
HKLM\SOFTWARE\Microsoft\Windows NT\WinLogon\SFCDisable
has its value set to 0xFFFFFF9D. 

This special value disables the Windows File Protection,
which allows any user on the remote host to view / modify
any file he wants.

This probably means that this host has been compromised.

Solution : set the value of this key to 0. You should reinstall
           this host

Reference : http://online.securityfocus.com/archive/1/66849
Reference : http://support.microsoft.com/default.aspx?scid=kb;en-us;Q222473

Risk factor : High
";


 desc["francais"] = "

La clé HKLM\SOFTWARE\Microsoft\Windows NT\WinLogon\SFCDisable
de la base de registre a sa valeur mise à
0xFFFFFF9D.

Cette valeur spéciale désactive la protection des fichiers,
ce qui permet à n'importe quel utilisateur local de lire / modifier
des fichiers arbitraires sur ce serveur.

Cela signifie certainement que ce système a est compromis.

Solution : mettez la valeur de cette clé à 0. Vous devriez
           réinstaller cette machine.
Facteur de risque : Elevé";


 script_description(english:desc["english"],
 		    francais:desc["francais"]);
 
 summary["english"] = "Determines the value of SFCDisable";
 summary["francais"] = "Détermine la valeur de SFCDisable";
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


key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon";
item = "SFCDisable";


value = registry_get_dword(key:key, item:item);
if(!isnull(value) && value != 0)
{
 security_hole(port);
}
