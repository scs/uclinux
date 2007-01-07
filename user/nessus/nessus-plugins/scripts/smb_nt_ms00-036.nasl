#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10434);
 script_version ("$Revision: 1.15 $");
 script_bugtraq_id(1262);
 script_cve_id("CVE-2000-0404");
 name["english"] = "NT ResetBrowser frame & HostAnnouncement flood patc";
 name["francais"] = "Patch ResetBrowser frame & HostAnnouncement flood";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
The hotfix for the 'ResetBrowser Frame' and the 'HostAnnouncement flood'
has not been applied.

The first of these vulnerabilities allows anyone to shut
down the network browser of this host at will.

The second vulnerability allows an attacker to
add thousands of bogus entries in the master browser,
which will consume most of the network bandwidth as
a side effect.


Solution : See http://www.microsoft.com/technet/security/bulletin/ms00-036.asp
Risk factor : Medium";


 desc["francais"] = "
Le hotfix pour les vulnérabilités 'ResetBrowser Frame' et
'HostAnnouncement flood' n'a pas été appliqué.

La première de ces vulnérabilités permet à n'importe
qui d'éteindre le network browser de cette machine.

La seconde permet à un pirate d'ajouter des milliers
d'entrées bidons dans le master browser, ce qui finit
par créer un traffic réseau très important, pouvant
saturer le réseau local.

Solution : cf http://www.microsoft.com/technet/security/bulletin/ms00-036.asp
Facteur de risque : Moyen";


 script_description(english:desc["english"],
 		    francais:desc["francais"]);
 
 summary["english"] = "Determines whether the hotfix Q262694 is installed";
 summary["francais"] = "Détermine si le hotfix Q262694 est installé";
 script_summary(english:summary["english"],
 		francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl", "smb_registry_access.nasl",
		     "smb_reg_service_pack_W2K.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/registry_access");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_nt.inc");
port = get_kb_item("SMB/transport");
if(!port)port = 139;
#---------------------------------------------------------------------#
# Here is our main()                                                  #
#---------------------------------------------------------------------#
access = get_kb_item("SMB/registry_access");
if(!access)exit(0);


sp=get_kb_item("SMB/Win2K/ServicePack");

if(ereg(string:sp, pattern:"^Service Pack [2-9]"))exit(0);

version = get_kb_item("SMB/WindowsVersion");
#exit if XP Pro or newer
if (ereg(pattern:"([6-9]\.[0-9])|(5\.[1-9])", string:version))exit(0);
	
key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\HotFix\Q299444";
item = "Comments";
# included in service rollup q299444"

value = registry_get_sz(key:key, item:item);
if(value)exit(0);
key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\HotFix\Q262694";
value = registry_get_sz(key:key, item:item);
if(!value)security_hole(port);
