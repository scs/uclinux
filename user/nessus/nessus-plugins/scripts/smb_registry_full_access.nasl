#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10428);
 script_version ("$Revision: 1.26 $");
 
 name["english"] = "SMB fully accessible registry";
 name["francais"] = "Base de registres completement accessible par SMB";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "

Nessus did not access the remote registry completely,
because this needs to be logged in as administrator.

If you want the permissions / values of all the sensitive
registry keys to be checked for, we recommend that
you fill the 'SMB Login' options in the
'Prefs.' section of the client by the administrator
login name and password.

Risk factor : None";



 desc["francais"] = "
Nessus ne peut pas acceder complètement à la base
de registres, parceque cela nécéssite d'etre loggué
en tant qu'administrateur.

Si vous voulez que Nessus teste les permissions / les valeurs
des clés sensibles de la base de registres, alors nous
recommandons que vous remplissiez les options 'SMB Login'
dans la sections 'Prefs.' du client avec le login
de l'administrateur, ainsi que son mot de passe.";


 script_description(english:desc["english"],
 		    francais:desc["francais"]);
 
 summary["english"] = "Determines whether the remote registry is fully accessible";
 summary["francais"] = "Détermine si la base de registres distante est completement accessible";
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

port = kb_smb_transport();
if(!port)port = 139;
if(!get_port_state(port))exit(0);

y = kb_smb_name();
if(!y)exit(0);

login = kb_smb_login();
if(!login)exit(0);


soc = open_sock_tcp(port);
if(!soc)exit(0);
close(soc);



access = get_kb_item("SMB/registry_access");
if(!access)security_note(port);


key = "SOFTWARE\Microsoft\Internet Explorer\Version Vector";
item = "IE";

value = registry_get_sz(key:key, item:item);
if(value)
{
 set_kb_item(name:"SMB/registry_full_access", value:TRUE);
 exit(0);
}
else {
	key = "SOFTWARE\Microsoft\Internet Explorer";
	item = "IVer";
	value = registry_get_sz(key:key, item:item);
	if(value)
	{
 		set_kb_item(name:"SMB/registry_full_access", value:TRUE);
 		exit(0);
	}
	security_note(port);
     }
