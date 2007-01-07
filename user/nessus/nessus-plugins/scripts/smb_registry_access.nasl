#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10400);
 script_version ("$Revision: 1.21 $");
 script_cve_id("CAN-1999-0562");
 
 name["english"] = "SMB accessible registry";
 name["francais"] = "Base de registres accessible par SMB";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "

The remote registry can be accessed remotely
using the login / password combination used
for the SMB tests.

Having the registry accessible to the world is
not a good thing as it gives extra knowledge to
a hacker.

Solution : Apply service pack 3 if not done already,
and set the key HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg
to restrict what can be browsed by non administrators.

In addition to this, you should consider filtering incoming packets
to this port.

Risk factor : Low";


 desc["francais"] = "

La base de registres de cet hote peut etre
consultée à distance en utilisant le login/password
que nous avons utilisé pour les autres tests.

Le fait que celle-ci soit accessible n'est pas une
bonne chose puisque la base de registre contient un
ensemble d'informations interessantes pour un
pirate.

Solution : Appliquez le service pack 3 si ce n'est pas
déjà fait, et configurez la clé HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg
pour restreindre ce qui peut etre visionné par les non admins.

De plus, vous devriez filtrez les paquets allant vers ce port.

Facteur de risque : Faible";


 script_description(english:desc["english"],
 		    francais:desc["francais"]);
 
 summary["english"] = "Determines whether the remote registry is accessible";
 summary["francais"] = "Détermine si la base de registres distante est accessible";
 script_summary(english:summary["english"],
 		francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl");
 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password");
 script_exclude_keys("SMB/samba");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_nt.inc");

port = kb_smb_transport();
if(!port)port = 139;
		 
#---------------------------------------------------------------------#
# Here is our main()                                                  #
#---------------------------------------------------------------------#


samba = get_kb_item("SMB/samba");
if(samba)exit(0);

name = kb_smb_name();
if(!name)exit(0);


if(!get_port_state(port))exit(0);

login = kb_smb_login();
pass  = kb_smb_password();

if(!login)login = "";
if(!pass) pass = "";

dom = kb_smb_domain();
	  
soc = open_sock_tcp(port);
if(!soc)exit(0);

#
# Request the session
# 
r = smb_session_request(soc:soc,  remote:name);
if(!r)exit(0);

#
# Negociate the protocol
#
prot = smb_neg_prot(soc:soc);
if(!prot)exit(0);

#
# Set up our session
#
r = smb_session_setup(soc:soc, login:login, password:pass, domain:dom, prot:prot);
if(!r)exit(0);
# and extract our uid
uid = session_extract_uid(reply:r);

#
# Connect to the remote IPC and extract the TID
# we are attributed
#      
r = smb_tconx(soc:soc, name:name, uid:uid, share:"IPC$");
# and extract our tree id
tid = tconx_extract_tid(reply:r);


#
# Create a pipe to lsarpc
#
r = smbntcreatex(soc:soc, uid:uid, tid:tid);
if(!r)exit(0);
# and extract its ID
pipe = smbntcreatex_extract_pipe(reply:r);

#
# Setup things
#
r = pipe_accessible_registry(soc:soc, uid:uid, tid:tid, pipe:pipe);
if(!r)exit(0);

else {
	security_warning(port);
	set_kb_item(name:"SMB/registry_access", value:TRUE);
     }
