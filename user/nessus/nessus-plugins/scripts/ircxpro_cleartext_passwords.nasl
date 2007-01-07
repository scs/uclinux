#
# (C) Tenable Network Security
#
# 
#Ref: 
# From: "morning_wood" <se_cur_ity@hotmail.com>
# To: <bugtraq@securityfocus.com>
# Subject: IRCXpro 1.0 - Clear local and default remote admin passwords
# Date: Tue, 3 Jun 2003 00:57:45 -0700

if(description)
{
 script_id(11696);
 script_bugtraq_id(7792);
 script_version ("$Revision: 1.4 $");
 
 
 name["english"] = "IRCXPro Clear Text Passwords";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote web server is running IRCXPro.

This software stores the list of user names and passwords 
in clear text in \Program Files\IRCXPro\Settings.ini

An attacker with a full access to this host may use this flaw
to gain the list of passwords of your users.

Solution : Upgrade to IRCXPro 1.1 or newer
Risk Factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks settings.init";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 script_require_ports(139, 445);
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl","smb_registry_access.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password",
		     "SMB/domain","SMB/transport");
 exit(0);
}

include("smb_nt.inc");
rootfile = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion", item:"ProgramFilesDir");
if(!rootfile)
{
 exit(0);
}
else
{
 share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:rootfile);
 db =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\IRCXPro\settings.ini", string:rootfile);
}




name 	=  kb_smb_name();
login	=  kb_smb_login();
pass  	=  kb_smb_password();
domain 	=  kb_smb_domain();
port    =  kb_smb_transport();
if(!port) port = 139;



if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);



r = smb_session_request(soc:soc, remote:name);
if(!r)exit(0);

prot = smb_neg_prot(soc:soc);
if(!prot)exit(0);

r = smb_session_setup(soc:soc, login:login, password:pass, domain:domain, prot:prot);
if(!r)exit(0);

uid = session_extract_uid(reply:r);



r = smb_tconx(soc:soc, name:name, uid:uid, share:share);
tid = tconx_extract_tid(reply:r);
if(!tid)exit(0);


fid = OpenAndX(socket:soc, uid:uid, tid:tid, file:db);
if(fid)
{
 security_warning(port);
 exit(0);
}


