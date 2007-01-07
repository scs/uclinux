#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11818);

 script_version("$Revision: 1.8 $");

 name["english"] = "The remote host is infected by msblast.exe";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host seems to be infected by the MS Blaster worm,
or the Nachi worm, and may make this host attack random hosts on the internet.

Solution : 
 - http://securityresponse.symantec.com/avcenter/venc/data/w32.blaster.worm.html
 - http://securityresponse.symantec.com/avcenter/venc/data/w32.blaster.b.worm.html
 - http://securityresponse.symantec.com/avcenter/venc/data/w32.blaster.c.worm.html
 - http://securityresponse.symantec.com/avcenter/venc/data/w32.blaster.d.worm.html
 - http://securityresponse.symantec.com/avcenter/venc/data/w32.blaster.e.worm.html
 - http://securityresponse.symantec.com/avcenter/venc/data/w32.blaster.f.worm.html
 - http://www.symantec.com/avcenter/venc/data/w32.welchia.worm.html
 - http://www.microsoft.com/technet/security/bulletin/ms03-039.asp

Risk Factor : Critical";




 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of msblast.exe";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl","smb_registry_access.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/registry_access");

 script_require_ports(139, 445);
 exit(0);
}


include("smb_nt.inc");

name	= kb_smb_name(); 	if(!name)exit(0);
login	= kb_smb_login(); 	if(!login)exit(0);
pass	= kb_smb_password(); 	if(!pass)exit(0);
domain  = kb_smb_domain(); 	if(!domain)exit(0);
port	= kb_smb_transport();

if(get_kb_item("SMB/registry_access"))
{
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item = "windows auto update";
value = tolower(registry_get_sz(key:key, item:item));
if(value && ("msblast.exe" >< value || "penis32.exe" >< value || "mspatch.exe"))security_hole(port); 


key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item = "microsoft inet xp..";
value = tolower(registry_get_sz(key:key, item:item));
if(value && "teekids.exe" >< value)security_hole(port); 


# Variant .F
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item = "www.hidro.4t.com";
value = tolower(registry_get_sz(key:key, item:item));
if(value && "enbiei.exe" >< value)security_hole(port); 

# Variant .E
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item = "Windows Automation";
value = tolower(registry_get_sz(key:key, item:item));
if(value && "mslaugh.exe" >< value)security_hole(port); 
}


# Nachi



rootfile = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion", item:"SystemRoot");
if(!rootfile)exit(0);

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:rootfile);
file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\wins\dllhost.exe", string:rootfile);


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

fid = OpenAndX(socket:soc, uid:uid, tid:tid, file:file);
if(fid)security_hole(port);

