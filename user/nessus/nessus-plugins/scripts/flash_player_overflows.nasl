#
#
# This script was written by Renaud Deraison
#
# See the Nessus Scripts License for details
#
# Ref: http://www.macromedia.com/v1/handlers/index.cfm?ID=23821
#
# There's an old SWFlash.ocx which lies around when
# the new version is installed. Not sure what we should
# do with it.

if(description)
{
 script_id(11323);
 script_bugtraq_id(7005);

 script_version("$Revision: 1.9 $");

 name["english"] = "Security issues in the remote version of FlashPlayer";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host has an old version of the Flash Player plugin installed.

An attacker may use this flaw to construct a malicious web site which
with a badly formed flash animation which will cause a buffer overflow
on this host, and allow him to execute arbitrary code with the
privileges of the user running internet explorer.

Solution : Upgrade to version 6.0.79.0 or newer.
See also : http://www.macromedia.com/v1/handlers/index.cfm?ID=23821
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of the remote flash plugin";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl","smb_registry_access.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password",
		     "SMB/WindowsVersion",
		     "SMB/registry_access");

 script_require_ports(139, 445);
 exit(0);
}


include("smb_nt.inc");



rootfile = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion", item:"SystemRoot");
if(!rootfile)
{
 exit(0);
}
else
{
 share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:rootfile);
 file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:rootfile);
}


name 	= kb_smb_name();
login	= kb_smb_login();
pass  	= kb_smb_password();
domain 	= kb_smb_domain();
port    = kb_smb_transport();
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

fid = OpenAndX(socket:soc, uid:uid, tid:tid, file:string(file, "\\System32\\Macromed\\Flash\\Flash.ocx"));
if(!fid)fid = OpenAndX(socket:soc, uid:uid, tid:tid, file:string(file, "\\System32\\Macromed\\Flash\\SWFlash.ocx"));

off = 0;
resp = ReadAndX(socket:soc, uid:uid, tid:tid, fid:fid, count:16384, off:off);
data = resp;
while(strlen(resp) >= 16383)
{
 off += 16384;
 resp = ReadAndX(socket:soc, uid:uid, tid:tid, fid:fid, count:16384, off:off);
 data += resp;
 if(strlen(data) > 1024*1024)break;
}



vers = strstr(data, "$version");
if(!vers){
	exit(0); # No version string ?
	}


version = "";
for(i=12;i<50;i++)
{ 
 if(ord(vers[i]) == 0)break;
 version = strcat(version, vers[i]);
}

if(ereg(pattern:"WIN .*", string:version))
{
 set_kb_item(name:"MacromediaFlash/version", value:version);
}

if(ereg(pattern:"WIN (([0-5],.*)|(6,0,([0-6][0-9]?,|7[0-8],))).*", string:version))security_hole(port);
