#
# This script was written by Renaud Deraison
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11329);

 script_version("$Revision: 1.20 $");

 name["english"] = "The remote host is infected by a virus";

 script_name(english:name["english"]);
 
 desc["english"] = "
This script checks for the presence of different virii on the remote
host, by using the SMB credentials you provide Nessus with.

	- W32/Badtrans-B
	- JS_GIGGER.A@mm
	- W32/Vote-A
	- CodeRed 
	- W32.Sircam.Worm@mm
	- W32.Nimda.A@mm
	- W32.Goner.A@mm
	- W32.HLLW.Fizzer@mm
	- W32.Sobig.B@mm
	- W32.Sobig.C@mm
	- W32.Sobig.E@mm
	- W32.Sobig.F@mm
	- W32.Yaha.J@mm
	- W32.Mimail.A@mm
	- W32.Welchia.Worm
	- W32.Swen.a@mm
        - W32.Mimail.C@mm
	
Risk factor : High
Solution : See the URLs which will appear in the report";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of different virii on the remote host";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl","smb_registry_access.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password",  "SMB/registry_access");

 script_require_ports(139, 445);
 exit(0);
}
include("smb_nt.inc");


function check_reg(name, url, key, item, exp)
{
 value = registry_get_sz(key:key, item:item);
 if(!value)return 0;
 
 if(exp == NULL || tolower(exp) >< tolower(value))
 {
  report = string(
"The virus '", name, "' is present on the remote host\n",
"Solution : ", url, "\n",
"Risk factor : High");
 
  security_hole(port:kb_smb_transport(), data:report);
 }
 return 1;
}





i = 0;

# http://www.infos3000.com/infosvirus/badtransb.htm
name[i] 	= "W32/Badtrans-B";
url[i] 		= "http://securityresponse.symantec.com/avcenter/venc/data/w32.badtrans.b@mm.html";
key[i] 		= "Software\Microsoft\Windows\CurrentVersion\RunOnce";
item[i] 	= "kernel32";
exp[i]		= "kernel32.exe";

i++;

# http://www.infos3000.com/infosvirus/jsgiggera.htm
name[i] 	= "JS_GIGGER.A@mm";
url[i] 		= "http://securityresponse.symantec.com/avcenter/venc/data/js.gigger.a@mm.html";
key[i] 		= "Software\Microsoft\Windows\CurrentVersion\Run";
item[i] 	= "NAV DefAlert";
exp[i]		= NULL;

i ++;

# http://www.infos3000.com/infosvirus/vote%20a.htm
name[i]		= "W32/Vote-A";
url[i]		= "http://www.symantec.com/avcenter/venc/data/w32.vote.a@mm.html";
key[i]		= "Software\Microsoft\Windows\CurrentVersion\Run";
item[i]		= "Norton.Thar";
exp[i]		= "zacker.vbs";

i++ ;

# http://www.infos3000.com/infosvirus/codered.htm
name[i]		= "CodeRed";
url[i]		= "http://www.symantec.com/avcenter/venc/data/codered.worm.html";
key[i]		= "SYSTEM\CurrentControlSet\Services\W3SVC\Parameters";
item[i]		= "VirtualRootsVC";
exp[i]		= "c:\,,217";

i ++;

# http://www.infos3000.com/infosvirus/w32sircam.htm
name[i]		= "W32.Sircam.Worm@mm";
url[i]		= "http://www.symantec.com/avcenter/venc/data/w32.sircam.worm@mm.html";
key[i]		= "Software\Microsoft\Windows\CurrentVersion\RunServices";
item[i]		= "Driver32";
exp[i] 		= "scam32.exe";

i++;

name[i]  	= "W32.HLLW.Fizzer@mm";
url[i] 		= "http://securityresponse.symantec.com/avcenter/venc/data/w32.hllw.fizzer@mm.html";
key[i]		= "Software\Microsoft\Windows\CurrentVersion\Run";
item[i]		= "SystemInit";
exp[i]		= "iservc.exe";

i++;

name[i]  	= "W32.Sobig.B@mm";
url[i] 		= "http://securityresponse.symantec.com/avcenter/venc/data/w32.sobig.b@mm.html";
key[i]		= "Software\Microsoft\Windows\CurrentVersion\Run";
item[i]		= "SystemTray";
exp[i]		= "msccn32.exe";

i ++;

name[i]		= "W32.Sobig.E@mm";
url[i]		= "http://securityresponse.symantec.com/avcenter/venc/data/w32.sobig.e@mm.html";
key[i]		= "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]		= "SSK Service";
exp[i]		= "winssk32.exe";

i ++;

name[i]		= "W32.Sobig.F@mm";
url[i]		= "http://securityresponse.symantec.com/avcenter/venc/data/w32.sobig.f@mm.html";
key[i]		= "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]		= "TrayX";
exp[i]		= "winppr32.exe";

i ++;

name[i]		= "W32.Sobig.C@mm";
url[i]		= "http://securityresponse.symantec.com/avcenter/venc/data/w32.sobig.c@mm.html";
key[i]		= "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]		= "System MScvb";
exp[i]		= "mscvb32.exe";

i ++;

name[i] 	= "W32.Yaha.J@mm";
url[i] 		= "http://securityresponse.symantec.com/avcenter/venc/data/w32.yaha.j@mm.html";
key[i]		= "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]		= "winreg";
exp[i]		= "winReg.exe";


i++;

name[i] 	= "W32.mimail.a@mm";
url[i] 		= "http://securityresponse.symantec.com/avcenter/venc/data/w32.mimail.a@mm.html";
key[i]		= "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]		= "VideoDriver";
exp[i]		= "videodrv.exe";


i++;

name[i] 	= "W32.mimail.c@mm";
url[i] 		= "http://securityresponse.symantec.com/avcenter/venc/data/w32.mimail.c@mm.html";
key[i]		= "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]		= "NetWatch32";
exp[i]		= "netwatch.exe";

i++;

name[i] 	= "W32.mimail.e@mm";
url[i] 		= "http://securityresponse.symantec.com/avcenter/venc/data/w32.mimail.e@mm.html";
key[i]		= "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]		= "SystemLoad32";
exp[i]		= "sysload32.exe";

i++;

name[i]        = "W32.Welchia.Worm";
url[i]         = "http://securityresponse.symantec.com/avcenter/venc/data/w32.welchia.worm.html";
key[i]         = "SYSTEM\CurrentControlSet\Services\RpcTftpd";
item[i]        = "ImagePath";
exp[i]         = "%System%\wins\svchost.exe";


i++;

name[i]        = "W32.Randex.Worm";
url[i]         = "http://securityresponse.symantec.com/avcenter/venc/data/w32.randex.b.html";
key[i]         = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]        = "superslut";
exp[i]         = "msslut32.exe";

i++;

name[i]        = "W32.Randex.Worm";
url[i]         = "http://securityresponse.symantec.com/avcenter/venc/data/w32.randex.c.html";
key[i]         = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]        = "Microsoft Netview";
exp[i]         = "gesfm32.exe";

i++;

name[i]        = "W32.Randex.Worm";
url[i]         = "http://securityresponse.symantec.com/avcenter/venc/data/w32.randex.d.html";
key[i]         = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]        = "mssyslanhelper";
exp[i]         = "msmsgri32.exe";


i++;

name[i]        = "W32.Randex.Worm";
url[i]         = "http://securityresponse.symantec.com/avcenter/venc/data/w32.randex.d.html";
key[i]         = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]        = "mslanhelper";
exp[i]         = "msmsgri32.exe";


for(i=0;name[i];i++)
{
  check_reg(name:name, url:url, key:key, item:item, exp:exp);
}




 
rootfile = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion", item:"SystemRoot");
if(!rootfile)exit(0);

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:rootfile);
file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\system.ini", string:rootfile);


name	= kb_smb_name();
login	= kb_smb_login();
pass	= kb_smb_password();
domain  = kb_smb_domain();
port	= kb_smb_transport();

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
if(fid)
{
off = 0;
resp = ReadAndX(socket:soc, uid:uid, tid:tid, fid:fid, count:16384, off:off);
data = resp;
while(strlen(resp) >= 16383)
{
 off += strlen(resp);
 resp = ReadAndX(socket:soc, uid:uid, tid:tid, fid:fid, count:16384, off:off);
 data += resp;
 if(strlen(data) > 1024 * 1024)break;
}

if("shell=explorer.exe load.exe -dontrunold" >< data)
{
  report = string(
"The virus 'W32.Nimda.A@mm' is present on the remote host\n",
"Solution : http://www.symantec.com/avcenter/venc/data/w32.nimda.a@mm.html\n",
"Risk factor : High");
 
  security_hole(port:port, data:report);
 }
}
 
file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\goner.scr", string:rootfile); 
fid = OpenAndX(socket:soc, uid:uid, tid:tid, file:file);
if(fid){
 report = string(
"The virus 'W32.Goner.A@mm' is present on the remote host\n",
"Solution : http://www.symantec.com/avcenter/venc/data/w32.goner.a@mm.html\n",
"Risk factor : High"); 
security_hole(port:port, data:report);
}




file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\Swen1.dat", string:rootfile); 
fid = OpenAndX(socket:soc, uid:uid, tid:tid, file:file);
if(fid){
 report = string(
"The virus 'W32.Swen.A@mm' is present on the remote host\n",
"Solution : http://securityresponse.symantec.com/avcenter/venc/data/w32.swen.a@mm.html\n",
"Risk factor : High"); 
security_hole(port:port, data:report);
}
