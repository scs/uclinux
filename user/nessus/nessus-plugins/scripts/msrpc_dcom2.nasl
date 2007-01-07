#
# (C) Tenable Network Security
#
# v1.2: use the same requests as MS checktool
# v1.16: use one of eEye's request when a null session can't be established
#
if(description)
{
 script_id(11835);
 script_cve_id("CAN-2003-0715", "CAN-2003-0528", "CAN-2003-0605");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-A-0012");
 script_bugtraq_id(8458);


 script_version ("$Revision: 1.23 $");
 
 name["english"] = "Microsoft RPC Interface Buffer Overrun (KB824146)";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of Windows which has a flaw in 
its RPC interface, which may allow an attacker to execute arbitrary code 
and gain SYSTEM privileges. 

An attacker or a worm could use it to gain the control of this host.

Note that this is NOT the same bug as the one described in MS03-026 
which fixes the flaw exploited by the 'MSBlast' (or LoveSan) worm.
 
Solution: see http://www.microsoft.com/technet/security/bulletin/MS03-039.asp 
Risk factor : High";
 
 script_description(english:desc["english"]);
 
 summary["english"] = "Checks if the remote host has a patched RPC interface (KB824146)";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Gain root remotely";
 script_family(english:family["english"]);
 script_require_ports("Services/msrpc", 135, 139, 593); 
 exit(0);
}

#
# The script code starts here
#

include("smb_nt.inc");


function open_wkssvc(soc, uid, tid)
{
 local_var uid_lo, uid_hi, tid_lo, tid_hi, r;
 
 uid_lo = uid % 256;
 uid_hi = uid / 256;
 
 tid_lo = tid % 256;
 tid_hi = tid / 256;
 

 r = raw_string(   0x00, 0x00,
 		   0x00, 0x64, 0xFF, 0x53, 0x4D, 0x42, 0xA2, 0x00,
		   0x00, 0x00, 0x00, 0x18, 0x07, 0xC8, 0x00, 0x00,
		   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		   0x00, 0x00, tid_lo, tid_hi, 0x00, 0x28,uid_lo, uid_hi,
		   0x00, 0x00, 0x18, 0xFF, 0x00, 0xDE, 0xDE, 0x00,
		   0x0E, 0x00, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00,
		   0x00, 0x00, 0x9F, 0x01, 0x02, 0x00, 0x00, 0x00,
		   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		   0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00,
		   0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x01, 0x00,
		   0x00, 0x00, 0x01, 0x11, 0x00, 0x00, 0x5C, 0x00,
		   0x77, 0x00, 0x6b, 0x00, 0x73, 0x00, 0x73, 0x00,
		   0x76, 0x00, 0x63, 0x00, 0x00, 0x00);

 send(socket:soc, data:r);
 r = smb_recv(socket:soc, length:4096);
 
 if(strlen(r) < 65)return(NULL);
 else
  {
   fid_lo = ord(r[42]);
   fid_hi = ord(r[43]);
   return(fid_lo + (fid_hi * 256));
  }
}

function bind(soc, uid, tid, fid)
{ 
 local_var uid_lo, uid_hi, tid_lo, tid_hi, fid_lo, fid_hi, r;
 
 uid_lo = uid % 256;
 uid_hi = uid / 256;
 
 tid_lo = tid % 256;
 tid_hi = tid / 256;
 
 fid_lo = fid % 256;
 fid_hi = fid / 256;
 
 r = raw_string(0x00, 0x00,
 		0x00, 0x9C, 0xFF, 0x53, 0x4D, 0x42, 0x25, 0x00,
		0x00, 0x00, 0x00, 0x18, 0x07, 0xC8, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, tid_lo, tid_hi, 0x00, 0x28, uid_lo, uid_hi,
		0x00, 0x00, 0x10, 0x00, 0x00, 0x48, 0x00, 0x00,
		0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54, 
		0x00, 0x48, 0x00, 0x54, 0x00, 0x02, 0x00, 0x26, 
		0x00, fid_lo, fid_hi, 0x59, 0x00, 0x05, 0x5C, 0x00,
		0x50, 0x00, 0x49, 0x00, 0x50, 0x00, 0x45, 0x00,
		0x5C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00,
		0x0B, 0x03, 0x10, 0x00, 0x00, 0x00, 0x48, 0x00,
		0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xB8, 0x10,
		0xB8, 0x10, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x98, 0xD0,
		0xFF, 0x6B, 0x12, 0xA1, 0x10, 0x36, 0x98, 0x33,
		0x46, 0xC3, 0xF8, 0x7E, 0x34, 0x5a, 0x01, 0x00,
		0x00, 0x00, 0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c,
		0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2B, 0x10,
		0x48, 0x60, 0x02, 0x00, 0x00, 0x00);

 send(socket:soc, data:r);
 r = smb_recv(socket:soc, length:4096);
 
 
 return r;
}


function get_wks_info(soc, uid, tid, fid)
{
  local_var uid_lo, uid_hi, tid_lo, tid_hi, fid_lo, fid_hi, r, name, len;
  local_var len_hi, len_lo, uname, i, wks, dce, smb;
 
 uid_lo = uid % 256;
 uid_hi = uid / 256;
 
 tid_lo = tid % 256;
 tid_hi = tid / 256;
 
 fid_lo = fid % 256;
 fid_hi = fid / 256;
 
 name = "\\" + get_host_ip();
 
 for(i=0;i<strlen(name);i++)
 { 
  uname += name[i] + raw_string(0);
 }
 
 uname += raw_string(0, 0);
 if((strlen(name) & 1) == 0)uname += raw_string(0, 0);
 
 len = strlen(name) + 1;
 len_hi = len / 256;
 len_lo = len % 256;
 
 
 wks = raw_string(0xB0, 0x3D, 
 		  0x7F, 0x00, len_lo, len_hi, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, len_lo, len_hi, 0x00, 0x00) + uname +
	raw_string(0x64, 0x00, 0x00, 0x00);


	
 
 len = 24 + strlen(wks);
 len_hi = len / 256;
 len_lo = len % 256;
 
 dce = raw_string(0x05, 0x00,
 	 	  0x00, 0x03, 0x10, 0x00, 0x00, 0x00, len_lo, len_hi,
		  0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x34, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00) + wks;
		  

 
  
 
		     
  smbpipe2 = raw_string(    0x05, 0x5C, 0x00,
 		     0x50, 0x00, 0x49, 0x00, 0x50, 0x00, 0x45, 0x00, 
		     0x5C, 0x00, 0x00, 0x00, 0x00, 0x00) + dce;
		     
		     
  len = strlen(smbpipe2);
  len_hi = len / 256;
  len_lo = len % 256;
  		
  smbpipe = raw_string(0x26, 0x00, fid_lo, fid_hi, len_lo, len_hi) + smbpipe2;
		     
		     						  
 
 smb = raw_string(	      0xFF, 0x53, 0x4D, 0x42, 0x25, 0x00,
 		  0x00, 0x00, 0x00, 0x18, 0x07, 0xc8, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, tid_lo, tid_hi, 0x00, 0x28, uid_lo, uid_hi,
		  0x00, 0x00, 0x10, 0x00, 0x00, strlen(dce) % 256, strlen(dce) / 256, 0x00,
		  0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54,
		  0x00, strlen(dce) % 256, strlen(dce) / 256, 0x54, 0x00, 0x02, 0x00) + smbpipe;
		  
 netbios = raw_string(0, 0, strlen(smb) / 256, strlen(smb) % 256) + smb;
 send(socket:soc, data:netbios);
 r = smb_recv(socket:soc, length:4096);
 if(strlen(r) < 120)return NULL;
 
 len = ord(r[120]) + (ord(r[121]) * 256);
 len --;
 name = NULL;
 for(i=124;i<124 + len*2;i+=2)
 {
  name += r[i];
 }
 return name;
}


function get_smb_host_name()
{
local_var r, soc, uid;

if(!get_port_state(139))return NULL;
soc = open_sock_tcp(139);
if(!soc)return NULL;

r = smb_session_request(soc:soc, remote:"*SMBSERVER");
if(!r)return NULL;

prot = smb_neg_prot(soc:soc);
if(!prot)return NULL;

r = smb_session_setup(soc:soc, login:"", password:"", domain:"", prot:prot);
if(!r)return NULL;

uid = session_extract_uid(reply:r);

r = smb_tconx(soc:soc, name:"*SMBSERVER", uid:uid, share:"IPC$");
tid = tconx_extract_tid(reply:r);
if(!tid)return NULL;

fid = open_wkssvc(soc:soc, uid:uid, tid:tid);

r = bind(soc:soc, uid:uid, tid:tid, fid:fid);

r = get_wks_info(soc:soc, uid:uid, tid:tid, fid:fid);
close(soc);
return r;
}





function dcom_recv(socket)
{
 local_var buf, len;
 
 buf = recv(socket:socket, length:10);
 if(strlen(buf) != 10)return NULL;
 
 len = ord(buf[8]);
 len += ord(buf[9])*256;
 buf += recv(socket:socket, length:len - 10);
 return buf;
}
 

port = 135;
if(!get_port_state(port))port = 593;
else {
 soc = open_sock_tcp(port);
 if(!soc)port = 593;
 else close(soc);
}
if(!get_port_state(port))exit(0);

#-------------------------------------------------------------#

function hex2raw(s)
{
 local_var i, j, ret;
 
 for(i=0;i<strlen(s);i+=2)
 {
  if(ord(s[i]) >= ord("0") && ord(s[i]) <= ord("9"))
  	j = int(s[i]);
  else
  	j = int((ord(s[i]) - ord("a")) + 10);

  j *= 16;
  if(ord(s[i+1]) >= ord("0") && ord(s[i+1]) <= ord("9"))
  	j += int(s[i+1]);
  else
  	j += int((ord(s[i+1]) - ord("a")) + 10);
  ret += raw_string(j);
 }
 return ret;
}

#--------------------------------------------------------------#
function check(req)
{ 
 local_var soc, bindstr, error_code, r;
 
 
 soc = open_sock_tcp(port);
 if(!soc)exit(0);

 bindstr = "05000b03100000004800000001000000d016d016000000000100000000000100a001000000000000c00000000000004600000000045d888aeb1cc9119fe808002b10486002000000";
 send(socket:soc, data:hex2raw(s:bindstr));
 r = dcom_recv(socket:soc);
 if(!r)exit(0);

 send(socket:soc, data:req);
 r = dcom_recv(socket:soc);
 if(!r)return NULL;

 close(soc);
 error_code = substr(r, strlen(r) - 4, strlen(r) - 1);

 return error_code;
}

function check2(req)
{ 
 local_var soc,bindstr, error_code, r;
 
 
 soc = open_sock_tcp(port);
 if(!soc)exit(0);

 bindstr = "05000b03100000004800000001000000d016d016000000000100000000000100a001000000000000c00000000000004600000000045d888aeb1cc9119fe808002b10486002000000";
 send(socket:soc, data:hex2raw(s:bindstr));
 r = dcom_recv(socket:soc);
 if(!r)exit(0);

 send(socket:soc, data:req);
 r = dcom_recv(socket:soc);
 close(soc);
 if(!r)return NULL;


 error_code = substr(r, strlen(r) - 8, strlen(r) - 5);
 return error_code;
}


function check3(req)
{
 local_var soc,bindstr, error_code, r;
 
 
 soc = open_sock_tcp(port);
 if(!soc)exit(0);

 bindstr = "05000b03100000004800000002000000d016d016000000000100000001000100b84a9f4d1c7dcf11861e0020af6e7c5700000000045d888aeb1cc9119fe808002b10486002000000";



 send(socket:soc, data:hex2raw(s:bindstr));
 r = dcom_recv(socket:soc);
 if(!r)exit(0);

 send(socket:soc, data:req);
 r = dcom_recv(socket:soc);
 close(soc);
 if(!r)return NULL;


 error_code = substr(r, strlen(r) - 24, strlen(r) - 21);
 return error_code;
}


function check4(req)
{
  local_var soc,bindstr, error_code, r;
 
 
 soc = open_sock_tcp(port);
 if(!soc)exit(0);

 bindstr = "05000b03100000004800000002000000d016d016000000000100000001000100b84a9f4d1c7dcf11861e0020af6e7c5700000000045d888aeb1cc9119fe808002b10486002000000";



 send(socket:soc, data:hex2raw(s:bindstr));
 r = dcom_recv(socket:soc);
 if(!r)exit(0);

 send(socket:soc, data:req);
 r = dcom_recv(socket:soc);
 if(!r)return NULL;
 close(soc);


 error_code = substr(r, strlen(r) - 24, strlen(r) - 21);
 return error_code;
}


function check6(req)
{
  local_var soc,bindstr, error_code, r;
 
 
 soc = open_sock_tcp(port);
 if(!soc)exit(0);

 bindstr = "05000b031000000048000000deadbeefd016d016000000000100000000000100b84a9f4d1c7dcf11861e0020af6e7c5700000000045d888aeb1cc9119fe808002b10486002000000";





 send(socket:soc, data:hex2raw(s:bindstr));
 r = dcom_recv(socket:soc);
 if(!r)exit(0);

 send(socket:soc, data:req);
 r = dcom_recv(socket:soc);
 close(soc);
 if(!r)return NULL;


 error_code = substr(r, strlen(r) - 24, strlen(r) - 21);
 return error_code;
}

function req5()
{
 local_var name, buf, uname;
 

 name = get_smb_host_name();	
 if(!name)return NULL;
 
 name = "\\" + name + "\C$\";
 
 len = strlen(name) + 1;
 
 for(i=0;i<strlen(name);i++)
 { 
  uname += name[i] + raw_string(0);
 }
 
 if((strlen(name) & 1) == 0)  uname += raw_string(0, 0);
 
 
 len_lo = len % 256;
 len_hi = len / 256;
 
 
 
 buf = raw_string(0x05, 0x00,
 	0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x95, 0x96,
	0x95, 0x2A, 0x8c, 0xDA, 0x6D, 0x4a, 0xb2, 0x36,
	0x19, 0xBC, 0xAF, 0x2C, 0x2d, 0xea, 0x30, 0xeb,
	0x8F, 0x00, len_lo, len_hi, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, len_lo, len_hi, 0x00, 0x00) + uname +
	raw_string(
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00,
	0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00,
	0x00, 0x00, 0xdc, 0xea, 0x8f, 0x00, 0x01, 0x00,
	0x00, 0x00, 0x95, 0x96, 0x95, 0x2A, 0x8C, 0xDA,
	0x6D, 0x4a, 0xb2, 0x36, 0x19, 0xbc, 0xaf, 0x2c,
	0x2d, 0xea, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00,
	0x00, 0x00, 0x5C, 0x00);
 
 len  = strlen(buf);
 len_lo = len % 256;
 len_hi = len / 256;
 tlen = len + 24;
 tlen_lo = tlen % 256;
 tlen_hi = tlen / 256;
 head = raw_string(0x05, 0x00,
 	0x00, 0x03, 0x10, 0x00, 0x00, 0x00, tlen_lo, tlen_hi,
	0x00, 0x00, 0x02, 0x00, 0x00, 0x00, len_lo,len_hi,
	0x00, 0x00, 0x01, 0x00, 0x00, 0x00) + buf;
 
 return head;
}

#---------------------------------------------------------------#


# Determine if we the remote host is running Win95/98/ME
bindwinme = "05000b03100000004800000053535641d016d016000000000100000000000100e6730ce6f988cf119af10020af6e72f402000000045d888aeb1cc9119fe808002b10486002000000";
soc = open_sock_tcp(port);
if(!soc)exit(0);
send(socket:soc, data:hex2raw(s:bindwinme));
rwinme = dcom_recv(socket:soc);
if(!rwinme)exit(0);
close(soc);
lenwinme = strlen(rwinme);
stubwinme = substr(rwinme, lenwinme-24, lenwinme-21);

# This is Windows 95/98/ME which is not vulnerable
if("02000100" >< hexstr(stubwinme))exit(0);


#----------------------------------------------------------------#

REGDB_CLASS_NOTREG = "5401048000";
CO_E_BADPATH = "0400088000";
NT_QUOTE_ERROR_CODE_EQUOTE = "00000000";



#
req1 = "0500000310000000b00300000100000098030000000004000500020000000000000000000000000000000000000000000000000000000000000000009005140068030000680300004d454f5704000000a201000000000000c0000000000000463803000000000000c0000000000000460000000038030000300300000000000001100800ccccccccc80000000000000030030000d80000000000000002000000070000000000000000000000000000000000000018018d00b8018d000000000007000000b901000000000000c000000000000046ab01000000000000c000000000000046a501000000000000c000000000000046a601000000000000c000000000000046a401000000000000c000000000000046ad01000000000000c000000000000046aa01000000000000c0000000000000460700000060000000580000009000000058000000200000006800000030000000c000000001100800cccccccc5000000000000000ffffffff0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001100800cccccccc4800000000000000005d889aeb1cc9119fe808002b1048601000000000000000000000000100000000000000b8470a005800000005000600010000000000000000000000c000000000000046cccccccc01100800cccccccc80000000000000000000000000000000000000000000000020ba09000000000060000000600000004d454f5704000000c001000000000000c0000000000000463b03000000000000c000000000000046000000003000000001000100673c70941333fd4687244d093988939d0200000000000000000000000000000000000000000000000100000001100800cccccccc480000000000000000000000b07e09000000000000000000f0890a0000000000000000000d000000000000000d000000730061006a00690061006400650076005f0078003800360000000800cccccccc01100800cccccccc10000000000000000000000000000000000000000000000001100800cccccccc5800000000000000c05e0a000000000000000000000000001b000000000000001b0000005c005c0000005c006a00690061006400650076005f007800000036005c007000750062006c00690063005c004100410041004100000000000100150001100800cccccccc200000000000000000000000905b09000200000001006c00c0df0800010000000700550000000000";

req2 = "0500000310000000b00300000200000098030000000004000500020000000000000000000000000000000000000000000000000000000000000000009005140068030000680300004d454f5704000000a201000000000000c0000000000000463803000000000000c0000000000000460000000038030000300300000000000001100800ccccccccc80000000000000030030000d80000000000000002000000070000000000000000000000000000000000000018018d00b8018d000000000007000000b901000000000000c000000000000046ab01000000000000c000000000000046a501000000000000c000000000000046f601000000000000c000000000000046ff01000000000000c000000000000046ad01000000000000c000000000000046aa01000000000000c0000000000000460700000060000000580000009000000058000000200000006800000030000000c000000001100800cccccccc5000000000000000ffffffff0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001100800cccccccc4800000000000000005d889aeb1cc9119fe808002b1048601000000000000000000000000100000000000000b8470a005800000005000600010000000000000000000000c000000000000046cccccccc01100800cccccccc80000000000000000000000000000000000000000000000020ba09000000000060000000600000004d454f5704000000c001000000000000c0000000000000463b03000000000000c000000000000046000000003000000001000100673c70941333fd4687244d093988939d0200000000000000000000000000000000000000000000000100000001100800cccccccc480000000000000000000000b07e09000000000000000000f0890a0000000000000000000d000000000000000d000000730061006a00690061006400650076005f0078003800360000000800cccccccc01100800cccccccc10000000000000000000000000000000000000000000000001100800cccccccc5800000000000000c05e0a000000000000000000000000001b000000000000001b0000005c005c0000005c006a00690061006400650076005f007800000036005c007000750062006c00690063005c004100410041004100000000000100150001100800cccccccc200000000000000000000000905b09000200000001006c00c0df0800010000000700550000000000";


req3  = "05000e03100000004800000003000000d016d01605af00000100000001000100b84a9f4d1c7dcf11861e0020af6e7c5700000000045d888aeb1cc9119fe808002b10486002000000";
req4 = "05000003100000009a00000003000000820000000100000005000200000000000000000000000000000000000000000000000000000000009596952a8cda6d4ab23619bcaf2c2dea34eb8f000700000000000000070000005c005c004d0045004f00570000000000000000005c0048005c0048000100000058e98f00010000009596952a8cda6d4ab23619bcaf2c2dea01000000010000005c00";





#display(hex2raw(s:req));
#exit(0);



 
 

error1 = check(req:hex2raw(s:req1));
error2 = check(req:hex2raw(s:req2)); 


error3 = check(req:hex2raw(s:req3));
error4 = check2(req:hex2raw(s:req4));
error5 = NULL;
null_session_failed = 0;

if(hexstr(error1) == "00000000")
 {
  req = req5();
  if(req)
  	error5 = check4(req:req);
  else null_session_failed = 1;	
 }

#display("error1=", hexstr(error1), "\n");
#display("error2=", hexstr(error2), "\n");
#display("error3=", hexstr(error3), "\n");
#display("error4=", hexstr(error4), "\n");
#display("error5=", hexstr(error5), "\n");

error5 = NULL;
null_session_failed = 1;

if(hexstr(error1) == "00000000" &&
   hexstr(error2) == "00000000" &&
   hexstr(error4) == "1c00001c" &&
   isnull(error5))exit(0); # HP-UX dced


if(hexstr(error2) == hexstr(error1))
{
 vulnerable = 1;
 if(hexstr(error1) == "05000780")exit(0); # DCOM disabled
 if(hexstr(error1) == "00000000")
 {
  if( hexstr(error5) == "04000880" )vulnerable = 0;
  else if( null_session_failed || hexstr(error5) == "05000780") { 
   req6 = "0500000310000000c600000000000000ae000000000000000500010000000000000000005b4e65737375735d5b4e65737375735d000000004e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e680f0b001e000000000000001e0000005c005c00410000005c000000630024005c0074006500730074005f0032003000300033005f006e00650073007300750073002e00740078007400000000000000020000000200000001000000b8eb0b00010000000000000000000000000000000000000001000000010000000700";
   error6 = check6(req:hex2raw(s:req6));
   req7 = "0500000310000000c600000000000000ae000000000000000500010000000000000000005b4e65737375735d5b4e65737375735d0000000048484848484848484848484848484848680f0b001e000000000000001e0000005c005c003100370032002e00340032002e003100340032002e0031003400320000005c0074006500730074005f004e0065007300730075007300000000000000020000000200000001000000b8eb0b00010000000000000000000000000000000000000001000000010000000700";
   error7 = check6(req:hex2raw(s:req7));
   if(hexstr(error6) == "54010480" && hexstr(error7) == "04000880")vulnerable = 0;
   #display("error6=", hexstr(error6), "\n");
   #display("error7=", hexstr(error7), "\n");
   if(hexstr(error6) == hexstr(error7) &&
      hexstr(error6) == "05000780")exit(0); # Dcom disabled
   
  }
 }
}
  
 
if(vulnerable)
{
 security_hole(port);
}
else {
 set_kb_item(name:"SMB/KB824146", value:TRUE);
}

