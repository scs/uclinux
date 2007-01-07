#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
#
# This function enumerates the services of the remote NT host.
# 
# Material I used to understand how to do it :
#
# - "DCE/RPC" over SMB, by Luke Kenneth Casson Leighton
# - Watching how NT4 and Win2K talk together
#
# Software used : 
#
# - ethereal
#
# 
# The functions SvcOpenSCManager() and SvcEnumServicesStatus()
# are implemented in this plugin. So, if you want to see how
# they work, have fun.
#
#

if(description)
{
 script_id(10456);
 script_version ("$Revision: 1.23 $");
 
 name["english"] = "SMB enum services";
 name["francais"] = "SMB enum services";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
This plugin implements the SvcOpenSCManager() and
SvcEnumServices() calls to obtain, using the SMB
protocol, the list of active services of the remote
host.

An attacker may use this feature to gain better
knowledge of the remote host.

Solution : To prevent the listing of the services for being
obtained, you should either have tight login restrictions,
so that only trusted users can access your host, and/or you
should filter incoming traffic to this port.

Risk factor : Low";





 script_description(english:desc["english"]);
 
 summary["english"] = "Enumerates the list of remote services";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl");
 script_require_keys("SMB/transport", "SMB/name", 
 		     "SMB/login", 
		     "SMB/password");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_nt.inc");


port = kb_smb_transport();
if(!port)port = 139;








#--------------------------------------------------------#
# Request the creation of a pipe to \svcctl. We will      #
# then use it to do our work                             #
#--------------------------------------------------------#
function svc_smbntcreatex(soc, uid, tid)
{
 tid_high = tid / 256;
 tid_low  = tid % 256;
 
 uid_high = uid / 256;
 uid_low  = uid % 256;
 
req = raw_string(0x00, 0x00,
  		   0x00, 0x5B, 0xFF, 0x53, 0x4D, 0x42, 0xA2, 0x00,
		   0x00, 0x00, 0x00, 0x18, 0x03, 0x00, 0x50, 0x81,
		   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		   0x00, 0x00, tid_low, tid_high, 0x00, 0x28, uid_low, uid_high,
		   0x00, 0x00, 0x18, 0xFF, 0x00, 0x00, 0x00, 0x00,
		   0x07, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00,
		   0x00, 0x00, 0x9F, 0x01, 0x02, 0x00, 0x00, 0x00,
		   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		   0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00,
		   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
		   0x00, 0x00, 0x00, 0x08, 0x00, 0x5C, 0x73, 0x76,
		   0x63, 0x63, 0x74, 0x6C, 0x00);

 send(socket:soc, data:req);
 r = smb_recv(socket:soc, length:4000);
 if(!r)return(FALSE);
 if(ord(r[9])==0x00)return(r);
 else return(FALSE);
}


#--------------------------------------------------------#
# Extract the ID of our pipe from the result             #
# of smbntcreatex()                                      #
#--------------------------------------------------------#

function svc_smbntcreatex_extract_pipe(reply)
{
 low = ord(reply[42]);
 high = ord(reply[43]);
 
 ret = high * 256;
 ret = ret + low;
 return(ret);
}

#--------------------------------------------------------#
# Decodes the data sent back by svcenumservicesstatus()  #
#--------------------------------------------------------#

function svc_decode(data)
{
 ret = "";
 sz = "";
  if(strlen(data) < 128)return(FALSE);
  for(i=4;i>0;i=i-1)
  {
   sz = sz * 256;
   sz = sz + ord(data[123+i]);
  }
  
  #display("size : ", sz, "\n");
  
  len = strlen(data);
  num_svc = ord(data[len-15]);
  num_svc = num_svc * 256;
  num_svc = num_svc + ord(data[len-16]);
  
  if(!num_svc){
  	return(FALSE);
  	}
  ret = string("There are ", num_svc, " services running on this host :\n");
  
  off = 0;
  lim = num_svc * 0x24;
 
  for(j=0;j<lim;j=j+0x24)
  {
  for(i=4;i>0;i=i-1)
  {
   off = off * 256;
   off = off + ord(data[87+i+j]);
  }
  
  off2 = 0;
  for(i=4;i>0;i=i-1)
  {
   off2 = off2 * 256;
   off2 = off2 + ord(data[91+i+j]);
  }

 
 if(off2 > strlen(data))return(0);
 if(off > strlen(data))return(0);
 
  name = "";
  svc = "";
 for(k=0;k<255;k = k+1)
  {
   	if(!(ord(data[off2+k+88])))
		k = 255;
	else	
		name = string(name, raw_string(ord(data[off2+k+88])));
  }
  
    
  for(k=0;k<255;k=k+1){
  	if(!(ord(data[off+k+88])))
		k = 255;
	else	
		svc = string(svc, raw_string(ord(data[off+k+88])));
	}
	
  
  ret = ret + string(name, " [", svc, "]\n");
  }
  return(ret);
}


#------------------------------------------------------#
# Obtains a handle we use in svcenumservicesstatus()   #
#------------------------------------------------------#
function svcopenscmanager(soc, name, uid, tid, pipe)
{
 tid_low = tid % 256;
 tid_high = tid / 256;
 uid_low = uid % 256;
 uid_high = uid / 256;
 pipe_low = pipe % 256;
 pipe_high = pipe / 256;
 

 
 
 req = raw_string(0x00, 0x00,
 		  0x00, 0x9c, 0xFF, 0x53, 0x4D, 0x42, 0x25, 0x00,
		  0x00, 0x00, 0x00, 0x18, 0x03, 0x80, 0x59, 0x81,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, tid_low, tid_high, 0x00, 0x28, uid_low, uid_high,
		  0x00, 0x00, 0x10, 0x00, 0x00, 0x48, 0x00, 0x00,
		  0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54,
		  0x00, 0x48, 0x00, 0x54, 0x00, 0x02, 0x00, 0x26,
		  0x00, pipe_low, pipe_high, 0x59, 0x00, 0x00, 0x5C, 0x00,
		  0x50, 0x00, 0x49, 0x00, 0x50, 0x00, 0x45, 0x00,
		  0x5C, 0x00, 0x00, 0x00, 0x00, 0x14, 0x05, 0x00,
		  0x0B, 0x00, 0x10, 0x00, 0x00, 0x00, 0x48, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x16,
		  0x30, 0x16, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x81, 0xBB,
		  0x7A, 0x36, 0x44, 0x98, 0xF1, 0x35, 0xAD, 0x32,
		  0x98, 0xF0, 0x38, 0x00, 0x10, 0x03, 0x02, 0x00,
		  0x00, 0x00, 0x04, 0x5D, 0x88, 0x8A, 0xEB, 0x1C,
		  0xC9, 0x11, 0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10,
		  0x48, 0x60, 0x02, 0x00, 0x00, 0x00);
		  
 send(socket:soc, data:req);
 r = smb_recv(socket:soc, length:4096);
 if(!r)return(FALSE);
 
 odd = 0;
 len = strlen(name);
if(len & 1){
 	len = len - 1;
	odd = 1;
	}
 tot_len = 134 + len;
 tot_len_lo = tot_len % 256;
 tot_len_hi = tot_len / 256;

 
 if(odd)len = len + 1; 
 bcc = 67 + len;
 if(odd)bcc = bcc - 1;
 bcc_lo = bcc % 256;
 bcc_hi = bcc / 256;
 tot = 50 + len;
 if(odd)tot = tot - 1;
 tot_hi = tot/256;
 tot_lo = tot%256;
 
 len2 = 26 + len;
 if(odd)len2 = len2 - 1;
 len2_lo = len2 % 256;
 len2_hi = len2 / 256;
 
 
 len    = len + 1;
 len_lo = len % 256;
 len_hi = len / 256;
 req = raw_string(0x00, 0x00,
 		  tot_len_hi, tot_len_lo, 0xFF, 0x53, 0x4D, 0x42, 0x25, 0x00,
		  0x00, 0x00, 0x00, 0x18, 0x03, 0x80, 0x63, 0x81,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, tid_low, tid_high, 0x00, 0x28, uid_low, uid_high,
		  0x00, 0x00, 0x10, 0x00, 0x00, tot_lo, tot_hi, 0x00,
		  0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54,
		  0x00, tot_lo, tot_hi, 0x54, 0x00, 0x02, 0x00, 0x26,
		  0x00, pipe_low, pipe_high, bcc_lo, bcc_hi, 0x00, 0x5C, 0x00,
		  0x50, 0x00, 0x49, 0x00, 0x50, 0x00, 0x45, 0x00,
		  0x5C, 0x00, 0x00, 0x00, 0x00, 0x5C, 0x05, 0x00,
		  0x00, 0x03, 0x10, 0x00, 0x00, 0x00, tot_lo, tot_hi,
		  0x00, 0x00, 0x01, 0x00, 0x00, 0x00, len2_lo, len2_hi,
		  0x00, 0x00, 0x00, 0x00, 0x1B, 0x00, 0x60, 0x02,
		  0x7D, 0x00, len_lo, len_hi, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, len_lo, len_hi, 0x00, 0x00) +
		  	tolower(name);
			
	if(odd)req = req + raw_string(0x00);
	else req = req + raw_string(0x00, 0x00);
	
	req = req + raw_string(0x00, 0x00,
		   0x00, 0x00, 0x04, 0x00, 0x00, 0x00);
  
  send(socket:soc, data:req);
  r = smb_recv(socket:soc, length:4096);
  if(!r)return(FALSE);
  #if(strlen(r) < 100)return(FALSE);
  if(strlen(r) < 104)exit(0);
  #display("hu\n");
  #
  # extract the handle
  #
  hdl = "";
  i = 0;
  for(i=0;i<21;i=i+1)
   {
 #   display(hex(ord(r[83+i])), " ");
   hdl =  string(hdl, raw_string(ord(r[83+i])));
   }
 # display("\n");
  return(hdl);
}


#------------------------------------------------#
# creates a valid smbreadx() request             #
#------------------------------------------------#
function smbreadx()
{
 return(raw_string(0x00, 0x00,
 		  0x00, 0x3C, 0xFF, 0x53, 0x4D, 0x42, 0x2E, 0x00,
		  0x00, 0x00, 0x00, 0x18, 0x00, 0x80, 0x00, 0x00, 
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, tid_low, tid_high, 0x00, 0x28, uid_low, uid_high,
		  0x00, 0x00, 0x0C, 0xFF, 0x00, 0x00, 0x00, pipe_low,
		  pipe_high, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF,
		  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x02));
}


#----------------------------------------------#
# returns TRUE if svcenumservicesstatus needs  #
# to call smbreadx() to get the rest of the    #
# services list                                #
#----------------------------------------------#


function moredata(data)
{
 len_data = strlen(data);
 start = len_data - 4;
 for(_i=start;_i<len_data;_i=_i+1)
  {
   #display(hex(data[_i]), " ");
   if(ord(data[_i]))return(TRUE);
  }
 return(FALSE);
}



#----------------------------------------------#
# svcenumservicesstatus() :                    #
# This function makes the appropriate calls    #
# to get the list of the remote active services#
# and decodes the result. It returns FALSE if  #
# no service is running at all.                #
#----------------------------------------------#
#
function svcenumservicesstatus(soc, name, uid, tid, pipe, handle)
{
 tid_low = tid % 256;
 tid_high = tid / 256;
 uid_low = uid % 256;
 uid_high = uid / 256;
 pipe_low = pipe % 256;
 pipe_high = pipe / 256;
 
 
 
 #
 # We make a first call to svcenumservicesstatus(), and we declare
 # our buffer size as being 0 bytes. We receive an error with the
 # amount of bytes we'd need, then we make a second request
 # with that value.
 #
 
 #
 # First request
 #
 req = raw_string(0x00, 0x00,
 		  0x00, 0x94, 0xFF, 0x53, 0x4D, 0x42, 0x25, 0x00,
		  0x00, 0x00, 0x00, 0x18, 0x03, 0x80, 0x6B, 0x80,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, tid_low, tid_high, 0x00, 0x28, uid_low, uid_high,
		  0x00, 0x00, 0x10, 0x00, 0x00, 0x40, 0x00, 0x00,
		  0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54,
		  0x00, 0x40, 0x00, 0x54, 0x00, 0x02, 0x00, 0x26,
		  0x00, pipe_low, pipe_high, 0x51, 0x00, 0x00, 0x5C, 0x00,
		  0x50, 0x00, 0x49, 0x00, 0x50, 0x00, 0x45, 0x00,
		  0x5C, 0x00, 0x00, 0x00, 0x00, 0x88, 0x05, 0x00,
		  0x00, 0x03, 0x10, 0x00, 0x00, 0x00, 0x40, 0x00,
		  0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x28, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x1A) + handle +
	raw_string(0x30, 0x00, 0x00, 0x00, 0x01, 0x00, 
		  0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x74, 0xFF,
		  0x12, 0x00, 0x00, 0x00, 0x00, 0x00);

  #display("strlen(req) : ", strlen(req), "\n");
  send(socket:soc, data:req);
  r = smb_recv(socket:soc, length:1024);
  if(strlen(r) < 128)return(NULL);
 len = "";
 for(i=124;i<128;i=i+1)len = string(len, raw_string(ord(r[i])));


  #
  # Second request, with the appropriate length
  # 
  
  
  req = raw_string(0x00, 0x00,
 		  0x00, 0x94, 0xFF, 0x53, 0x4D, 0x42, 0x25, 0x00,
		  0x00, 0x00, 0x00, 0x18, 0x03, 0x80, 0x6B, 0x80,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, tid_low, tid_high, 0x00, 0x28, uid_low, uid_high,
		  0x00, 0x00, 0x10, 0x00, 0x00, 0x40, 0x00, 0x00,
		  0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54,
		  0x00, 0x40, 0x00, 0x54, 0x00, 0x02, 0x00, 0x26,
		  0x00, pipe_low, pipe_high, 0x51, 0x00, 0x00, 0x5C, 0x00,
		  0x50, 0x00, 0x49, 0x00, 0x50, 0x00, 0x45, 0x00,
		  0x5C, 0x00, 0x00, 0x00, 0x00, 0x88, 0x05, 0x00,
		  0x00, 0x03, 0x10, 0x00, 0x00, 0x00, 0x40, 0x00,
		  0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x28, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x1A) + 
		  handle +
	raw_string(0x30, 0x00, 0x00, 0x00, 0x01, 0x00, 
		  0x00, 0x00) + len + 
	raw_string(0x74, 0xFF,
		  0x12, 0x00, 0x00, 0x00, 0x00, 0x00);
		  
		  

  send(socket:soc, data:req);
  r = smb_recv(socket:soc, length:65535);

 #
 # get what's left - smbreadX request
 #
 if(ord(r[9]))
 {
 req = smbreadx();
 send(socket:soc, data:req);
 r2 = smb_recv(socket:soc, length:67000);
 

 #
 # Merge the relevant portion of r2 into r
 #
 len_r2 = strlen(r2);
 for(k=64;k<len_r2;k=k+1)
 {
  r = r + raw_string(ord(r2[k]));
 }
 
 while(moredata(data:r2))
 {
  req = smbreadx();
  send(socket:soc, data:req);
  r2 = smb_recv(socket:soc, length:67000);
  len_r2 = strlen(r2);
  for(k=88;k<len_r2;k=k+1)
  {
  # display("->", r2[k], "\n");
   r = r + raw_string(ord(r2[k]));
  }
 }
 }

# display(r);
 ret = svc_decode(data:r);
 if(ret)
 {
  # Set the list of services in the kb
  set_kb_item(name:"SMB/svcs", value:ret);
 }
 return(ret);		  
}


# Does not work against Samba
smb = get_kb_item("SMB/samba");
if(smb)exit(0);


name = kb_smb_name();
if(!name)return(FALSE);
while(" " >< name)
{
 name = name - " ";
}



if(!get_port_state(port))return(FALSE);

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
if(!r)return(FALSE);

#
# Negociate the protocol
#
prot = smb_neg_prot(soc:soc);
if(!prot)return(FALSE);

#
# Set up our session
#
r = smb_session_setup(soc:soc, login:login, password:pass, domain:dom, prot:prot);
if(!r)return(FALSE);
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
# Create a pipe to \svcctl
#
r = svc_smbntcreatex(soc:soc, uid:uid, tid:tid);
if(!r)return(FALSE);
# and extract its ID
pipe = svc_smbntcreatex_extract_pipe(reply:r);


handle = svcopenscmanager(soc:soc, name:name, uid:uid, tid:tid, pipe:pipe);

services = svcenumservicesstatus(soc:soc, name:name, uid:uid, tid:tid, pipe:pipe,handle:handle);
#display(services);

if(services)
{
 moral = string(
"You should turn off the services you do not use.\n",
"This list is useful to an attacker, who can make his attack\n",
"more silent by not portscanning this host.\n\n",
"Solution :  To prevent the listing of the services for being\n",
"obtained, you should either have tight login restrictions,\n",
"so that only trusted users can access your host, and/or you\n",
"should filter incoming traffic to this port.\n\n",
"Risk factor : Low");
 services = services + moral;
 security_warning(data:services, port:port);
}
