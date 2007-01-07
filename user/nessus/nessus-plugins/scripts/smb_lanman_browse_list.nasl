#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# modified by Axel Nennker 20020418 <axel@nennker.de>

if(description)
{
 script_id(10397);
 script_version ("$Revision: 1.19 $");
 name["english"] = "SMB LanMan Pipe Server browse listing";
 name["francais"] = "SMB LanMan Pipe Server browse listing";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
This script obtains the remote host browse
list using the \PIPE\LANMAN transaction pipe

Risk factor : Low"; 

 desc["francais"] = "
Ce script récupère la browse list de la machine
distante en utilisant le pipe de transaction
\PIPE\LANMAN

Risk factor : Low";

 script_description(english:desc["english"],
 		    francais:desc["francais"]);
 
 summary["english"] = "Gets the list of remote host browse list";
 summary["francais"] = "Obtention de la browser list distante";
 script_summary(english:summary["english"],
 		francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl", "smb_login.nasl");
 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_nt.inc");
port = kb_smb_transport();
if(!port)port = 139;

#--------------------------------------------------------#
# Request the list of browse                             #
#--------------------------------------------------------#
function lanman_netshare_enum2_request(soc,uid, tid)
{
 uid_high = uid / 256;
 uid_low = uid % 256;
 
 tid_high = tid / 256;
 tid_low = tid % 256;
 
 
 req = raw_string(0x00, 0x00,
 		  0x00, 0x66, 0xFF, 0x53, 0x4D, 0x42, 0x25, 0x00,
		  0x00, 0x00, 0x00, 0x18, 0x01, 0x20, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, tid_low, tid_high, 0x00, 0x28, uid_low, uid_high,
		  0x00, 0x00, 0x0E, 0x1A, 0x00, 0x00, 0x00, 0x08,
		  0x00, 0x10, 0x27, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x1A, 0x00, 0x4C,
		  0x00, 0x00, 0x00, 0x66, 0x00, 0x00, 0x00, 0x27,
		  0x00, 0x5C, 0x50, 0x49, 0x50, 0x45, 0x5C, 0x4C,
		  0x41, 0x4E, 0x4D, 0x41, 0x4E, 0x00, 0x68, 0x00,
		  0x57, 0x72, 0x4C, 0x65, 0x68, 0x44, 0x4F, 0x00,
		  0x42, 0x31, 0x36, 0x42, 0x42, 0x44, 0x7A, 0x00,
		  0x01, 0x00, 0x00, 0x20, 0xFF, 0xFF, 0xFF, 0xFF);
		  
     			
 send(socket:soc, data:req);
 r = smb_recv(socket:soc, length:65535);
 if(!r)return(FALSE);
 if(ord(r[9])==0)return(r);
 else return(FALSE);		
}	  


#-------------------------------------------------------------#
# Extract the names (and comments) of the browse              #
# from the result of the function above                       #
#-------------------------------------------------------------#
function netshare_extract_browse(reply)
{
 browse = "";
 
 num_treated = 0;

 replylen = strlen(reply);

 if(replylen < 52)return(FALSE);

 param_offset = ord(reply[46])*256;
 param_offset = param_offset + ord(reply[45]) + 4;
 
 
 data_count = ord(reply[50])*256;
 data_count = data_count + ord(reply[49]);
 
 data_offset = ord(reply[52])*256;
 data_offset = data_offset + ord(reply[51]) + 4;
 i = data_offset;
 if(data_offset > replylen)return(FALSE);
 
 if(replylen < param_offset+5)return(FALSE);
 
 converter_low = ord(reply[param_offset+2]);
 converter_high = ord(reply[param_offset+3]);
 converter = converter_high * 256;
 converter = converter + converter_low;

 num_low = ord(reply[param_offset+4]);
 num_high = ord(reply[param_offset+5]);
 num =  num_high*256;
 num = num + num_low;
 
 
 limit = data_offset + data_count;

 #display("limit ", limit, ", reply len ", replylen, "\n");
 # limit and replylen (strlen(reply) seem to be == even when errors
 # can only buffer 4292 bytes (165 shares)
 # get crap after that
 
 if (num > 165)
 {
   browse = "WARNING - LARGE BROWSE LIST. 
   Only the first 165 names enumerated\n";
   num = 165;
 }
 for(s=0;s<num;s=s+1)
 {
  end = i+13;
  
  if(end < limit) limit = end;
  
  if(i > replylen)return(FALSE);

  # share name
  for(j=i;j<end;j=j+1)
  {
   i = j;
   if(ord(reply[i]))
   	{
   	browse = string(browse, reply[i]);
	}
  }
  
  
  i = i+10;

  if(converter)
  {
   if(i+1 > replylen)return(FALSE);
   off = ord(reply[i+1]);
   off = off * 256;
   off = off + ord(reply[i]);
   off = off  - converter;
   k = off + data_offset;
   if(k)
   {
    browse = browse + " - ";
    if(k > replylen)return(FALSE);
    while(ord(reply[k]))
    {
     if(k > replylen)return(FALSE);
     browse = string(browse, reply[k]);
     k = k+1;
    }
  }
 }
  else browse = browse + " - ";
  
  browse = string(browse, "\n");
  i = i+4;
 }
 return(browse);
}
    		
		
		
#------------------------------------------------------------------------------#
# 				main()                                         #
#------------------------------------------------------------------------------#		


name = kb_smb_name();
if(!name)exit(0);

if(!get_port_state(port))exit(0);

login = kb_smb_login();
pass = kb_smb_password();

if(!login)login = "";
if(!pass) pass = "";
	  
dom = kb_smb_domain();
if (!dom) dom = "";
  
soc = open_sock_tcp(port);
if (!soc) exit(0);

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
# Set up our null session
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
if(!r)exit(0);
tid = tconx_extract_tid(reply:r);

#
# Request the list of browse
#
r = lanman_netshare_enum2_request(soc:soc, uid:uid, tid:tid);
if(r)
{
 # decode the list
 browse = netshare_extract_browse(reply:r);
 if(browse)
 {
  # display the list
  res = string("Here is the browse list of the remote host : \n\n");
  res = res + browse;
  res = res + string("\n\nThis is potentially dangerous as this may help the attack\n");
  res = res + string("of a potential hacker by giving him extra targets to check for\n\n");
  res = res + string("Solution : filter incoming traffic to this port\n");
  res = res + string("Risk factor : Low\n");
  security_warning(port:port, data:res);
  set_kb_item(name:"SMB/browse", value:browse);
 }
}
