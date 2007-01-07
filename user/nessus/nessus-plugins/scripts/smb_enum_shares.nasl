#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# July 5, 2002: Michael Scheidell / SECNAP Network Security, LLC
# Added test for num shares > 215
# problem with this function if buffer returned (strlen(reply) >= 4360
# shares past 215 and 'comment' section are trashed so not reported anymore
#

if(description)
{
 script_id(10395);
 script_version ("$Revision: 1.22 $");
 name["english"] = "SMB shares enumeration";
 name["francais"] = "Enumeration des shares SMB";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
This script connects to the remote host
using a null session, and enumerates the
exported shares

Risk factor : Medium"; 

 desc["francais"] = "
Ce script se connect the l'hote distant
en utilisant une 'null session' et énumère
les ressources partagées

Facteur de risque : Moyen";

 script_description(english:desc["english"],
 		    francais:desc["francais"]);
 
 summary["english"] = "Gets the list of remote shares";
 summary["francais"] = "Obtention de la liste des shares distantes";
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

#-----------------------------------------------------#
# Request the list of shares                          #
#-----------------------------------------------------#
function lanman_netshare_enum_request(soc,uid, tid)
{
 uid_high = uid / 256;
 uid_low = uid % 256;
 
 tid_high = tid / 256;
 tid_low = tid % 256;
 
 
 req = raw_string(0x00, 0x00,
 		  0x00, 0x5F, 0xFF, 0x53, 0x4D, 0x42, 0x25, 0x00,
		  0x00, 0x00, 0x00, 0x18, 0x01, 0x20, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, tid_low, tid_high, 0x00, 0x28, uid_low, uid_high,
		  0x00, 0x00, 0x0E, 0x13, 0x00, 0x00, 0x00, 0x00,
		  0x04, 0xE0, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x00, 0x4C,
		  0x00, 0x00, 0x00, 0x5F, 0x00, 0x00, 0x00, 0x20,
		  0x00, 0x5C, 0x50, 0x49, 0x50, 0x45, 0x5C, 0x4C, 
		  0x41, 0x4E, 0x4D, 0x41, 0x4E, 0x00, 0x00, 0x00,
		  0x57, 0x72, 0x4C, 0x65, 0x68, 0x00, 0x42, 0x31,
		  0x33, 0x42, 0x57, 0x7A, 0x00, 0x01, 0x00, 0xE0,
		  0xFF);
     			
 send(socket:soc, data:req);
 r = smb_recv(socket:soc, length:65535);
 if(strlen(r) < 10)return(FALSE);
 if(ord(r[9])==0)return(r);
 else return(FALSE);		
}	  


#-----------------------------------------------------#
# Extract the names (and comments) of the shares      #
# from the result of the function above               #
#-----------------------------------------------------#
function netshare_extract_shares(reply)
{
 len_reply = strlen(reply);
 if(len_reply < 63)return(0);
 
 shares = "";
 
 
 num_treated = 0;

 param_offset = ord(reply[46])*256;
 param_offset = param_offset + ord(reply[45]) + 4;
 
 data_count = ord(reply[50])*256;
 data_count = data_count + ord(reply[49]);
 
 data_offset = ord(reply[52])*256;
 data_offset = data_offset + ord(reply[51]) + 4;
 i = data_offset;
 

 if(param_offset+5 > len_reply)return(0);
 
 
 converter_low = ord(reply[param_offset+2]);
 converter_high = ord(reply[param_offset+3]);
 converter = converter_high * 256;
 converter = converter + converter_low;

 num_low = ord(reply[param_offset+4]);
 num_high = ord(reply[param_offset+5]);
 
 num = num_high*256;
 num = num+num_low;
 
 
 
 limit = data_offset + data_count;
 
#display(get_host_name(),":num shares: ",num,".limit: ",limit,".\n");

## if that packet size (limit) is == to 4360 than  things fail.
  if(num > 215)
  {
    shares = string("Warning: Only 215 out of ",num," shares enumerated\n");
    num = 215;
  }
 for(s=0;s<num;s=s+1)
 {
  end = i+13;
  share = "";
  for(j=i;j<end;j=j+1)
  {
   i = j;
   if((i < limit) && ord(reply[i]))
   	{
   	share = string(share, reply[i]);
	}
  }
  
  set_kb_item(name:"SMB/shares", value:share);
  shares = string(shares, share);
  
  
  i = i+4;
 
  # large buffer trashes the comment section anyway.
  if(converter && (limit < 4360))
  {
  off = ord(reply[i+1]);
  off = off * 256;
  off = off + ord(reply[i]);
  off = off  - converter;
  k = off + data_offset;
  if(k)
  {
   shares = shares + " - ";
   while(ord(reply[k]))
    {
    shares = string(shares , reply[k]);
    k = k+1;
    }
   }
  }
  else shares = string(shares , " - ");
  
  shares = string(shares,"\n"); 
  i = i+4;
 }
 return(shares);
}
    		
		
		
#----------------------------------------------------------------#
# 			  main()                                 #
#----------------------------------------------------------------#		


name = kb_smb_name();
if(!name)exit(0);

if(!get_port_state(port))exit(0);

	  
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
# Set up our null session
#
login = kb_smb_login();
pass =  kb_smb_password();

if(!login)login = "";
if(!pass)pass = "";

dom = kb_smb_domain();

r = smb_session_setup(soc:soc, login:login, password:pass, domain:dom, prot:prot);
if(!r)exit(0);
# and extract our uid
uid = session_extract_uid(reply:r);
#
# Connect to the remote IPC and extract the TID
# we are attributed
#      
r = smb_tconx(soc:soc, name:name, uid:uid, share:"IPC$");
tid = tconx_extract_tid(reply:r);
if(!tid)exit(0);

#
# Request the list of shares
#
r = lanman_netshare_enum_request(soc:soc, uid:uid, tid:tid);
if(r)
{ 
 
 # decode the list
 shares = netshare_extract_shares(reply:r);
 if(shares)
 {
  # display the list
  res = string("Here is the list of the SMB shares of this host : \n\n");
  res = res + shares;
  res = res + string("\n\nThis is potentially dangerous as this may help the attack\n");
  res = res + string("of a potential hacker.\n\n");
  res = res + string("Solution : filter incoming traffic to this port\n");
  res = res + string("Risk factor : Medium");
  security_warning(port:port, data:res);
 }
}
