#
# This script was written by Noam Rathaus <noamr@securiteam.com>
#
# See the Nessus Scripts License for details
#
# Changes by rd :
# - bug fix in the adaptater conversion
# - export results in the KB
#
# rev 1.5 changes by ky :
# - added full support for Win2k/WinXP/Win2k3
# - added export of SMB/username KB
#
# rev 1.6 changes by KK :
# - added export of SMB/messenger KB

if(description)
{
 script_id(10150);
 script_version ("$Revision: 1.37 $");
 script_cve_id("CAN-1999-0621");
 
 name["english"] = "Using NetBIOS to retrieve information from a Windows host";
 script_name(english:name["english"]);
 
 desc["english"] = "The NetBIOS port is open (UDP:137). A remote attacker may use this to gain
access to sensitive information such as computer name, workgroup/domain
name, currently logged on user name, etc.

Solution: Block those ports from outside communication

Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Using NetBIOS to retrieve information from a Windows host";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 1999 SecuriTeam");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 script_dependencies("cifs445.nasl");
 exit(0);
}

#
# The script code starts here
#

function isprint(c)
{
 min = ord("!");
 max = ord("~");
 ordc = ord(c);
 if(ordc > max)return(FALSE);
 if(ordc < min)return(FALSE);
 return(TRUE);
}

# do not test this bug locally

NETBIOS_LEN = 50;


sendata = raw_string(
rand()%255, rand()%255, 0x00, 0x00, 0x00,
0x01, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x20, 0x43, 0x4B,
0x41, 0x41, 0x41, 0x41, 0x41,
0x41, 0x41, 0x41, 0x41, 0x41,
0x41, 0x41, 0x41, 0x41, 0x41,
0x41, 0x41, 0x41, 0x41, 0x41,
0x41, 0x41, 0x41, 0x41, 0x41,
0x41, 0x41, 0x41, 0x41, 0x41,
0x00, 0x00, 0x21, 0x00, 0x01
			);

hostname_found = 0;
group_found = 0;
messenger_found = 0;
candidate = "";

if(!(get_udp_port_state(137))){
	set_kb_item(name:"SMB/name", value:"*SMBSERVER");
	exit(0);
	}
	
dsport = 137;
soc = open_sock_udp(137);
send(socket:soc, data:sendata, length:NETBIOS_LEN);

result = recv(socket:soc, length:4096);

if (strlen(result) > 56)
{  
 hole_answer = "";

 hole_data = result;

 location = 0;
 location = location + 56;
 
 num_of_names = ord(hole_data[location]);
 if (num_of_names > 0)
 {
  hole_answer = string(hole_answer, "The following ",	num_of_names,
	" NetBIOS names have been gathered :\n");
 }

 location = location + 1;

 for (name_count = 0; name_count < num_of_names; name_count = name_count + 1)
 {
  name = "";
  for (name_copy = 0; name_copy < 15; name_copy = name_copy + 1)
  {
   loc = location+name_copy+name_count*18;
   if(isprint(c:hole_data[location+name_copy+name_count*18]))
   {
    name = string(name, hole_data[location+name_copy+name_count*18]);
   }
   else
    name = string(name, " ");
  }
  loc = location+16+name_count*18;
 
   
  # Win2k/WinXP sends 0xc4-196 and 0x44-68 as the loc name flags
  if(hole_data[loc] == raw_string(68))
  {
   subloc = location+15+name_count*18;
   if(ord(hole_data[subloc])==32)
   {
    if(!hostname_found && name)
    {
     set_kb_item(name:"SMB/name", value:name);
     hostname_found = 1;
    }
   }
   else if(ord(hole_data[subloc])==0)
   {
    candidate = name;
    if(!("~" >< name))
    {
     if(!hostname_found && name)
     {
      set_kb_item(name:"SMB/name", value:name);
      hostname_found = 1;
     }
    }
   }
   # Set the current logged in user based on the last entry
   if (hole_data[subloc] == raw_string(3))
   {
    # Ugh, we can get multiple usernames with TS or Citrix
    # Also, the entry is the same for the local workstation or user name
    username = name;
    name = name + " = This is the current logged in user or registered workstation name.";
   }
        
   if(ord(hole_data[subloc]) == 27)
   {
    if(!group_found && name)
    {
     set_kb_item(name:"SMB/workgroup", value:name);
     group_found = 1;
    }
   }

   if (hole_data[subloc] == raw_string(1))
   {
    name = name + " = Computer name that is registered for the messenger service on a computer that is a WINS client.";
    messenger_found = 1;
    messenger = name;
   }
   if (hole_data[subloc] == raw_string(190))
   {
    name = name + " = A unique name that is registered when the Network Monitor agent is started on the computer";
   }
   if (hole_data[subloc] == raw_string(31))
   {
    name = name + " = A unique name that is registered for Network dynamic data exchange (DDE) when the NetDDE service is started on the 
computer.";
   }
   
   
  }

  # Set the workgroup info on WinXP
  if (hole_data[loc] == raw_string(196))
  {
   subloc = location+15+name_count*18;
   
   if (hole_data[subloc] == raw_string(0))  
   {
    if(!group_found && name)
    {
      set_kb_item(name:"SMB/workgroup", value:name);
      group_found = 1;
    }
    name = name + " = Workgroup / Domain name";
   }
   if (hole_data[subloc] == raw_string(30))  
   {
    name = name + " = Workgroup / Domain name (part of the Browser elections)";
   }
   if (hole_data[subloc] == raw_string(27))  
   {
    name = name + " = Workgroup / Domain name (elected Master Browser)";
   }
   if (hole_data[subloc] == raw_string(28))  
   {
    name = name + " = Workgroup / Domain name (Domain Controller)";
   }
   if (hole_data[subloc] == raw_string(191))  
   {
    name = name + " = A group name that is registered when the Network Monitor agent is started on the computer.";
   }
  }

  # WinNT sends 0x04-4 and 0x84-132 as the loc name flags
  if (hole_data[loc] == raw_string(4))
  {
   subloc = location+15+name_count*18;

   if (hole_data[subloc] == raw_string(0))
   {
    if(!hostname_found && name)
    {
     set_kb_item(name:"SMB/name", value:name);
     hostname_found = 1;
    }
    name = name + " = This is the computer name registered for workstation services by a WINS client.";
   }

   # Set the current logged in user based on the last entry
   if (hole_data[subloc] == raw_string(3))
   {
   {
    # Ugh, we can get multiple usernames with TS or Citrix
    username = name;
    name = name + " = This is the current logged in user registered for this workstation.";
   }
   }

   if (hole_data[subloc] == raw_string(1))
   {
    name = name + " = Computer name that is registered for the messenger service on a computer that is a WINS client.";
    messenger_found = 1;
    messenger = name;
   }
   if (hole_data[subloc] == raw_string(190))
   {
    name = name + " = A unique name that is registered when the Network Monitor agent is started on the computer";
   }
   if (hole_data[subloc] == raw_string(31))
   {
    name = name + " = A unique name that is registered for Network dynamic data exchange (DDE) when the NetDDE service is started on the 
computer.";
   }   
   
  }

  loc = location+16+name_count*18;

 
  
  # Set the workgroup info on WinNT  
  if (hole_data[loc] == raw_string(132))
  {
   subloc = location+15+name_count*18;
   
   if (hole_data[subloc] == raw_string(0))  
   {
    if(!group_found && name)
    {
      set_kb_item(name:"SMB/workgroup", value:name);
      group_found = 1;
    }
    name = name + " = Workgroup / Domain name";
   }
   if (hole_data[subloc] == raw_string(30))  
   {
    name = name + " = Workgroup / Domain name (part of the Browser elections)";
   }
   if (hole_data[subloc] == raw_string(27))  
   {
    name = name + " = Workgroup / Domain name (elected Master Browser)";
   }
   if (hole_data[subloc] == raw_string(28))  
   {
    name = name + " = Workgroup / Domain name (Domain Controller)";
   }
   if (hole_data[subloc] == raw_string(191))  
   {
    name = name + " = A group name that is registered when the Network Monitor agent is started on the computer.";
   }
   
  }
  

  hole_answer = hole_answer + " " + name + string("\n");
 }

 
 location = location + num_of_names*18;

 adapter_name = "";
 for (adapter_count = 0; adapter_count < 6; adapter_count = adapter_count + 1)
 {
  loc = location + adapter_count;
  adapter_name = adapter_name + string(hex(ord(hole_data[loc])), " ");
 }
 if(adapter_name == "0x00 0x00 0x00 0x00 0x00 0x00 ")
 {
   set_kb_item(name:"SMB/samba", value:TRUE);  
   hole_answer = hole_answer + string("\n. This SMB server seems to be a SAMBA server (this is not a security
risk, this is for your information). This can be told because this server 
claims to have a null MAC address");
 }
 else
 {
  hole_answer = hole_answer + string("The remote host has the following MAC address on its adapter :\n");
  hole_answer = hole_answer + "   " + adapter_name;
 }
 hole_answer = hole_answer + string("\n\nIf you do not want to allow everyone to find the NetBios name\nof your computer, you should filter incoming traffic to this port.\n\nRisk factor : Medium");
 security_warning(port:137, data:hole_answer, protocol:"udp");
}
 if(!hostname_found)
     {
      if(candidate)
      {
      set_kb_item(name:"SMB/name", value:candidate);
      hostname_found = 1;
      }
      else set_kb_item(name:"SMB/name", value:"*SMBSERVER");
     }

 if (username)
     {
	set_kb_item(name:"SMB/username", value:username);
     }

 if (messenger_found && messenger)
     {
	set_kb_item(name:"SMB/username", value:messenger);
     }

close(soc);
