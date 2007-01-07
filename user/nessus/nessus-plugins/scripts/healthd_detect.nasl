#
# Copyright 2001 by Noam Rathaus <noamr@securiteam.com> 
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Should cover BID: 1107
#
# See the Nessus Scripts License for details
#
#

if(description)
{
 script_id(10731); 
 script_version ("$Revision: 1.6 $");
 
 name["english"] = "HealthD detection";
 script_name(english:name["english"]);
 
desc["english"] = "The FreeBSD Health Daemon was detected.
The HealthD provides remote administrators with information about the 
current hardware temperature, fan speed, etc, allowing them to monitor
the status of the server.

Such information about the hardware's current state might be sensitive; 
it is recommended that you do not allow access to this service from the 
network.

Solution: Configure your firewall to block access to this port.

Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "HealthD detection";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 family["english"] = "General";
 script_family(english:family["english"]);

 script_copyright(english:"This script is Copyright (C) 2001 SecuriTeam");
 script_dependencie("find_service.nes");
 script_require_ports("Services/healthd", 1281, 9669);
 exit(0);
}

#
# The script code starts here
#

 port = get_kb_item("Services/healthd");
 if (!port) port = 1281;

 if (get_port_state(port))
 {
  soctcp1281 = open_sock_tcp(port);

  if (!soctcp1281)
  {
   port = 9669;
  }

  close(soctcp1281);
 }

 if (get_port_state(port))
 {
  soctcphealthd = open_sock_tcp(port);

  if (soctcphealthd)
  {
   data = string("foobar");
   resultsend = send(socket:soctcphealthd, data:data);
   resultrecv = recv(socket:soctcphealthd, length:8192);
   if ("ERROR: Unsupported command" >< resultrecv)
   {
    data = string("VER d");
    resultsend = send(socket:soctcphealthd, data:data);
    resultrecv = recv(socket:soctcphealthd, length:8192);

    if ("ERROR: Unsupported command" >< resultrecv)
    {
     security_warning(port:port);
    }
    else
    {
data = string("The FreeBSD Health Daemon was detected.\n",
"The HealthD provides remote administrators with information about\n",
"the current hardware temperature, fan speed, etc, allowing them to monitor\n",
"the status of the server.\n",
"\n",
"Such information about the hardware's current state might be sensitive; \n",
"it is recommended that you do not allow access to this service from the \n",
"network.",
"\n\nThe HealthD version we found is: ", resultrecv, "\n\n",
"Solution: Configure your firewall to block access to this port.\n",
"\n",
"Risk factor : Low\n");
     security_warning(port:port, data:data);
    }
   close(soctcphealthd);
   }
  }
 }
