#
# This script was written by Noam Rathaus <noamr@securiteam.com>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10879);
 script_version("$Revision: 1.13 $");
 name["english"] = "Shell Command Execution Vulnerability";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote port seems to be running some form of shell script,
with some provided user input. The input is not stripped for such meta 
characters as ` ' | , etc. This would allow a remote attacker to
execute arbitrary code.

Solution : Make sure all meta characters are filtered out, or close the port 
for access from untrusted networks

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the filtering of dangerous meta characters from network binded scripts";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK); # Potentially destructive
 
 script_copyright(english:"This script is Copyright (C) 2001 SecurITeam");

 family["english"] = "Gain a shell remotely";

 script_family(english:family["english"]);
 exit(0);
}

#
# The script code starts here
#

function test_port(port, command)
{
  soc = open_sock_tcp(port);
  if(soc)
  {
   data = string("`", command, "` #\r\n");
   send(socket:soc, data:data);
 
   buf = recv(socket:soc, length:65535, min:1);
   looking_for = string("uid=");

   if (looking_for >< buf)
   {
    security_hole(port);
    return(1);
   }

   close(soc);
  }
 }


function test_for_backtick(port)
{
  soc = open_sock_tcp(port);
  if(soc)
  {
   data = string("`\r\n");
   send(socket:soc, data:data);

   buf = recv(socket:soc, length:65535, min:1);

   looking_for = string("sh: unexpected EOF while looking for ");
   looking_for_2 = raw_string(0x60, 0x60, 0x27);

   looking_for = string(looking_for, looking_for_2);
   if (looking_for >< buf)
   {
    security_hole(port);
    return(1);
   }

   close(soc);
  }
}

ports = get_kb_list("Ports/tcp/*");
if(isnull(ports))exit(0);

foreach port (keys(ports))
{
 port = int(port - "Ports/tcp/");
 if(test_for_backtick(port:port))break;
 if(test_port(port:port, command:"/bin/id"))break;
 test_port(port:port, command:"/usr/bin/id");
}


