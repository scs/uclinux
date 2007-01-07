#
# This script was written by Noam Rathaus <noamr@securiteam.com>
# Updated by Paul Johnston for Westpoint Ltd <paul@westpoint.ltd.uk>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10185);
 script_version ("$Revision: 1.12 $");
 name["english"] = "POP3 Server type and version";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote POP3 servers leak information about the software it is running, 
through the login banner. This may assist an attacker in choosing an attack 
strategy. 
 
Versions and types should be omitted where possible.


Solution : Change the login banner to something generic.
Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "POP3 Server type and version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 1999 SecuriTeam");
 family["english"] = "General";
 script_family(english:family["english"]);

 script_dependencie("find_service.nes");
 script_require_ports("Services/pop3", 110);
 exit(0);
}

#
# The script code starts here
#
include("misc_func.inc");

port = get_kb_item("Services/pop3");
if(!port) port = 110;
banner = get_service_banner_line(service:"pop3", port:port);

banner = ereg_replace(pattern:"\[.*\]", replace:"", string:banner);
banner = ereg_replace(pattern:"<.*>", replace:"", string:banner);
banner = ereg_replace(pattern:"POP3", replace:"", string:banner, icase:TRUE);

if(ereg(pattern:"[0-9]", string:banner))
{
  report = "
The remote POP3 servers leak information about the software it is running, 
through the login banner. This may assist an attacker in choosing an attack 
strategy. 
 
Versions and types should be omitted where possible.

The version of the remote POP3 server is : 
" + banner + "

Solution : Change the login banner to something generic.
Risk factor : Low";
  security_note(port:port, data:report);
}
