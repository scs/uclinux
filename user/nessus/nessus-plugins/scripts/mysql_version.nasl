# This script was written by Noam Rathaus <noamr@securiteam.com>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10719); 
 script_version ("$Revision: 1.14 $");
 name["english"] = "MySQL Server version";
 script_name(english:name["english"]);

 desc["english"] = "This detects MySQL Server's version by connecting to the server and processing the buffer received.
This information gives potential attackers additional information about the system they are attacking. Versions should be omitted where possible.

Solution: Change the version number to something generic (like: 0.0.0.0)

Risk factor : Low";

 script_description(english:desc["english"]);

 summary["english"] = "MySQL Server version";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2001 SecuriTeam");
 family["english"] = "General";
 script_family(english:family["english"]);
 script_require_ports("Services/mysql", 3306);
 script_dependencies("find_service.nes");
 exit(0);
}


#
# The script code starts here
#

include("misc_func.inc");

port = get_kb_item("Services/mysql");
if (!port) port = 3306;

mySQL_version=get_mysql_version(port);

if(mySQL_version)
{
   mySQL_version = string("Remote MySQL version : ", mySQL_version);
   security_note(port:port, data:mySQL_version);
   register_service(port:port, proto:"mysql");
}

