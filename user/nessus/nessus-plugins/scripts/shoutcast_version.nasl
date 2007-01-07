#
# Copyright 2000 by Noam Rathaus <noamr@securiteam.com>
#
# See the Nessus Scripts License for details
#
#

if(description)
{
 script_id(10717); 
script_cve_id("CAN-2001-1304");
 script_version ("$Revision: 1.6 $");
 
 name["english"] = "SHOUTcast Server DoS detector vulnerability";
 script_name(english:name["english"]);
 
 desc["english"] = "This detects SHOUTcast Server's version. If the version equals 
1.8.2 it is vulnerable to a denial of service attack.

Solution: Upgrade to the latest version of SHOUTcast Server.

Risk factor : Medium

Additional information:
http://www.securiteam.com/exploits/5YP031555Q.html
";

 script_description(english:desc["english"]);
 
 summary["english"] = "SHOUTcast Server DoS detector vulnerability";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2001 SecuriTeam");
 family["english"] = "General";
 script_family(english:family["english"]);

 script_dependencie("find_service.nes");
 script_require_ports("Services/www", 8000);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

 port = get_kb_item("Services/www");
 if (!port) port = 8000;

 if (get_port_state(port))
 {
   banner = get_http_banner(port:port);
   if(!banner)exit(0);
   if ("SHOUTcast Distributed Network Audio Server" >< banner)
   {
    resultrecv = banner;
    resultrecv = strstr(resultrecv, "SHOUTcast Distributed Network Audio Server/");
    resultsub = strstr(resultrecv, string("<BR>"));
    resultrecv = resultrecv - resultsub;
    resultrecv = resultrecv - "SHOUTcast Distributed Network Audio Server/";
    resultrecv = resultrecv - "<BR>";
    report = string("The remote SHOUTcast server version is :\n");
    report = report + resultrecv;
    if ("1.8.2" >< resultrecv)
    {
     report = report + string("\n\nThis version of SHOUTcast is supposedly vulnerable to a denial of service attack. Upgrade your SHOUTcast server.\n");
     security_hole(port:port, data:report);
    }
    else
    {
     security_note(port:port, data:report);
    }
   } 
 }
