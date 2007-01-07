#
# Copyright 2001 by Noam Rathaus <noamr@securiteam.com>
#
# See the Nessus Scripts License for details
#
#

desc["english"] = "
We detected the remote web server to be a Compaq WBEM server. 
This web server enables attackers to gather sensitive information on 
the remote host, especially if anonymous access has been enabled.

Sensitive information includes: Platform name and version (including 
service packs), installed hotfixes, Running services, installed Drivers, 
boot.ini content, registry settings, NetBIOS name, system root directory, 
administrator full name, CPU type, CPU speed, ROM versions and revisions, 
memory size, sever recovery settings, and more.

Solution: Disable the Anonymous access to Compaq WBEM web server, or 
block the web server's port number on your Firewall.

Risk factor : Medium";



if(description)
{
 script_id(10746);
 script_version ("$Revision: 1.7 $");

 name["english"] = "Compaq WBEM Server Detection";
 script_name(english:name["english"]);

 
 script_description(english:desc["english"]);

 summary["english"] = "Compaq WBEM Server Detect";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2001 SecuriTeam");
 family["english"] = "General";
 script_family(english:family["english"]);

 script_dependencie("find_service.nes");
 script_require_ports("Services/www", 2301);
 exit(0);
}

#
# The script code starts here
#
 include("http_func.inc");
 include("misc_func.inc");
 
 ports = add_port_in_list(list:get_kb_list("Services/www"), port:2301);
 foreach port (ports)
 {
 banner = get_http_banner(port:port);
 if(banner)
 {
  buf = banner;
  if (egrep(pattern:"^Server: CompaqHTTPServer/", string:buf))
  {
   mod_buf = strstr(buf, "Server: CompaqHTTPServer/");
   mod_buf = mod_buf - "Server: CompaqHTTPServer/";
   subbuf = strstr(mod_buf, string("\n"));
   mod_buf = mod_buf - subbuf;
   version = mod_buf;

   wbem_version = "false";
   if (buf >< "var VersionCheck = ")
   {
    mod_buf = strstr(buf, "var VersionCheck = ");
    mod_buf = mod_buf - string("var VersionCheck = ");
    mod_buf = mod_buf - raw_string(0x22);
    subbuf = strstr(mod_buf, raw_string(0x22));
    mod_buf = mod_buf - subbuf;
    wbem_version = mod_buf;
   }

   buf = "Remote Compaq HTTP server version is: ";
   buf = buf + version;
   if (!(wbem_version == "false"))
   {
    buf = string(buf, "\nCompaq WBEM server version: ");
    buf = buf + wbem_version;
   }
   report = string(desc["english"], "\n", buf);
   security_warning(data:buf, port:port);
  }
  }
 }
