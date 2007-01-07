#
# Copyright 2001 by Noam Rathaus <noamr@securiteam.com>
#
# See the Nessus Scripts License for details
#
#
 desc = "
Matt Wright's Formmail CGI is installed on the remote host.
The product exposes its version number, and in addition, 
early versions of the product suffered from security 
vulnerabilities, which include: allowing SPAM, file disclosure, 
environment variable disclosure, and more.

Solution: Upgrade to the latest version.

Risk factor : Low

Additional information:
http://www.securiteam.com/cgi-bin/htsearch?config=htdigSecuriTeam&words=Formmail";

if(description)
{
 script_id(10782);
 script_version ("$Revision: 1.16 $");
 script_cve_id("CAN-2001-0357");

 name["english"] = "Formmail Version Information Disclosure";
 script_name(english:name["english"]);

 script_description(english:desc);

 summary["english"] = "Formmail Version Information Disclosure";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2001 SecuriTeam");
 family["english"] = "General";
 script_family(english:family["english"]);

 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");


dir = make_list(cgi_dirs());


program[0] = "/formmail.pl";
program[1] = "/formmail.pl.cgi";
program[2] = "/FormMail.cgi";

port = get_kb_item("Services/www");
if (!port) port = 80;
if(!get_port_state(port))exit(0);

for (i = 0; dir[i] ; i = i + 1)
{
 for (j = 0; program[j] ; j = j + 1)
 {
   url = string(dir[i], program[j]);
   req = http_get(item:url, port:port);
   buf = http_keepalive_send_recv(port:port, data:req);
   if(buf == NULL)exit(0);
   find_type_1 = string("<title>FormMail v");
   find_type_2 = string("FormMail</a> V");
   if ( ((find_type_1 >< buf) && ("Version " >< buf)) || (find_type_2 >< buf))
    {
     report = string(desc, "\n", "Version : ", buf);
     security_note(port:port, data:report);
     exit(0);
    }
 }
}
