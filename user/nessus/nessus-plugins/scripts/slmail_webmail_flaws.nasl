#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Refs:
#
#  From: "NGSSoftware Insight Security Research" <nisr@nextgenss.com>
#  To: <ntbugtraq@listserv.ntbugtraq.com>, <bugtraq@securityfocus.com>,
#        <vulnwatch@vulnwatch.org>
#  Subject: Multiple Vulnerabilities in SLWebmail
#  Date: Wed, 7 May 2003 18:05:18 +0100

if(description)
{
 script_id(11596);
 script_version ("$Revision: 1.3 $");
 name["english"] = "SLMail WebMail overflows";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of the SLmail 
WebMail server which is vulnerable to various flaws.

These flaws may let a user to execute arbitrary code
on this host or read arbitrary files.


Solution : Upgrade to the latest version of SLWebMail 3
Risk Factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if the remote SLWebMail server is flawed";
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_kb_item("Services/www");
if(!port)port = 80;

no404 = get_kb_item(string("www/", port, "/no404"));
if(no404)exit(0);

if(get_port_state(port))
{ 
  dirx = make_list();
  foreach dir (cgi_dirs())
  {
   dirx = make_list(dirx, dir + "/SLwebmail");
  }
  
  foreach dir (dirx)
  {
   req = http_get(item:dir + "/ShowLogin.dll?Language=fr", port:port);
   res = http_keepalive_send_recv(port:port, data:req);
   if('class="ContentTitle"' >< res && 
      'class="BDTitle"' >< res && 
      "Company = " >< res)
   {
    req = http_get(item:dir + "/ShowGodLog.dll", port:port);
    if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 ", string:req))
    {
     security_hole(port);
     exit(0);
    }
   }
  }
}

