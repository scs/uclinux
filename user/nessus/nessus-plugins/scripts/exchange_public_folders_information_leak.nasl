#
# Copyright 2000 by Noam Rathaus <noamr@securiteam.com>
#
# See the Nessus Scripts License for details
#
#

if(description)
{
 script_id(10755);
 script_cve_id("CVE-2001-0660");
 script_bugtraq_id(3301);
 script_version ("$Revision: 1.12 $");

 name["english"] = "Microsoft Exchange Public Folders Information Leak";
 script_name(english:name["english"]);

 desc["english"] = "Microsoft Exchange Public Folders can be set to allow anonymous connections (set by default). If this is not changed it is possible for
an attacker to gain critical information about the users (such as full email address, phone number, etc) that are present in the Exchange Server.

Risk factor : Medium

Additional information:
http://www.securiteam.com/windowsntfocus/5WP091P5FQ.html
";

 script_description(english:desc["english"]);

 summary["english"] = "Microsoft Exchange Public Folders Information Leak";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2001 SecuriTeam");
 family["english"] = "General";
 script_family(english:family["english"]);

 script_dependencie("find_service.nes", "no404.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/iis");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = is_cgi_installed("/exchange/root.asp");
if (port)
{
 Host = "";
 if (get_host_name())
 {
  Host = get_host_name();
 }
 else
 {
  Host = get_host_ip();
 } 

 #display(Host, "\n");
 if (Host)
 {
  first = http_get(item:"/exchange/root.asp?acs=anon", port:port);

  soctcp80 = http_open_socket(port);
  if (soctcp80)
  {
   send(socket:soctcp80, data:first);
   result = http_recv(socket:soctcp80);

   SetCookie = 0;
   #display(result);
   
   if ((egrep(pattern:"^HTTP/[0-9]\.[0-9] 200 .*", string:result)) && ("Set-Cookie: " >< result) && ("top.location='/exchange/logonfrm.asp'" >< result))
   {
    #display("Done First step\n");

    SetCookie = strstr(result, "Set-Cookie: ");
    resultsub = strstr(SetCookie, "; path=/");
    SetCookie = SetCookie - "Set-Cookie: ";
    SetCookie = SetCookie - resultsub;

    #display("Cookie: ", SetCookie, "\n");

    second = string("GET /exchange/logonfrm.asp HTTP/1.1\r\nHost: ", Host, "\r\nCookie: ", SetCookie, "\r\n\r\n");
    

    send(socket:soctcp80, data:second);
    result = http_recv(socket:soctcp80);
    #display(result);

    if ((egrep(pattern:"^HTTP/[0-9]\.[0-9] 302 .*", string:result)) && ("Location: /exchange/root.asp?acs=anon" >< result))
    {
     #display("Done Second step\n");

     third = string("GET /exchange/root.asp?acs=anon HTTP/1.1\r\nHost: ", Host, "\r\nCookie: ", SetCookie, "\r\n\r\n");

     send(socket:soctcp80, data:third);
     result = http_recv(socket:soctcp80);
     #display(result);

     if ((egrep(pattern:"^HTTP/[0-9]\.[0-9] 200 .*", string:result)) && ("/exchange/Navbar/nbAnon.asp" >< result))
     {
      #display("Done Third step\n");

      final = string("POST /exchange/finduser/fumsg.asp HTTP/1.1\r\nHost: ", Host, "\r\nAccept: */*\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 44\r\nCookie: ", SetCookie, "\r\n\r\nDN=a&FN=&LN=&TL=&AN=&CP=&DP=&OF=&CY=&ST=&CO=");

      send(socket:soctcp80, data:final);
      result = http_recv(socket:soctcp80);
      http_close_socket(soctcp80);
      #display(result);
      if ((egrep(pattern:"^HTTP/[0-9]\.[0-9] 200 .*", string:result)) && (("details.asp?obj=" >< result) || ("This query would return" >< result)) )
      {
       security_hole(port:port);
      }
     }
    }
   }
  }
 }
}
