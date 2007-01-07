#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GNU Public Licence
#
########################

if(description)
{
 script_id(11239);
 script_version ("$Revision: 1.4 $");
 #script_bugtraq_id(2979);
 #script_cve_id("CVE-2000-0002");
 
 name["english"] = "Hidden WWW server name";
 name["francais"] = "Nom du server WWW caché";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
It seems that your web server tries to hide its version 
or name, which is a good thing.
However, using a special crafted request, Nessus was able 
to discover it.

Risk factor : None

Solution : Fix your configuration.";

 desc["francais"] = "
Il semble que votre serveur web essaie de dissimuler sa
version ou son nom, ce qui est une bonne chose. Toutefois, 
en envoyant une requête spéciale, Nessus a pu le découvrir.

Facteur de risque : Aucun

Solution : Réparez votre configuration.";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Tries to discover the web server name";
 summary["francais"] = "Essaie de découvrir le nom du serveur web";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO); 
 
 script_copyright(english:"This script is Copyright (C) 2003 Michel Arboi",
		francais:"Ce script est Copyright (C) 2003 Michel Arboi");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/www", "httpver.nasl", 80);
 exit(0);
}

#

include("http_func.inc");

port = get_kb_item("Services/www");
if(!port)port = 80;
if (! get_port_state(port)) exit(0);


s = http_open_socket(port);
if(! s) exit(0);

r = http_head(port: port, item: "/");
send(socket: s, data: r);

r = http_recv_headers(s);
http_close_socket(s);

# If anybody can get the server name, exit
srv = string("^Server: *[^ \t\n\r]");
if (egrep(string: r, pattern: srv)) exit(0);

i = 0;
req[i] = string("HELP\r\n\r\n"); i=i+1;
req[i] = string("HEAD / \r\n\r\n"); i=i+1;
req[i] = string("HEAD / HTTP/1.0\r\n\r\n"); i=i+1;
req[i] = string("HEAD / HTTP/1.1\r\nHost: ", get_host_name(), "\r\n\r\n"); i=i+1;

for (i = 0; req[i]; i=i+1)
{
  s = http_open_socket(port);
  if (s)
  {
    send(socket: s, data: req[i]);
    r = http_recv_headers(s);
    http_close_socket(s);
    if (strlen(r) && (s1 = egrep(string: r, pattern: srv)))
    {
     s1 -= '\r\n'; s1 -= 'Server:';
     rep = "
It seems that your web server tries to hide its version 
or name, which is a good thing.
However, using a special crafted request, Nessus was able 
to determine that is is running : 
" + s1 + "

Risk factor : None
Solution : Fix your configuration.";

      security_warning(port:port, data:rep);
      # We check before: creating a list is not a good idea
      sb = string("www/banner/", port);
      if (! get_kb_item(sb))
        set_kb_item(name: sb, value: r);
      else
      {
        sb = string("www/alt-banner/", port);
        if (! get_kb_item(sb))
          set_kb_item(name: sb, value: r);
      }
      exit(0);
    }
  }
}
