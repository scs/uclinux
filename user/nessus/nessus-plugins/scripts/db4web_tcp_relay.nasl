# The script was written by Michel Arboi <arboi@alussinan.org>
# GNU Public Licence
#
# References:
#
# From:Stefan.Bagdohn@guardeonic.com
# To: bugtraq@securityfocus.com
# Subject: Advisory: TCP-Connection risk in DB4Web 
# Date: Tue, 17 Sep 2002 14:44:17 +0200
#

if(description)
{
 script_id(11180);
 script_version ("$Revision: 1.3 $");
  
 name["english"] = "DB4Web TCP relay";
 script_name(english:name["english"]);
 
 desc["english"] = "
DB4Web debug page allows anybody to scan other machines.
You may be held for responsible.

Solution : Replace the debug page with a non-verbose error page.

Risk factor : Medium";


 desc["francais"] = "
La page de debug de DB4Web permet à n'importe qui
de scanner d'autres machines.
Votre responsabilité pourrait être engagée.

Solution : Remplacez la page de debug par une page d'erreur moins verbeuse 

Facteur de risque : Moyen";




 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "DB4Web debug page allow bounce scan";
 summary["francais"] = "La page de debug de DB4Web permet de scanner par rebond";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi",
		francais:"Ce script est Copyright (C) 2002 Michel Arboi");	

 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 	

 script_dependencie("find_service.nes", "no404.nasl", "httpver.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}


include("http_func.inc");

port = get_kb_item("Services/www");
if (! port) port = 80;
if (! get_port_state(port)) exit(0);

s = http_open_socket(port);
if (!s) exit(0);

# testhost = "nosuchwww.example.com";
testhost = this_host_name();

r = http_get(port: port, item: string("/DB4Web/", testhost, ":23/foo"));
send(socket: s, data: r);
c = http_recv(socket: s);
http_close_socket(s);

if ((("connect() ok" >< c) || ("connect() failed:" >< c)) &&
    ("callmethodbinary_2 failed" >< c))
  security_hole(port);
