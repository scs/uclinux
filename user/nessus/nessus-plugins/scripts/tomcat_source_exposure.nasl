#
# This script was written by Felix Huber <huberfelix@webtopia.de>
#
# v. 1.00 (last update 24.09.02)

if(description)
{
 script_id(11176);
 script_version("$Revision: 1.8 $");
 name["english"] = "Tomcat 4.x JSP Source Exposure";
 script_name(english:name["english"]);

 desc["english"] = "
Tomcat 4.0.4 and 4.1.10 (probably all other 
earlier versions also) are vulnerable to source 
code exposure by using the default servlet
org.apache.catalina.servlets.DefaultServlet.

Solution:
Upgrade to the last releases 4.0.5 and 4.1.12
See
http://jakarta.apache.org/builds/jakarta-tomcat-4.0/release/ 
for the last releases.

Risk factor : Serious";


 script_description(english:desc["english"]);

 summary["english"] = "Tomcat 4.x JSP Source Exposure";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);


 script_copyright(english:"This script is Copyright (C) 2002 Felix Huber");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes");
 script_dependencie("httpver.nasl", "webmirror.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#


include("http_func.inc");
include("http_keepalive.inc");

function check(sfx)
{
 
   url = string("/servlet/org.apache.catalina.servlets.DefaultServlet", sfx);
   req = http_get(item:url, port:port);
   r = http_keepalive_send_recv(port:port, data:req);
   if( r == NULL ) exit(0);

   if("<%@" >< r){
       security_hole(port);
       exit(0);
      }
      
    if(" 200 OK" >< r)
    {
     if("Server: Apache Tomcat/4." >< r)
     {
                security_hole(port); 
                exit(0); 
      } 
    }
}


 
port = get_kb_item("Services/www");
if(!port)port = 80;

if(!get_port_state(port))exit(0);




dir[0] = "/";
dir[1] = "/index.jsp";
dir[2] = "/default.jsp";
dir[3] = "/index.html";
dir[4] = "/profile.jsp";
dir[5] = "/sort.jsp";
dir[6] = "/topic.jsp";

files = get_kb_list(string("www/",port, "/content/extensions/jsp"));
if(!isnull(files))
 {
  files = make_list(files);
  dir[7] = files[0];
 }

 for (i = 0; dir[i] ; i = i + 1)
 {
  check(sfx:dir[i]);
 }
 
