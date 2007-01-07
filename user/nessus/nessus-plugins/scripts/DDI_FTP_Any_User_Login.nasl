#
# This script was written by H D Moore
# 


if(description)
{
    script_id(10990);
    script_version ("$Revision: 1.6 $"); 
    name["english"] = "FTP Service Allows Any Username";
    name["francais"] = "FTP Service Allows Any Username";
    script_name(english:name["english"], francais:name["francais"]);


    desc["english"] = "

The FTP service can be accessed using any username and password.
Many other plugins may trigger falsely because of this, although
they can fixed by setting this plugin as a dependency and excluding
the ftp/AnyUser KB key item.
 
Solution: None

Risk factor : None
";

    desc["francais"] = "FTP Service Allows Any Username";

    script_description(english:desc["english"], francais:desc["francais"]);


    summary["english"] = "FTP Service Allows Any Username";
    summary["francais"] = "FTP Service Allows Any Username";
    script_summary(english:summary["english"], francais:summary["francais"]);


    script_category(ACT_GATHER_INFO);

    script_copyright(english:"This script is Copyright (C) 2002 Digital Defense Inc.",
               francais:"Ce script est Copyright (C) 2002 Digital Defense Inc.");

    family["english"] = "FTP";
    family["francais"] = "FTP";
    script_family(english:family["english"], francais:family["francais"]);
    script_dependencie("find_service.nes", "ftpserver_detect_type_nd_version.nasl");
    
    exit(0);
}


#
# The script code starts here
#

port = get_kb_item("Services/ftp");
if(!port)port = 21;

counter = 0;
if(get_port_state(port))
{
   soc = open_sock_tcp(port);
   if(!soc)exit(0);
   r = recv_line(socket:soc, length:255);
   if(!r)exit(0);
   close(soc);
   
   
    # try NULL:NULL
    soc = open_sock_tcp(port);
    if(soc)
    {
        if(ftp_log_in(socket:soc, user:"NULL", pass:"NULL"))
        {
            counter = counter + 1;
        }
    }
    close(soc);
    
    # try BOGUS:BOGUS123
    soc = open_sock_tcp(port);
    if(soc)
    {
        if(ftp_log_in(socket:soc, user:"BOGUS", pass:"BOGUS123"))
        {
            counter = counter + 1;
        }
    }
    close(soc);
    
    # try root:123456
    soc = open_sock_tcp(port);
    if(soc)
    {
        if(ftp_log_in(socket:soc, user:"root", pass:"123456"))
        {
            counter = counter + 1;
        }
    }
    close(soc);
    
    if (counter == 3)
    {
        set_kb_item(name:"ftp/" + port + "/AnyUser", value:TRUE);
        security_hole(port:port);
    } 
}
