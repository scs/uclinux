
if(description)
{
 script_id(10674);
 script_version ("$Revision: 1.15 $");
 name["english"] = "Microsoft's SQL UDP Info Query";
 script_name(english:name["english"]);
 
 desc["english"] = "
The plugin sends a SQL 'ping' request to retrieve
information about the remote MS SQL database (if any)

Risk factor : Low
Solution : filter incoming traffic to this port";


 script_description(english:desc["english"]);
 
 summary["english"] = "Microsoft's SQL UDP Info Query";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2001 H D Moore");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 exit(0);
}

#
# The script code starts here
#

##
# data returned will look like:
#
#   xServerName;REDEMPTION;InstanceName;MSSQLSERVER;IsClustered;No;Version;8.00.194;tcp;1433;np;\\REDEMPTION\pipe\sql\query;;
#
##

# this magic info request packet
req = raw_string(0x02);


if(!get_udp_port_state(1434))exit(0);

soc = open_sock_udp(1434);


if(soc)
{
	send(socket:soc, data:req);
	r  = recv(socket:soc, length:4096);
	if(!r)exit(0);
        r = strstr(r, "Server");
	close(soc);
	if(r)
	{
	        report = string("Microsoft SQL server has a function wherein remote users can \n");
                report += string("query the database server for the version that is being run.\n");
                report += string("The query takes place over the same UDP port which handles the \n");
                report += string("mapping of multiple SQL server instances on the same machine.\n\n");
                report += string("CAVEAT: It is important to note that, after Version 8.00.194, Microsoft\n");
                report += string("decided not to update this function.  This means that the data \n");
                report += string("returned by the SQL ping is inaccurate for newer releases of SQL Server\n\n");
 		report += string("Nessus sent an MS SQL 'ping' request. The results were : \n", r, "\n\n");
                report += string("If you are not running multiple instances of Microsoft SQL Server\n");
                report += string("on the same machine, It is suggested you filter incoming traffic to this port");
		security_warning(port:1434, protocol:"udp", data:report);
		set_kb_item(name:"mssql/udp/1434", value:TRUE);
	}
}
