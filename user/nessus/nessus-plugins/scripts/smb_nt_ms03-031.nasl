 #
# (C) Tenable Network Security
#
	       
if(description)
{
 script_id(11804);
 script_version ("$Revision: 1.4 $");
 name["english"] = "Cumulative Patch for MS SQL Server (815495)";
 script_name(english:name["english"]);
 
 script_cve_id("CAN-2003-0230", "CAN-2003-0231", "CAN-2003-0232");
	       
 script_bugtraq_id(8274, 8275, 8276);
  
 desc["english"] = "
The remote Microsoft SQL server is vulnerable to several flaws :

- Named pipe hijacking
- Named Pipe Denial of Service
- SQL server buffer overrun

These flaws may allow a user to gain elevated privileges on this
host.

Solution : See http://www.microsoft.com/technet/security/bulletin/ms03-031.asp
Risk Factor : High";


 script_description(english:desc["english"]);

 summary["english"] = "Microsoft's SQL Version Query";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 script_dependencies("mssql_version.nasl");
 script_require_keys("mssql/SQLVersion");
 script_require_ports(139, 445, 1433, "Services/mssql");

 exit(0);
}


# Filed by mssql_version.nasl

version = get_kb_item("mssql/SQLVersion");
if(!version)exit(0);

if(ereg(pattern:"^7\.00\.([0-9][0-9]?[0-9]?$|10([0-8][0-9]|9[0-3]))", string:version))
{
 port = get_kb_item("Services/mssql");
 if(!port)port = 1433;
 if(!get_port_state(port))port = get_kb_item("SMB/transport");
 security_hole(port);
 exit(0);
}

if(ereg(pattern:"^8\.00\.(0?[0-9]?[0-9]?$|0?([0-7][0-9][0-9]|8(0[0-9]|1[0-7]))$)", string:version))
{
 port = get_kb_item("Services/mssql");
 if(!port)port = 1433;
 if(!get_port_state(port))port = get_kb_item("SMB/transport");
 security_hole(port);
}
