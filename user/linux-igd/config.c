#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>
#include <sys/stat.h>


#define CONF_FILE "/etc/config/upnpd.conf"
#define MAX_CONFIG_LINE 256
#define IPTABLES_DEFAULT_FORWARD_CHAIN "FORWARD"
#define IPTABLES_DEFAULT_PREROUTING_CHAIN "PREROUTING"
#define IPTABLES_DEFAULT_UPSTREAM_BITRATE "0"
#define IPTABLES_DEFAULT_DOWNSTREAM_BITRATE "0"
#define DESC_DOC_DEFAULT "gatedesc.xml"
#define XML_PATH_DEFAULT "/etc/linuxigd"

int getConfigOptionArgument(char string[],char line[], regmatch_t *submatch) 
{
    int match_length;
    match_length=submatch[1].rm_eo-submatch[1].rm_so;
    // Make sure we don't write past the end of string[]
    if (sizeof(string) >= match_length) {
	match_length = sizeof(string) - 1;
    }
    strncpy(string,&line[submatch[1].rm_so],match_length);
    // Make sure string[] is null terminated
    strcpy(string + match_length,"");
    return 0;
}

int parseConfigFile(int *insert_forward_rules, int *debug_mode, char iptables_location[],
		    char forward_chain_name[], char prerouting_chain_name[],
		    char upstream_bitrate[], char downstream_bitrate[],
		    char desc_doc[], char xml_path[])
{
    FILE *conf_file;
    regmatch_t submatch[2]; // Stores the regex submatch start end end index
    
    regex_t re_comment;
    regex_t re_empty_row;
    regex_t re_iptables_location;
    regex_t re_debug_mode;
    regex_t re_insert_forward_rules_yes;
    regex_t re_forward_chain_name;
    regex_t re_prerouting_chain_name;
    regex_t re_upstream_bitrate;
    regex_t re_downstream_bitrate;
    regex_t re_desc_doc;
    regex_t re_xml_path;

    // Make sure all vars are 0 or \0 terminated
    *debug_mode = 0;
    *insert_forward_rules = 0;
    strcpy(iptables_location,"");
    strcpy(forward_chain_name,"");
    strcpy(prerouting_chain_name,"");
    strcpy(upstream_bitrate,"");
    strcpy(downstream_bitrate,"");
    strcpy(desc_doc,"");
    strcpy(xml_path,"");

    // Regexp to match a comment line
    regcomp(&re_comment,"^[[:blank:]]*#",0);
    regcomp(&re_empty_row,"^[[:blank:]]*\r?\n$",REG_EXTENDED);
    regcomp(&re_iptables_location,"iptables_location[[:blank:]]*=[[:blank:]]*([[:alpha:]/_]+)",REG_EXTENDED);
    // Regexps to match debug_mode, insert_forward_rules, forward_chain_name
    regcomp(&re_debug_mode,"debug_mode[[:blank:]]*=[[:blank:]]*([[:digit:]])",REG_EXTENDED);
    regcomp(&re_insert_forward_rules_yes,"insert_forward_rules[[:blank:]]*=[[:blank:]]*yes",REG_ICASE);
    regcomp(&re_forward_chain_name,"forward_chain_name[[:blank:]]*=[[:blank:]]*([[:alpha:]_-]+)",REG_EXTENDED);
    regcomp(&re_prerouting_chain_name,"prerouting_chain_name[[:blank:]]*=[[:blank:]]([[:alpha:]_-]+)",REG_EXTENDED);
    regcomp(&re_upstream_bitrate,"upstream_bitrate[[:blank:]]*=[[:blank:]]*([[:digit:]]+)",REG_EXTENDED);
    regcomp(&re_downstream_bitrate,"downstream_bitrate[[:blank:]]*=[[:blank:]]*([[:digit:]]+)",REG_EXTENDED);
    
    regcomp(&re_desc_doc,"description_document_name[[:blank:]]*=[[:blank:]]*([[:alpha:].]{1,20})",REG_EXTENDED);
    regcomp(&re_xml_path,"xml_document_path[[:blank:]]*=[[:blank:]]*([[:alpha:]_/.]{1,50})",REG_EXTENDED);

    if ((conf_file=fopen(CONF_FILE,"r")) != NULL)
    {
	char line[MAX_CONFIG_LINE];
	// Walk through the config file line by line
	while(fgets(line,MAX_CONFIG_LINE,conf_file) != NULL)
	{
	    // Check if a comment line or an empty one
	    if ( (0 != regexec(&re_comment,line,0,NULL,0)  )  && 
		 (0 != regexec(&re_empty_row,line,0,NULL,0))  )
	    {
		// Chec if iptables_location
		if (0 == regexec(&re_iptables_location,line,2,submatch,0))
		{
		    getConfigOptionArgument(iptables_location,line,submatch);
		}
		
		// Check is insert_forward_rules
		else if (0 == regexec(&re_insert_forward_rules_yes,line,0,NULL,0))
		{
		    *insert_forward_rules = 1;
		}
		// Check forward_chain_name
		else if (0 == regexec(&re_forward_chain_name,line,2,submatch,0))
		{
		    getConfigOptionArgument(forward_chain_name,line,submatch);
		}
		else if (0 == regexec(&re_debug_mode,line,2,submatch,0) )
		{
		    char tmp[2];
		    sprintf(tmp,"0");
		    strncpy(tmp,&line[submatch[1].rm_so],1);
		    *debug_mode = atoi(tmp);
		}
		else if (0 == regexec(&re_prerouting_chain_name,line,2,submatch,0))
		{
		    getConfigOptionArgument(prerouting_chain_name,line,submatch);
		}
		else if (0 == regexec(&re_upstream_bitrate,line,2,submatch,0))
		{
		    getConfigOptionArgument(upstream_bitrate,line,submatch);
		}
		else if (0 == regexec(&re_downstream_bitrate,line,2,submatch,0))
		{
		    getConfigOptionArgument(downstream_bitrate,line,submatch);
		}
		else if (0 == regexec(&re_desc_doc,line,2,submatch,0))
		{
		    getConfigOptionArgument(desc_doc,line,submatch);
		}
		else if (0 == regexec(&re_xml_path,line,2,submatch,0))
		{
		    getConfigOptionArgument(xml_path,line,submatch);
		}
		else
		{
		    // We end up here if ther is an unknown config directive
		    printf("Unknown config line:%s",line);
		}
	    }
	}
	fclose(conf_file);
    }
    regfree(&re_comment);
    regfree(&re_empty_row);
    regfree(&re_debug_mode);	
    regfree(&re_insert_forward_rules_yes);	
    regfree(&re_forward_chain_name);
    regfree(&re_prerouting_chain_name);
    regfree(&re_upstream_bitrate);
    regfree(&re_downstream_bitrate);
    regfree(&re_desc_doc);
    regfree(&re_xml_path);
    // Set default values for options not found in config file
    if (0 == strlen(forward_chain_name))
    {
	// No forward chain name was set in conf file, set it to default
	sprintf(forward_chain_name,IPTABLES_DEFAULT_FORWARD_CHAIN);
    }
    if (0 == strlen(prerouting_chain_name))
    {
	// No prerouting chain name was set in conf file, set it to default
	sprintf(prerouting_chain_name,IPTABLES_DEFAULT_PREROUTING_CHAIN);
    }
    if (0 == strlen(upstream_bitrate))
    {
	// No upstream_bitrate was found in the conf file, set it to default
	sprintf(upstream_bitrate,IPTABLES_DEFAULT_UPSTREAM_BITRATE);
    }
    if (0 == strlen(downstream_bitrate))
    {
	// No downstream bitrate was found in the conf file, set it to default
	sprintf(downstream_bitrate,IPTABLES_DEFAULT_DOWNSTREAM_BITRATE);
    }
    if (0 == strlen(desc_doc))
    {
	sprintf(desc_doc,DESC_DOC_DEFAULT);
    }
    if (0 == strlen(xml_path))
    {
	sprintf(xml_path,XML_PATH_DEFAULT);
    }
    if (0 == strlen(iptables_location)) {
	// Can't find the iptables executable, return -1 to 
	// indicate en error
	return -1;
    }
    else
    {
	return 0;
    }
}
/*
int main (int argc, char** argv)
{
    int insert_forward_rules;
    int debug_mode;
    char iptables[30]="";
    char forward_chain_name[20]="";
    char prerouting_chain_name[20]="";
    char upstream_bitrate[10]="";
    char downstream_bitrate[10]="";
    char desc_doc[10]="";
    char xml_path[50]="";
    if (-1 == parseConfigFile(&insert_forward_rules, &debug_mode, iptables, forward_chain_name,
			      prerouting_chain_name, upstream_bitrate, downstream_bitrate,
			      desc_doc, xml_path) )
    {
	printf("Error: can't find iptables executable");
    }
    printf("\nForward = %d\n",insert_forward_rules);
    printf("Forward chain = %s\n",forward_chain_name);
    printf("Debug-mode = %d\n",debug_mode);
    printf("iptables= %s\n",iptables);
    printf("prerouting chain=%s\n",prerouting_chain_name);
    printf("upstream bitrate=%s\n",upstream_bitrate);
    printf("downstream bitrate=%s\n",downstream_bitrate);
    printf("desc_doc=%s\n",desc_doc);
    printf("xml_path=%s\n",xml_path);
    printf("\n");
    return 0;
}

*/
