#ifndef _CONFIG_H_
	#define _CONFIG_H_

int parseConfigFile(int *insert_forward_rules, int *debug_mode, char iptables_location[],
		    char forward_chain_name[], char prerouting_chain_name[],
		    char upstream_bitrate[], char downstream_bitrate[],
		    char desc_doc[], char xml_path[]);

#endif // _CONFIG_H_
