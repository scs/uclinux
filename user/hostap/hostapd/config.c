/*
 * Host AP (software wireless LAN access point) user space daemon for
 * Host AP kernel driver / Configuration file
 * Copyright (c) 2003, Jouni Malinen <jkmaline@cc.hut.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. See README and COPYING for
 * more details.
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "hostapd.h"


static struct hostapd_config *hostapd_config_defaults(void)
{
	struct hostapd_config *conf;

	conf = malloc(sizeof(*conf));
	if (conf == NULL) {
		printf("Failed to allocate memory for configuration data.\n");
		return NULL;
	}
	memset(conf, 0, sizeof(*conf));

	conf->ssid_len = 4;
	memcpy(conf->ssid, "test", 4);
	conf->wep_rekeying_period = 300;

	conf->logger_syslog_level = HOSTAPD_LEVEL_INFO;
	conf->logger_stdout_level = HOSTAPD_LEVEL_INFO;
	conf->logger_syslog = (unsigned int) -1;
	conf->logger_stdout = (unsigned int) -1;

	conf->auth_algs = HOSTAPD_AUTH_OPEN | HOSTAPD_AUTH_SHARED_KEY;

	return conf;
}


static int mac_comp(const void *a, const void *b)
{
	return memcmp(a, b, sizeof(macaddr));
}


static int hostapd_config_read_maclist(const char *fname, macaddr **acl,
				       int *num)
{
	FILE *f;
	char buf[128], *pos;
	int line = 0;
	u8 addr[ETH_ALEN];
	macaddr *newacl;

	if (!fname)
		return 0;

	f = fopen(fname, "r");
	if (!f) {
		printf("MAC list file '%s' not found.\n", fname);
		return -1;
	}

	while (fgets(buf, sizeof(buf), f)) {
		line++;

		if (buf[0] == '#')
			continue;
		pos = buf;
		while (*pos != '\0') {
			if (*pos == '\n') {
				*pos = '\0';
				break;
			}
			pos++;
		}
		if (buf[0] == '\0')
			continue;

		if (hwaddr_aton(buf, addr)) {
			printf("Invalid MAC address '%s' at line %d in '%s'\n",
			       buf, line, fname);
			fclose(f);
			return -1;
		}

		newacl = (macaddr *) realloc(*acl, (*num + 1) * ETH_ALEN);
		if (newacl == NULL) {
			printf("MAC list reallocation failed\n");
			fclose(f);
			return -1;
		}

		*acl = newacl;
		memcpy((*acl)[*num], addr, ETH_ALEN);
		(*num)++;
	}

	fclose(f);

	qsort(*acl, *num, sizeof(macaddr), mac_comp);

	return 0;
}


static int
hostapd_config_read_radius_addr(struct hostapd_radius_server **server,
				int *num_server, const char *val, int def_port,
				struct hostapd_radius_server **curr_serv)
{
	struct hostapd_radius_server *nserv;
	int ret;

	nserv = realloc(*server, (*num_server + 1) * sizeof(*nserv));
	if (nserv == NULL)
		return -1;

	*server = nserv;
	nserv = &nserv[*num_server];
	(*num_server)++;
	(*curr_serv) = nserv;

	memset(nserv, 0, sizeof(*nserv));
	nserv->port = def_port;
	ret = !inet_aton(val, &nserv->addr);

	return ret;
}


static int hostapd_config_check(struct hostapd_config *conf)
{
	if (conf->ieee802_1x && !conf->minimal_eap && !conf->auth_servers) {
		printf("Invalid IEEE 802.1X configuration.\n");
		return -1;
	}

	return 0;
}


struct hostapd_config * hostapd_config_read(const char *fname)
{
	struct hostapd_config *conf;
	FILE *f;
	char buf[256], *pos;
	int line = 0;
	int errors = 0;
	char *accept_mac_file = NULL, *deny_mac_file = NULL;

	f = fopen(fname, "r");
	if (f == NULL) {
		printf("Could not open configuration file '%s' for reading.\n",
		       fname);
		return NULL;
	}

	conf = hostapd_config_defaults();
	if (conf == NULL) {
		fclose(f);
		return NULL;
	}

	while (fgets(buf, sizeof(buf), f)) {
		line++;

		if (buf[0] == '#')
			continue;
		pos = buf;
		while (*pos != '\0') {
			if (*pos == '\n') {
				*pos = '\0';
				break;
			}
			pos++;
		}
		if (buf[0] == '\0')
			continue;

		pos = strchr(buf, '=');
		if (pos == NULL) {
			printf("Line %d: invalid line '%s'\n", line, buf);
			errors++;
			continue;
		}
		*pos = '\0';
		pos++;

		if (strcmp(buf, "interface") == 0) {
			snprintf(conf->iface, sizeof(conf->iface), "%s", pos);
		} else if (strcmp(buf, "debug") == 0) {
			conf->debug = atoi(pos);
		} else if (strcmp(buf, "logger_syslog_level") == 0) {
			conf->logger_syslog_level = atoi(pos);
		} else if (strcmp(buf, "logger_stdout_level") == 0) {
			conf->logger_stdout_level = atoi(pos);
		} else if (strcmp(buf, "logger_syslog") == 0) {
			conf->logger_syslog = atoi(pos);
		} else if (strcmp(buf, "logger_stdout") == 0) {
			conf->logger_stdout = atoi(pos);
		} else if (strcmp(buf, "dump_file") == 0) {
			conf->dump_log_name = strdup(pos);
		} else if (strcmp(buf, "daemonize") == 0) {
			conf->daemonize = atoi(pos);
		} else if (strcmp(buf, "ssid") == 0) {
			conf->ssid_len = strlen(pos);
			if (conf->ssid_len >= HOSTAPD_SSID_LEN ||
			    conf->ssid_len < 1) {
				printf("Line %d: invalid SSID '%s'\n", line,
				       pos);
				errors++;
			}
			memcpy(conf->ssid, pos, conf->ssid_len);
			conf->ssid[conf->ssid_len] = '\0';
		} else if (strcmp(buf, "macaddr_acl") == 0) {
			conf->macaddr_acl = atoi(pos);
			if (conf->macaddr_acl != ACCEPT_UNLESS_DENIED &&
			    conf->macaddr_acl != DENY_UNLESS_ACCEPTED &&
			    conf->macaddr_acl != USE_EXTERNAL_RADIUS_AUTH) {
				printf("Line %d: unknown macaddr_acl %d\n",
				       line, conf->macaddr_acl);
			}
		} else if (strcmp(buf, "accept_mac_file") == 0) {
			accept_mac_file = strdup(pos);
			if (!accept_mac_file) {
				printf("Line %d: allocation failed\n", line);
				errors++;
			}
		} else if (strcmp(buf, "deny_mac_file") == 0) {
			deny_mac_file = strdup(pos);
			if (!deny_mac_file) {
				printf("Line %d: allocation failed\n", line);
				errors++;
			}
		} else if (strcmp(buf, "assoc_ap_addr") == 0) {
			if (hwaddr_aton(pos, conf->assoc_ap_addr)) {
				printf("Line %d: invalid MAC address '%s'\n",
				       line, pos);
				errors++;
			}
			conf->assoc_ap = 1;
		} else if (strcmp(buf, "ieee8021x") == 0) {
			conf->ieee802_1x = atoi(pos);
		} else if (strcmp(buf, "minimal_eap") == 0) {
			conf->minimal_eap = atoi(pos);
		} else if (strcmp(buf, "eap_message") == 0) {
			conf->eap_req_id_text = strdup(pos);
		} else if (strcmp(buf, "wep_key_len_broadcast") == 0) {
			conf->default_wep_key_len = atoi(pos);
			if (conf->default_wep_key_len > 13) {
				printf("Line %d: invalid WEP key len %d "
				       "(= %d bits)\n", line,
				       conf->default_wep_key_len,
				       conf->default_wep_key_len * 8);
				errors++;
			}
		} else if (strcmp(buf, "wep_key_len_unicast") == 0) {
			conf->individual_wep_key_len = atoi(pos);
			if (conf->individual_wep_key_len < 0 ||
			    conf->individual_wep_key_len > 13) {
				printf("Line %d: invalid WEP key len %d "
				       "(= %d bits)\n", line,
				       conf->individual_wep_key_len,
				       conf->individual_wep_key_len * 8);
				errors++;
			}
		} else if (strcmp(buf, "wep_rekey_period") == 0) {
			conf->wep_rekeying_period = atoi(pos);
			if (conf->wep_rekeying_period < 0) {
				printf("Line %d: invalid period %d\n",
				       line, conf->wep_rekeying_period);
				errors++;
			}
		} else if (strcmp(buf, "eapol_key_index_workaround") == 0) {
			conf->eapol_key_index_workaround = atoi(pos);
		} else if (strcmp(buf, "iapp_interface") == 0) {
			conf->ieee802_11f = 1;
			snprintf(conf->iapp_iface, sizeof(conf->iapp_iface),
				 "%s", pos);
		} else if (strcmp(buf, "own_ip_addr") == 0) {
			if (!inet_aton(pos, &conf->own_ip_addr)) {
				printf("Line %d: invalid IP address '%s'\n",
				       line, pos);
				errors++;
			}
		} else if (strcmp(buf, "auth_server_addr") == 0) {
			if (hostapd_config_read_radius_addr(
				    &conf->auth_servers,
				    &conf->num_auth_servers, pos, 1812,
				    &conf->auth_server)) {
				printf("Line %d: invalid IP address '%s'\n",
				       line, pos);
				errors++;
			}
		} else if (conf->auth_server &&
			   strcmp(buf, "auth_server_port") == 0) {
			conf->auth_server->port = atoi(pos);
		} else if (conf->auth_server &&
			   strcmp(buf, "auth_server_shared_secret") == 0) {
			int len = strlen(pos);
			if (len == 0) {
				/* RFC 2865, Ch. 3 */
				printf("Line %d: empty shared secret is not "
				       "allowed.\n", line);
				errors++;
			}
			conf->auth_server->shared_secret = strdup(pos);
			conf->auth_server->shared_secret_len = len;
		} else if (strcmp(buf, "acct_server_addr") == 0) {
			if (hostapd_config_read_radius_addr(
				    &conf->acct_servers,
				    &conf->num_acct_servers, pos, 1813,
				    &conf->acct_server)) {
				printf("Line %d: invalid IP address '%s'\n",
				       line, pos);
				errors++;
			}
		} else if (conf->acct_server &&
			   strcmp(buf, "acct_server_port") == 0) {
			conf->acct_server->port = atoi(pos);
		} else if (conf->acct_server &&
			   strcmp(buf, "acct_server_shared_secret") == 0) {
			int len = strlen(pos);
			if (len == 0) {
				/* RFC 2865, Ch. 3 */
				printf("Line %d: empty shared secret is not "
				       "allowed.\n", line);
				errors++;
			}
			conf->acct_server->shared_secret = strdup(pos);
			conf->acct_server->shared_secret_len = len;
		} else if (strcmp(buf, "radius_retry_primary_interval") == 0) {
			conf->radius_retry_primary_interval = atoi(pos);
		} else if (strcmp(buf, "radius_acct_interim_interval") == 0) {
			conf->radius_acct_interim_interval = atoi(pos);
		} else if (strcmp(buf, "auth_algs") == 0) {
			conf->auth_algs = atoi(pos);
		} else {
			printf("Line %d: unknown configuration item '%s'\n",
			       line, buf);
			errors++;
		}
	}

	fclose(f);

	if (hostapd_config_read_maclist(accept_mac_file, &conf->accept_mac,
					&conf->num_accept_mac))
		errors++;
	free(accept_mac_file);
	if (hostapd_config_read_maclist(deny_mac_file, &conf->deny_mac,
					&conf->num_deny_mac))
		errors++;
	free(deny_mac_file);

	conf->auth_server = conf->auth_servers;
	conf->acct_server = conf->acct_servers;

	if (hostapd_config_check(conf))
		errors++;

	if (errors) {
		printf("%d errors found in configuration file '%s'\n",
		       errors, fname);
		hostapd_config_free(conf);
		conf = NULL;
	}

	return conf;
}


static void hostapd_config_free_radius(struct hostapd_radius_server *servers,
				       int num_servers)
{
	int i;

	for (i = 0; i < num_servers; i++) {
		free(servers[i].shared_secret);
	}
	free(servers);
}


void hostapd_config_free(struct hostapd_config *conf)
{
	if (conf == NULL)
		return;

	free(conf->dump_log_name);
	free(conf->eap_req_id_text);
	free(conf->accept_mac);
	free(conf->deny_mac);
	hostapd_config_free_radius(conf->auth_servers, conf->num_auth_servers);
	hostapd_config_free_radius(conf->acct_servers, conf->num_acct_servers);
	free(conf);
}


/* Perform a binary search for given MAC address from a pre-sorted list.
 * Returns 1 if address is in the list or 0 if not. */
int hostapd_maclist_found(macaddr *list, int num_entries, u8 *addr)
{
	int start, end, middle, res;

	start = 0;
	end = num_entries - 1;

	while (start <= end) {
		middle = (start + end) / 2;
		res = memcmp(list[middle], addr, ETH_ALEN);
		if (res == 0)
			return 1;
		if (res < 0)
			start = middle + 1;
		else
			end = middle - 1;
	}

	return 0;
}
