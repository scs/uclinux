/*
 * ftp writeable dirs
 *
 * This plugin explores a FTP server and searches for 
 * world writeable directories
 *
 * This plugin was written by Alexis de Bernis <alexis@nessus.org>,
 * based on the work of Renaud Deraison and is distributed
 * under the GPL
 */
 
#include <includes.h>


/* Globals */
static char **writable_dirs = NULL;
static unsigned int num_found = 0;


/* Functions declarations */
PlugExport int plugin_init(struct arglist *);
PlugExport int plugin_run(struct arglist *);
void check_directory(struct arglist *, char *, unsigned int, int);
void add_writable_directory(char *);

/* plug-in description */
#define EN_NAME "ftp writeable directories"
#define FR_NAME "Répertoires ftp sur lequel on peut ecrire"
 
#define EN_DESC "\
It is usually a bad idea to have world writeable\n\
directories in a public FTP server, since it may\n\
allow anyone to use the FTP server as a 'warez'\n\
server (this means that the FTP server will be\n\
used to exchange non-free software between\n\
software pirates). It may also allow anyone to\n\
make a denial of service by filling up the FTP\n\
server filesystem\n\n\
Risk factor : Medium"

#define FR_DESC "\
C'est generalement une mauvaise idée que d'avoir\n\
des répertoires en écriture libre sur un serveur FTP\n\
puisque cela permet à n'importe qui de le transformer\n\
en serveur de 'warez' (permettant l'echange de logiciels\n\
payants). Cela peut aussi permettre à n'importe qui de\n\
créer un déni de service en remplissant le disque dur\n\
du serveur FTP.\n\
Facteur de risque : moyen"


#define COPYRIGHT "this plugin is distributed under the GPL"
#define SUMMARY "checks if the remote FTP server has any world writeable dirs"
#define FR_SUMM "vérifie si le serveur FTP distant contient des repertoires writeable"

#define OPTION "How to check if directories are writeable : "
#define OPT1 "Trust the permissions (drwxrwx---)"
#define OPT2 "Attempt to store a file"

#define OPTALL OPT1";"OPT2

#define MOD_WRITE 1
#define MOD_CHK_PERM 2
#define CHECKFILE_NAME "nessus_check"

static int connection_encaps;


/* functions implementation */

/*
 * Initialize the descriptions
 */
PlugExport int plugin_init(struct arglist * desc)
{
	plug_set_id(desc, 10332);
	plug_set_version(desc, "$Revision: 1.19 $");
	plug_set_cve_id(desc, "CAN-1999-0527");
 
	plug_set_name(desc, FR_NAME, "francais");
	plug_set_name(desc, EN_NAME, NULL);
  
	plug_set_description(desc, FR_DESC, "francais");
	plug_set_description(desc, EN_DESC, NULL);
  
	plug_set_summary(desc, FR_SUMM, "francais");
	plug_set_summary(desc, SUMMARY, NULL);
	plug_set_copyright(desc, COPYRIGHT, NULL);
	plug_set_category(desc, ACT_ATTACK);
	plug_set_family(desc, "FTP",NULL);
	add_plugin_preference(desc, OPTION, PREF_RADIO, OPTALL);
	plug_set_dep(desc, "find_service.nes");
	plug_set_dep(desc, "ftp_anonymous.nasl");
	plug_require_port(desc, "Services/ftp");
	plug_require_port(desc, "21");
	return(0);
}


/*
 * The plugin starts here
 */
PlugExport int plugin_run(struct arglist * env)
{	
	int soc;
	char *asc_port =  plug_get_key(env, "Services/ftp");
	int port;
	unsigned int test_mode = MOD_CHK_PERM;
	char *option;
	if(asc_port)
		port = atoi(asc_port);
	else
		port = 21;

	connection_encaps = plug_get_port_transport(env, port);
	
	if(!plug_get_key(env, "ftp/anonymous"))
		return(0);
	if(host_get_port_state(env, port) <= 0)
		return(0);
	if((soc = open_stream_connection(env, port, connection_encaps, 10)) < 0)
		return(0);
	if(ftp_log_in(soc, "anonymous", "nessus@nessus.org"))
		return(0);

	option = (char *) get_plugin_preference(env, OPTION);
	if(option && !strcmp(option, OPT2))
		test_mode = MOD_WRITE;

	/* Launch the recursive test */
	check_directory(env, "/", test_mode, soc);
	
	/* Analyze the results */
	if(num_found > 0) {
		char *result;
		char *report;
		unsigned int result_len = 1;
		unsigned int i;

		plug_set_key(env, "ftp/writeable_dir", ARG_STRING, writable_dirs[0]);

		for(i = 0; i < num_found; i++) {
			result_len += 1 + strlen(writable_dirs[i]) + 1;
		}
		result = emalloc(result_len);
		for(i = 0; i < num_found; i++) {
			result = strcat(result, "\t");
			result = strcat(result, writable_dirs[i]);
			result = strcat(result, "\n");
			efree(&writable_dirs[i]);
		}
		
		report = emalloc(255 + strlen(result));
		sprintf(report, "\
The following directories are world-writeable. You should\n\
correct this problem quickly\n%s\nRisk factor : Medium\n", result);
		post_hole(env, port, report);
		efree(&report);
		efree(&result);
	}
    close_stream_connection(soc);
	return 0;
}


/*
 * Recursive function. It analyzes the given directory
 * then is launched against the subdirectories
 */
void check_directory(struct arglist * env, char *abs_name, unsigned int test_mode, int soc)
{
	int data_soc;
	unsigned int i;
	struct sockaddr_in addr;
	char *command;
	char line[4096];
	char **subdirs = NULL;
	unsigned int subdirs_num = 0;
#if 0
	printf("CHECKING '%s'\n", abs_name);fflush(stdout);
#endif	
	/* initiate PASV mode */
	if(ftp_get_pasv_address(soc, &addr))
		return;

	if ((data_soc = open_stream_connection(env, ntohs(addr.sin_port), connection_encaps, 10)) < 0)
	  return;


	if(test_mode == MOD_WRITE) {
		int code;	
		command = emalloc(8 + strlen(abs_name) + strlen(CHECKFILE_NAME));
		sprintf(command, "STOR %s%s\r\n", abs_name, CHECKFILE_NAME);
		write_stream_connection(soc, command, strlen(command));
		bzero(command, strlen(command));
		command = realloc(command, 8192);
		bzero(command, 8192);
		read_stream_connection(soc, command, 8191);
		command[3] = '\0';
		code = atoi(command);
		if(code == 425 || code == 150) {
			add_writable_directory(abs_name);
			command = realloc(command, 8 + strlen(abs_name) + strlen(CHECKFILE_NAME));
			write_stream_connection(data_soc, "nessus", 6);
			close_stream_connection(data_soc);
			sprintf(command, "DELE %s%s\r\n", abs_name, CHECKFILE_NAME);
			write_stream_connection(soc, command, strlen(command));
			command = realloc(command, 8192);
			bzero(command, 8192);
			read_stream_connection(soc, command, 8191);
			if(ftp_get_pasv_address(soc, &addr))
				return;
			data_soc = open_stream_connection(env, ntohs(addr.sin_port), connection_encaps, 10);
		}
		efree(&command);
	}


	/* Get directory content */
	command = emalloc(5 + strlen(abs_name) + 3);
	sprintf(command, "LIST %s\r\n", abs_name);
	write_stream_connection(soc, command, strlen(command));
	efree(&command);


	/*
	 * Get a list of the subdirectories
	 */
	for(;;) {
		char *new_name = NULL;
		char *rel_name;
		bzero(line, sizeof(line));
		recv_line(data_soc, line, sizeof(line) - 1);
		if(strlen(line) == 0)
			break;

		line[strlen(line) - 2] = '\0';  /* kill the '\r\n' */

		if(line[0] != 'd')
			continue;
			
		
		rel_name = strrchr(line, ' ');
		if(rel_name)
			rel_name++;
		else
			continue;                   /* No space found */
		

		if(!strcmp(rel_name, ".") || !strcmp(rel_name, ".."))
			continue;
		
		/* Go on to the new directory */
		new_name = emalloc(strlen(abs_name) + strlen(rel_name) + 2);
		sprintf(new_name, "%s%s/", abs_name, rel_name);

		if(test_mode == MOD_CHK_PERM && line[8] == 'w')
			add_writable_directory(new_name);

		/* Add it to the queue if browsable */
		if(line[9] == 'x') {
			subdirs = realloc(subdirs, (subdirs_num + 1) * sizeof(char *));
			subdirs[subdirs_num] = new_name;
			subdirs_num++;
		} else {
			efree(&new_name);
		}
	}

	/* Free the input buffer (two ACK lines) */
	close_stream_connection(data_soc);
	recv_line(soc, line, sizeof(line) - 1);
	recv_line(soc, line, sizeof(line) - 1);
	

	/*
	 * Then analyze them
	 */
	for(i = 0; i < subdirs_num; i++) {
		check_directory(env, subdirs[i], test_mode, soc);
		efree(&(subdirs[i]));
	}
	efree(&subdirs);
}


/*
 * Just add a name to the list
 */
void add_writable_directory(char *name)
{
	writable_dirs = realloc(writable_dirs, (num_found + 1) * sizeof(char *));
	writable_dirs[num_found] = emalloc(strlen(name) + 1);
	strcpy(writable_dirs[num_found], name);
	num_found++;
}
