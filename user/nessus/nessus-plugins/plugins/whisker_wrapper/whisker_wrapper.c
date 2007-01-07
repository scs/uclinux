/*
 * whisker wrapper
 *
 * Finds bad CGI
 */

#include <includes.h>
#define WHISKER1 "whisker.pl"
#define WHISKER2 "whisker"	/* For OpenBSD ports and Whisker 2.1 */

/*
 *  Plugin functions
 */

#define EN_NAME "Whisker"
#define FR_NAME "Whisker"

#define EN_DESC "\
This plugin runs whisker(1) to find CGI.\n\
See the section 'plugins options' to configure it"

#define FR_DESC "\
Ce plugin appelle whisker(1) pour trouver les CGI.\n\
Allez voir la section 'plugins options' pour le configurer"


#define COPYRIGHT "This script is copyright (C) Michel Arboi - <arboi@algoriel.fr>"
/*Whisker is written by RainForestPuppy*/

#define EN_SUMMARY "Find CGI with whisker"
#define FR_SUMMARY "Trouve les CGI à l'aide de whisker"

#define EN_FAMILY "CGI abuses"
#define FR_FAMILY "Abus de CGI"


#define WHISKER_METHOD "Method:"
#define WHISKER_METHOD_DFL "\
1 HEAD method (default);\
2 GET method;\
3 GET method w/ byte-range"

#define WHISKER_DB	"script database: "
#define WHISKER_DB_DFL	""

#define WHISKER_ALT_DB_FMT	"Alternate database format: "
#define WHISKER_ALT_DB_FMT_DFL	"X standard;\
1 Voideye exp.dat;\
2 cgichk*.r (in rebol);\
3 cgichk.c/messala.c (not cgiexp.c)"

#define WHISKER_BRUTEF_U	"Brute force usernames via directories"
#define WHISKER_BRUTEF_U_DFL	"no"

#define WHISKER_PASS_FILE	"Password file: "
#define WHISKER_PASS_FILE_DFL	""


PlugExport int plugin_init(desc)
     struct arglist	*desc;
{
  if(! is_shell_command_present(WHISKER1) 
     && ! is_shell_command_present(WHISKER2))
    	return -1;
  plug_set_id(desc, 10845);
  plug_set_version(desc, "$Revision: 1.21 $");
   
  plug_set_name(desc, FR_NAME, "francais");
  plug_set_name(desc, EN_NAME, NULL);
 
  plug_set_summary(desc, FR_SUMMARY, "francais");
  plug_set_summary(desc, EN_SUMMARY, NULL);
 
  plug_set_description(desc, FR_DESC, "francais");
  plug_set_description(desc, EN_DESC, NULL);
 
  plug_set_copyright(desc, COPYRIGHT,NULL);
  plug_set_category(desc, ACT_GATHER_INFO);
  plug_set_family(desc, FR_FAMILY, "francais");
  plug_set_family(desc, EN_FAMILY, NULL);
  plug_set_dep(desc, "find_service.nes");
  plug_set_dep(desc, "httpver.nasl");
  plug_set_dep(desc, "logins.nasl");
  plug_set_dep(desc, "no404.nasl");
  plug_set_dep(desc, "libwhisker_settings.nasl");
  plug_require_port(desc, "Services/www");
  plug_require_port(desc, "80");
 
  /* plug_set_timeout(desc, -1); */
  add_plugin_preference(desc, WHISKER_METHOD, PREF_RADIO, WHISKER_METHOD_DFL);
  add_plugin_preference(desc, WHISKER_DB, PREF_FILE, WHISKER_DB_DFL);
  add_plugin_preference(desc, WHISKER_ALT_DB_FMT, PREF_RADIO, WHISKER_ALT_DB_FMT_DFL);
  add_plugin_preference(desc, WHISKER_BRUTEF_U, PREF_CHECKBOX, WHISKER_BRUTEF_U_DFL);
  add_plugin_preference(desc, WHISKER_PASS_FILE, PREF_FILE, WHISKER_PASS_FILE_DFL);
  return 0;
}


static pid_t	whisker_pid = -1;

static void	kill_whisker()
{
  if (whisker_pid == -1)
    return;
  if (kill (whisker_pid, SIGTERM) < 0 )
    return ;	     
  usleep(500);
  kill(whisker_pid, SIGKILL);
}

static void
term_handler(int s)
{
  kill_whisker();
  _exit(0);
}

static void
chld_handler(int s)
{
	int status = 0;
	wait(&status);
}

/* TBD:
 * Support Whisker 2.1
 * Detect Whisker version (including 1.4+SSL)
 */

PlugExport int plugin_run(desc)
     struct arglist	*desc;
{
  struct in_addr	*ip;
  FILE	*fp = NULL;
  char	*method = get_plugin_preference(desc, WHISKER_METHOD);
  char	*dir, *cmd;
  char	*db = get_plugin_preference(desc, WHISKER_DB);
  char	*altdbfmt = get_plugin_preference(desc, WHISKER_ALT_DB_FMT);
  char	**argv, s[256], *rep;
  char * p;
  char	*port_str = plug_get_key(desc, "Services/www");
  int	cnx_encaps, port, httpver = 10;
  char	*user = plug_get_key(desc, "http/login");
  char	*pass = plug_get_key(desc, "http/password");
  char	*bfu = get_plugin_preference(desc, WHISKER_BRUTEF_U);
  char	*passfile = get_plugin_preference(desc, WHISKER_PASS_FILE);
  char	*ids = plug_get_key(desc, "/Settings/Whisker/NIDS");


  signal(SIGTERM, term_handler);
  signal(SIGCHLD, chld_handler);

  cmd = WHISKER1;
  if ((dir = find_in_path(cmd, 1)) == NULL)
    {
      cmd = WHISKER2;
      dir = find_in_path(cmd, 1);
    }

  if (port_str != NULL)
    port = atoi(port_str);
  else
    port = 80;

  /* Whisker will generate many false positives if the web server is broken */
  snprintf(s, sizeof(s), "www/no404/%d", port);
  p = plug_get_key(desc, s);
  if (p != NULL)
    {
      /* Skip white spaces just in case */
      while (isspace(*p))
	p ++;
      if (*p != '\0')
	return 0;
    }

  cnx_encaps =  plug_get_port_transport(desc, port);

  snprintf(s, sizeof(s), "http/%d", port);
  if ((p = plug_get_key(desc, s)) != NULL && *p != '\0')
    httpver = atoi(p);
  
  if (dir != NULL && dir[0] != '\0')
    /* chdir is needed by option -U */
    if (chdir(dir) < 0)
      perror(dir);		/* If "." is in $PATH, you lose! */
  /* Do not prepend dir to command, that would be _really_ insecure! */

  argv = append_argv(0, cmd);

  if (IS_ENCAPS_SSL(cnx_encaps))
    {
      /* SSL not supported yet by whisker without patch */

      fp = nessus_popen(cmd, (const char**)argv, &whisker_pid);
      while ((p = fgets(s, sizeof(s) - 1, fp)) != NULL)
	if (strstr(s, "-x") != NULL && strstr(s, "use SSL") != NULL)
	  break;

      if (p == NULL)		/* SSL not supported! */
	{
	  destroy_argv (argv);
	  return 0;
	}
      argv = append_argv(argv, "-x");
    }

  
  if (httpver > 10)
    {
      argv = append_argv(argv, "-V");
      p = (char*)plug_get_host_fqdn(desc);
    }
  else
    p = NULL;
  if (p == NULL || *p == '\0')
    {
      ip = plug_get_host_ip(desc);
      p = inet_ntoa(*ip);
    }
  argv = append_argv(argv, "-h");
  argv = append_argv(argv, p);

  snprintf(s, sizeof(s), "%d", port);
  argv = append_argv(argv, "-p");
  argv = append_argv(argv, s);
  s[0] = method[0]; s[1] = '\0';
  argv = append_argv(argv, "-M");
  argv = append_argv(argv, s);
  if (ids != NULL && *ids != 'X')
    {
      s[0] = ids[0]; s[1] = '\0';
      argv = append_argv(argv, "-I");
      argv = append_argv(argv, s);
    }
  if (db != NULL && *db != '\0')
    {
      char	*local = (char*)get_plugin_preference_fname(desc, db);
      if (local != NULL)
	{
	  argv = append_argv(argv, "-s");
	  argv = append_argv(argv, local);
	}
    }
  if (*altdbfmt != 'X')
    {
      s[0] = altdbfmt[0]; s[1] = '\0';
      argv = append_argv(argv, "-A");
      argv = append_argv(argv, s);
    }
  if (user != NULL && *user != '\0')
    {
      if (pass != NULL && *pass !='\0')
	snprintf(s, sizeof(s), "%s:%s", user, pass);
      else 
        {
	strncpy(s, user, sizeof(s) - 1);
	s[sizeof(s) - 1] = '\0';
	}
      argv = append_argv(argv, "-a");
      argv = append_argv(argv, s);
    }

  if (bfu != NULL && strcmp(bfu, "yes") == 0)
    argv = append_argv(argv, "-U");
  if (passfile != NULL && *passfile != '\0')
    {
      char	*local = (char*)get_plugin_preference_fname(desc, db);
      if (local != NULL)
	{
	  argv = append_argv(argv, "-P");
	  argv = append_argv(argv, local);
	}
    }

  fp = nessus_popen(cmd, (const char**)argv, &whisker_pid);
  destroy_argv (argv);

  if (fp == NULL)
    {
      fprintf(stderr, "nessus_popen(%s) failed\n", cmd);
      return 0;
    }

  /* read output */

  while ((p = fgets(s, sizeof(s) - 1, fp)) != NULL)
    {
#if 0
      fprintf(stderr, "> %s", s);
#endif
#define SRV	"= Server: "
      if (strncmp(s, SRV, sizeof(SRV)-1) == 0)
	{
	  rep = emalloc(128 + strlen(p));
	  snprintf(rep, 128 + strlen(p), "Whisker has found the HTTP server to be:\n%s", 
		  s + sizeof(SRV)-1);
	  post_note(desc, port, rep);
	  efree(&rep);
	}
#define OK200	"+ 200 OK: "
      else if (strncmp(s, OK200, sizeof(OK200)-1) == 0)
	{
	  p = strchr(s + sizeof(OK200) - 1, ' ');
	  if (p != NULL)
	    {
	      p ++;
	      rep = emalloc(80 + strlen(p));
	      snprintf(rep, 80 + strlen(p), "Whisker could access: %s", p);
	      post_info(desc, port, rep);
	      efree(&rep);
	    }
	}
#define KO403	"+ 403 Forbidden: "
      else if (strncmp(s, KO403, sizeof(KO403)-1) == 0)
	{
	  p = strchr(s + sizeof(KO403) - 1, ' ');
	  if (p != NULL)
	    {
	      p ++;
	      rep = emalloc(80 + strlen(p));
	      snprintf(rep, 80 + strlen(p), "Whisker detected but could not access: %s", p);
	      post_note(desc, port, rep);
	      efree(&rep);
	    }
	}
      /* else cannot parse input */
    }
  
  fclose(fp);
  kill_whisker();

  return 0;
}


