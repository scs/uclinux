/*
 * nikto wrapper
 *
 * Finds bad CGI
 */

#include <includes.h>
#define NIKTO "nikto.pl"

/*
 *  Plugin functions
 */

#define EN_NAME "Nikto"
#define FR_NAME "Nikto"

#define EN_DESC "\
This plugin runs nikto(1) to find CGI.\n\
See the section 'plugins options' to configure it"

#define FR_DESC "\
Ce plugin appelle nikto(1) pour trouver les CGI.\n\
Allez voir la section 'plugins options' pour le configurer"


#define COPYRIGHT "This script is copyright (C) Michel Arboi - <arboi@algoriel.fr>"
/*Nikto is based upon whisker, by RainForestPuppy*/

#define EN_SUMMARY "Find CGI with nikto"
#define FR_SUMMARY "Trouve les CGI à l'aide de nikto"

#define EN_FAMILY "CGI abuses"
#define FR_FAMILY "Abus de CGI"


#define NIKTO_ALLCGI	"Force scan all possible CGI directories"
#define NIKTO_GENERIC	"Force full (generic) scan"

PlugExport int plugin_init(desc)
     struct arglist	*desc;
{
  if(!is_shell_command_present(NIKTO))
    	return -1;
  plug_set_id(desc, 10864);
  plug_set_version(desc, "$Revision: 1.25 $");
   
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
  plug_require_port(desc, "443");
 
  plug_set_timeout(desc, -1);	/* Is this wise? */
  add_plugin_preference(desc, NIKTO_ALLCGI, PREF_CHECKBOX, "no");
  add_plugin_preference(desc, NIKTO_GENERIC, PREF_CHECKBOX, "no");
  return 0;
}

static pid_t	nikto_pid = -1;

static void	kill_nikto()
{
  if (nikto_pid == -1)
    return;
  if (kill (nikto_pid, SIGTERM) == -1)
    return ;	     
  usleep(500);
  kill(nikto_pid, SIGKILL);
}

static void
term_handler(int s)
{
  kill_nikto();
  _exit(0);
}

static void
chld_handler(int s)
{
 int status = 0;
 wait(&status);
}

PlugExport int plugin_run(desc)
     struct arglist	*desc;
{
  struct in_addr	*ip;
  FILE	*fp = NULL;
  char	*allcgi = get_plugin_preference(desc, NIKTO_ALLCGI);
  char	*gener = get_plugin_preference(desc, NIKTO_GENERIC);
  char	**argv, s[256], *p, *rep, *repp;
  char	*port_str = plug_get_key(desc, "Services/www");
  int	cnx_encaps, port, flag, httpver = 0;
  char	*user = plug_get_key(desc, "http/login");
  char	*pass = plug_get_key(desc, "http/password");
  char	*ids = plug_get_key(desc, "/Settings/Whisker/NIDS");


  signal(SIGTERM, term_handler);
  signal(SIGCHLD, chld_handler);
#ifdef HAVE_ATEXIT
  atexit(kill_nikto);
#endif  

  if (port_str != NULL)
    port = atoi(port_str);
  else
    port = 80;

  if(host_get_port_state(desc, port) == 0)
    return 0;

  /* Nikto will generate many false positives if the web server is broken */
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

  argv = append_argv(0, NIKTO);

  snprintf(s, sizeof(s), "http/%d", port);
  if ((p = plug_get_key(desc, s)) != NULL && *p != '\0')
    httpver = atoi(p);
  
  if (httpver > 10)
    {
      p = (char*)plug_get_host_fqdn(desc);
      if (p != NULL && *p != '\0')
	{
	  argv = append_argv(argv, "-vhost");
	  argv = append_argv(argv, p);
	}
    }

  ip = plug_get_host_ip(desc);
  p = inet_ntoa(*ip);
  argv = append_argv(argv, "-h");
  argv = append_argv(argv, p);

  snprintf(s, sizeof(s), "%d", port);
  argv = append_argv(argv, "-p");
  argv = append_argv(argv, s);

  if (IS_ENCAPS_SSL(cnx_encaps))
    argv = append_argv(argv, "-ssl");
  
  if (strcmp(allcgi, "yes") == 0)
    argv = append_argv(argv, "-allcgi");
  if (strcmp(gener, "yes") == 0)
    argv = append_argv(argv, "-gener");

  if (ids != NULL && *ids != 'X')
    {
      s[0] = ids[0]; s[1] = '\0';
      argv = append_argv(argv, "-evasion");
      argv = append_argv(argv, s);
    }

  if (user != NULL && *user != '\0')
    {
      if (pass != NULL && *pass !='\0')
	snprintf(s, sizeof(s), "%s:%s", user, pass);
      else
       {
	strncpy(s, user, sizeof(s) - 1);
	s[sizeof(s) - 1 ] = '\0';
       }
      argv = append_argv(argv, "-id");
      argv = append_argv(argv, s);
    }

  /* 
   * If we cannot find the nikto directory or enter it, 
   * expect problems!
   */
  if ((p = find_in_path(NIKTO, 1)) != NULL && *p != '\0')
    {
      if (chdir(p) < 0)
	perror(p);
    }
  else
    fprintf(stderr, "Could not find %s in $PATH\n", NIKTO);

  fp = nessus_popen(NIKTO, (const char**)argv, &nikto_pid);
  destroy_argv (argv);

  if (fp == NULL)
    {
      fprintf(stderr, "nessus_popen(%s) failed\n", NIKTO);
      return 0;
    }

  /* read output */

  rep = emalloc(80);
  strcpy(rep, "Here is the nikto report:\n");
  for (repp = rep; *repp != '\0'; repp++)
    ;

  flag = 0;
  for (;;)
    {
      errno = 0;
      p = fgets(s, sizeof(s) - 1, fp);
      if (p == NULL)
	{
	  if (feof(fp) != 0 )
	    fprintf(stderr, "fgets: EOF\n");
	  else
	  perror("fgets");
	break;
	}
#if DEBUG
      fprintf(stderr, "> %s", s);
#endif
#if 1
      /* This code filters Nikto output: otherwise, on (old) SuSE systems, 
       * Nikto report is intermixed with debug traces from other plugins */
      for (p = s; *p == ' ' || *p == '\t'; p ++)
	;
      if (*p != '+' && *p != '-' && strncmp(s, "ERROR", 5) != 0)
	continue;
#endif

      rep = (char*)erealloc(rep, strlen(rep) + strlen(p) + 1);
      /* rep may have changed */
      for (repp = rep; *repp != '\0'; repp++)
	;
      strcpy(repp, p);
      flag = 1;
    }
  if (flag)
    post_note(desc, port, rep);
  efree(&rep);

  fclose(fp);
  kill_nikto();

  return 0;
}


