/*
 * Find service
 *
 * This plugin is released under the GPL
 */
#define DETECT_WRAPPED_SVC
#define SMART_TCP_RW
#undef PRINT_UNKOWN_SVC_BANNER

#include <includes.h>

#define EN_NAME "Services"
#define FR_NAME "Services"

#define EN_FAMILY "Misc."
#define FR_FAMILY "Divers"

#define EN_DESC "This plugin attempts to guess which\n\
service is running on the remote ports. For instance,\n\
it searches for a web server which could listen on\n\
another port than 80 and set the results in the plugins\n\
knowledge base.\n\n\
Risk factor : None"

#define FR_DESC "Ce plugin tente de deviner quels\n\
services tournent sur quels ports.\n\
Par exemple, il cherche si un serveur\n\
web tourne sur un port autre que le 80\n\
et il stocke ses résultats dans la\n\
base de connaissance des plugins.\n\n\
Facteur de risque : Aucun"

#define EN_COPY "Written by Renaud Deraison <deraison@cvs.nessus.org>"
#define FR_COPY "Ecrit par Renaud Deraison <deraison@cvs.nessus.org>"

#define EN_SUMM "Find what is listening on which port"
#define FR_SUMM "Détermine ce qui écoute sur quel port"


#ifdef HAVE_SSL
#define CERT_FILE "SSL certificate : "
#define KEY_FILE  "SSL private key : "
#define PEM_PASS "PEM password : "
#define CA_FILE	"CA file : "
#endif
#define CNX_TIMEOUT_PREF	"Network connection timeout : "
#define RW_TIMEOUT_PREF		"Network read/write timeout : "
#ifdef DETECT_WRAPPED_SVC
#define WRAP_TIMEOUT_PREF	"Wrapped service read timeout : "
#endif


#define NUM_CHILDREN		"Number of connections done in parallel : "
#define NUM_CHILDREN_DEFAULT 	"5"
/*
 * XXX
 * This plugin is highly beta and NOT complete
 *
 */

int plugin_init(desc)
 struct arglist * desc;
{ 
 plug_set_id(desc, 10330);
 plug_set_version(desc, "$Revision: 1.192 $");
 
 plug_set_name(desc, FR_NAME, "francais");
 plug_set_name(desc, EN_NAME, NULL);
 
 
 plug_set_category(desc, ACT_GATHER_INFO);
 
 
 plug_set_family(desc, FR_FAMILY, "francais");
 plug_set_family(desc, EN_FAMILY, NULL);
 
 plug_set_description(desc, FR_DESC, "francais");
 plug_set_description(desc, EN_DESC, NULL);
 
 plug_set_summary(desc, FR_SUMM, "francais");
 plug_set_summary(desc, EN_SUMM,NULL);
 
 plug_set_copyright(desc, FR_COPY, "francais");
 plug_set_copyright(desc, EN_COPY, NULL);
 add_plugin_preference(desc, NUM_CHILDREN, PREF_ENTRY, NUM_CHILDREN_DEFAULT);
 add_plugin_preference(desc, CNX_TIMEOUT_PREF, PREF_ENTRY, "5");
 add_plugin_preference(desc, RW_TIMEOUT_PREF, PREF_ENTRY, "5");
#ifdef DETECT_WRAPPED_SVC
 add_plugin_preference(desc, WRAP_TIMEOUT_PREF, PREF_ENTRY, "2");
#endif 

#ifdef HAVE_SSL
 add_plugin_preference(desc, CERT_FILE, PREF_FILE, "");
 add_plugin_preference(desc, KEY_FILE, PREF_FILE, "");
 add_plugin_preference(desc, PEM_PASS, PREF_PASSWORD, "");
 add_plugin_preference(desc, CA_FILE, PREF_FILE, "");

#define TEST_SSL_PREF	"Test SSL based services"
 add_plugin_preference(desc, TEST_SSL_PREF, PREF_RADIO, "All;Known SSL ports;None");
#endif
 plug_set_timeout(desc, PLUGIN_TIMEOUT*4);
 return(0);
}




static void
register_service(desc, port, proto)
     struct arglist	*desc;
     int		port;
     const char		*proto;
{
  char	k[96];
  int	l;

#ifdef DEBUG
  if (port < 0 || proto == NULL ||
      (l = strlen(proto)) == 0 || l > sizeof(k) - 10)
    {
      fprintf(stderr, "register_service: invalid value - port=%d, proto=%s\n",
	      port, proto == NULL ? "(null)" : proto);
      return;
    }
#endif
  /* Old "magical" key set */
  snprintf(k, sizeof(k), "Services/%s", proto);
  plug_set_key(desc, k, ARG_INT, (void *)port);

  /* 2002-08-24 - MA - My new key set 
   * There is a problem: if register_service is called twice for a port,
   * e.g. first with HTTP and then with SWAT, the plug_get_key function
   * will fork. This would not happen if we registered a boolean (i.e. "known")
   * instead of the name of the protocol.
   * However, we *need* this name for some scripts.
   * We'll just have to keep in mind that a fork is possible...
   */
  snprintf(k, sizeof(k), "Known/tcp/%d", port);
  plug_set_key(desc, k, ARG_STRING, (char*)proto);
}

void mark_chargen_server(desc, port)
 struct arglist * desc;
 int port;
{
 register_service(desc, port, "chargen");
 post_note(desc, port, "Chargen is running on this port");
}

void mark_echo_server(desc, port)
 struct arglist * desc;
 int port;
{
 register_service(desc, port, "echo");
 post_note(desc, port, "An echo server is running on this port");
}

void mark_ncacn_http_server(desc, port, buffer)
 struct arglist * desc;
 int port;
 char * buffer;
{
 char ban[256];
 if(port==593)
 {
  register_service(desc, port, "http-rpc-epmap");
  snprintf(ban, sizeof(ban), "http-rpc-epmap/banner/%d", port);
  plug_set_key(desc, ban, ARG_STRING, buffer);
 }
 else
 {
  register_service(desc, port, "ncacn_http");
  snprintf(ban, sizeof(ban), "ncacn_http/banner/%d", port);
  plug_set_key(desc, ban, ARG_STRING, buffer);
 }
}

void mark_vnc_server(desc, port, buffer)
 struct arglist * desc;
 int port;
 char * buffer;
{
 char ban[512];
 register_service(desc, port, "vnc");
 snprintf(ban, sizeof(ban), "vnc/banner/%d", port);
 plug_set_key(desc, ban, ARG_STRING, buffer);
}

void mark_nntp_server(desc, port, buffer, trp)
 struct arglist * desc;
 int port, trp;
 char * buffer;
{
 char ban[512];
 register_service(desc, port, "nntp");
 snprintf(ban, sizeof(ban), "nntp/banner/%d", port);
 plug_set_key(desc, ban, ARG_STRING, buffer);
 snprintf(ban, sizeof(ban), "An NNTP server is running on this port%s",
	     get_encaps_through(trp));
 post_note(desc, port, ban);
}


void mark_swat_server(desc, port, buffer)
struct arglist * desc;
 int port;
 char * buffer;
{
 register_service(desc, port, "swat");
}

void mark_vqserver(desc, port, buffer)
struct arglist * desc;
 int port;
 char * buffer;
{
 register_service(desc, port, "vqServer-admin");
}


void mark_mldonkey(desc, port, buffer)
struct arglist * desc;
 int port;
 char * buffer;
{
 char ban[512];
 register_service(desc, port, "mldonkey");
 snprintf(ban, sizeof(ban), "A mldonkey server is running on this port");
 post_note(desc, port, ban);
}



void mark_http_server(desc, port, buffer, trp)
 struct arglist * desc;
 int port, trp;
 char * buffer;
{
   char ban[512];
   register_service(desc, port, "www");
   snprintf(ban, sizeof(ban), "www/banner/%d", port);
   plug_set_key(desc, ban, ARG_STRING, buffer);
   snprintf(ban, sizeof(ban), "A web server is running on this port%s",
	       get_encaps_through(trp));
   post_note(desc, port, ban);
}


void mark_locked_adsubtract_server(desc, port, buffer, trp)
 struct arglist * desc;
 int port, trp;
 char * buffer;
{
   char ban[512];
   register_service(desc, port, "AdSubtract");
   snprintf(ban, sizeof(ban), "AdSubtract/banner/%d", port);
   plug_set_key(desc, ban, ARG_STRING, buffer);
   snprintf(ban, sizeof(ban), "A (locked) AdSubtract server is running on this port%s",
	       get_encaps_through(trp));
   post_note(desc, port, ban);
}

static void 
mark_gopher_server(struct arglist* desc, int port)
{
 register_service(desc, port, "gopher");
 post_note(desc, port, "A gopher server is running on this port");
}

#if 0
static void
mark_gnutella_servent(desc, port, buffer, trp)
     struct arglist	*desc;
     int		port, trp;
     char		*buffer;
{
  char	ban[256];

  register_service(desc, port, "gnutella");
  snprintf(ban, sizeof(ban), "www/banner/%d", port);
  plug_set_key(desc, ban, ARG_STRING, buffer);
  snprintf(ban, sizeof(ban), "A Gnutella servent is running on this port%s",
	  get_encaps_through(trp));
  post_note(desc, port, ban);
}
#endif

void mark_rmserver(desc, port, buffer, trp)
 struct arglist * desc;
 int port, trp;
 char * buffer;
{
   char ban[512];
   register_service(desc, port, "realserver");
   snprintf(ban, sizeof(ban), "realserver/banner/%d", port);
   plug_set_key(desc, ban, ARG_STRING, buffer);
    
   snprintf(ban, sizeof(ban), "A RealMedia server is running on this port%s",
	     get_encaps_through(trp));
   post_note(desc, port, ban);
}

void mark_smtp_server(desc, port, buffer, trp)
 struct arglist * desc;
 int port, trp;
 char * buffer;
{
 char ban[512];
 register_service(desc, port, "smtp");
 snprintf(ban, sizeof(ban), "smtp/banner/%d", port);
 plug_set_key(desc, ban, ARG_STRING, buffer);

 if(strstr(buffer, " postfix"))
 	plug_set_key(desc, "smtp/postfix", ARG_INT,(void*) 1);
 
 {
  char * report = emalloc(255 + strlen(buffer));
  char *t = strchr(buffer, '\n');
  if(t)t[0]=0;
  snprintf(report, 255 + strlen(buffer), "An SMTP server is running on this port%s\n\
Here is its banner : \n%s",
	  get_encaps_through(trp), buffer);
   post_note(desc, port, report);
   efree(&report);
 }
}

void 
mark_snpp_server(desc, port, buffer, trp)
 struct arglist * desc;
 int port, trp;
 char * buffer;
{
  char	ban[512], *report, *t;
  register_service(desc, port, "snpp");
  snprintf(ban, sizeof(ban), "snpp/banner/%d", port);
  plug_set_key(desc, ban, ARG_STRING, buffer);

  report = emalloc(255 + strlen(buffer));
  t = strchr(buffer, '\n');
  if (t != NULL) *t = '\0';
  snprintf(report, 255 + strlen(buffer), 
	   "An SNPP server is running on this port%s\n\
Here is its banner : \n%s",
	     get_encaps_through(trp), buffer);
    post_note(desc, port, report);
    efree(&report);
}

void mark_ftp_server(desc, port, buffer, trp)
 struct arglist * desc;
 int port, trp;
 char * buffer;
{
 register_service(desc, port, "ftp");
 
 if(buffer != NULL)
 {
  char ban[255];
  
  snprintf(ban, sizeof(ban), "ftp/banner/%d", port);
  plug_set_key(desc, ban, ARG_STRING, buffer);
 }

 if(buffer != NULL)
 {
  char * report = emalloc(255 + strlen(buffer));
  char *t = strchr(buffer, '\n');
  if(t != NULL )
  	t[0]= '\0';
  snprintf(report, 255 + strlen(buffer), "An FTP server is running on this port%s.\n\
Here is its banner : \n%s",
	  get_encaps_through(trp), buffer);
   post_note(desc, port, report);
   efree(&report);
 }
 else
 {
  char report[255];
  snprintf(report, sizeof(report), "An FTP server is running on this port%s.",
  	get_encaps_through(trp));
  post_note(desc, port, report);
 }
}

void
mark_ssh_server(desc, port, buffer, trp)
 struct arglist * desc;
 int port;
 char * buffer;
 int trp;
{
 char ban[512];
 register_service(desc, port, "ssh");
 while((buffer[strlen(buffer)-1]=='\n')||
       (buffer[strlen(buffer)-1]=='\r'))buffer[strlen(buffer)-1]='\0';
 snprintf(ban, sizeof(ban), "ssh/banner/%d", port);
 plug_set_key(desc, ban, ARG_STRING, buffer);
 post_note(desc, port, "An ssh server is running on this port");
}

void
mark_http_proxy(desc, port, buffer, trp)
 struct arglist * desc;
 int port, trp;
 char * buffer;
{
 char ban[512];
 /* the banner is in www/banner/port */
 register_service(desc, port, "http_proxy");
 snprintf(ban, sizeof(ban), "An HTTP proxy is running on this port%s",
	 get_encaps_through(trp));
 post_note(desc, port, ban);
}

void
mark_pop_server(desc, port, buffer)
 struct arglist * desc;
 int port;
 char * buffer;
{
 char * c = strchr(buffer, '\n');
 char ban[512];
 char * buffer2;
 int i;
 if(c)c[0]=0;
 buffer2 = estrdup(buffer);
 for(i=0;i<strlen(buffer2);i++)buffer2[i] = tolower(buffer2[i]);    
 if(!strcmp(buffer2, "+ok"))
  {
  register_service(desc, port, "pop1");
  snprintf(ban, sizeof(ban), "pop1/banner/%d", port);
  plug_set_key(desc, ban, ARG_STRING, buffer);
  }
  else if(strstr(buffer2, "pop2"))
   {
   register_service(desc, port, "pop2");
   snprintf(ban, sizeof(ban), "pop2/banner/%d", port);
   plug_set_key(desc, ban, ARG_STRING, buffer);
   post_note(desc, port, "a pop2 server is running on this port");
   }
   else
    {
    register_service(desc, port, "pop3");
    snprintf(ban, sizeof(ban), "pop3/banner/%d", port);
    plug_set_key(desc, ban, ARG_STRING, buffer);
    post_note(desc, port, "A pop3 server is running on this port");
    }
   efree(&buffer2); 
}

void
mark_imap_server(desc, port, buffer, trp)
 struct arglist * desc;
 int port, trp;
 char * buffer;
{
 char ban[512];
 register_service(desc, port, "imap");
 snprintf(ban, sizeof(ban), "imap/banner/%d", port);
 plug_set_key(desc, ban, ARG_STRING, buffer);
   {
     snprintf(ban, sizeof(ban), "An IMAP server is running on this port%s",
	     get_encaps_through(trp));
	     post_note(desc, port, ban);
   }
}

void
mark_auth_server(desc, port, buffer)
 struct arglist * desc;
 int port;
 char * buffer;
{
 register_service(desc, port, "auth");
 post_note(desc, port, "An identd server is running on this port");
}


/* 
 * Postgres, MySQL & CVS pserver detection by 
 * Vincent Renardias <vincent@strongholdnet.com>
 */
void
mark_postgresql(desc, port, buffer)
 struct arglist * desc;
 int port;
 char * buffer;
{
  register_service(desc, port, "postgresql");
  /* if (port != 5432)*/
  post_note(desc, port, "A PostgreSQL server is running on this port");
}

void
mark_mysql(desc, port, buffer)
 struct arglist * desc;
 int port;
 char * buffer;
{
 register_service(desc, port, "mysql");
 /*if (port != 3306)*/
 post_note(desc, port, "A MySQL server is running on this port");
}

void
mark_cvspserver(desc, port, buffer, trp)
        struct arglist * desc;
        int port;
        char * buffer;
	int trp;
{
  register_service(desc, port, "cvspserver");
  /* if (port != 2401) */
  post_info(desc, port, "A CVS pserver server is running on this port");
}


void
mark_cvsupserver(desc, port, buffer, trp)
        struct arglist * desc;
        int port;
        char * buffer;
	int trp;
{
  register_service(desc, port, "cvsup");
  post_info(desc, port, "A CVSup server is running on this port");
}


void
mark_cvslockserver(desc, port, buffer, trp)
        struct arglist * desc;
        int port;
        char * buffer;
	int trp;
{
  register_service(desc, port, "cvslockserver");
  /* if (port != 2401) */
  post_info(desc, port, "A CVSLock server server is running on this port");
}

void
mark_rsyncd(desc, port, buffer, trp)
	struct arglist * desc;
	int port;
	char * buffer;
	int trp;
{
 register_service(desc, port, "rsyncd");
 post_info(desc, port, "An rsync server is running on this port");
}


void
mark_wild_shell(desc, port, buffer, trp)
 struct arglist * desc;
 int port, trp;
 char * buffer;
{

 register_service(desc, port, "wild_shell");
 
 post_hole(desc, port, "A shell seems to be running on this port ! (this is a possible backdoor)");
}

void
 mark_telnet_server(desc, port, buffer, trp)
 struct arglist * desc;
 int port, trp;
 char * buffer;
{
 char ban[255];
 register_service(desc, port, "telnet");
   {
     snprintf(ban, sizeof(ban), "A telnet server seems to be running on this port%s",
	     get_encaps_through(trp));
     post_note(desc, port, ban);
   }
}

void
 mark_gnome14_server(desc, port, buffer, trp)
 struct arglist * desc;
 int port, trp;
 char * buffer;
{
 char ban[255];
 register_service(desc, port, "gnome14");
   {
     snprintf(ban, sizeof(ban), "A Gnome 1.4 server seems to be running on this port%s",
	     get_encaps_through(trp));
     post_note(desc, port, ban);
   }
}

void
 mark_eggdrop_server(desc, port, buffer, trp)
 struct arglist * desc;
 int port, trp;
 char * buffer;
{
 char ban[255];
 register_service(desc, port, "eggdrop");
   {
     snprintf(ban, sizeof(ban), "An eggdrop IRC bot seems to be running a control server on this port%s",
	     get_encaps_through(trp));
     post_note(desc, port, ban);
   }
}

void
 mark_netbus_server(desc, port, buffer)
 struct arglist * desc;
 int port;
 char * buffer;
{

 register_service(desc, port, "netbus");
 post_hole(desc, port, "NetBus is running on this port");
}


void
mark_linuxconf(desc, port, buffer)
 struct arglist * desc;
 int port;
 char * buffer;
{
 char ban[512];
 register_service(desc, port, "linuxconf");
 snprintf(ban, sizeof(ban), "linuxconf/banner/%d", port);
 plug_set_key(desc, ban, ARG_STRING, buffer);
 post_note(desc, port, "Linuxconf is running on this port");
}

static void
mark_finger_server(desc, port, banner, trp)
     struct arglist	*desc;
     const char		*banner;
     int		port, trp;
{
  char	tmp[256], *p;


  register_service(desc, port, "finger");
  
  snprintf(tmp, sizeof(tmp), "A finger server seems to be running on this port%s",
	  get_encaps_through(trp));
  post_note(desc, port, tmp);
}


static void
mark_vtun_server(desc, port, banner, trp)
    struct arglist	*desc;
     const char		*banner;
     int		port, trp;
{
  char tmp[255];
  
  snprintf(tmp, sizeof(tmp), "vtun/banner/%d", port);
  plug_set_key(desc, tmp, ARG_STRING, (char*)banner);

  register_service(desc, port, "vtun");
  
  if(banner == NULL)
  {
  snprintf(tmp, sizeof(tmp), "A VTUN server seems to be running on this port%s",
	  get_encaps_through(trp));
  }
  else  snprintf(tmp, sizeof(tmp), "A VTUN server seems to be running on this port%s\nHere is its banner:\n%s\n",
	  get_encaps_through(trp), banner);
	  
	
  
  post_note(desc, port, tmp);
}

static void
mark_uucp_server(desc, port, banner, trp)
    struct arglist	*desc;
     const char		*banner;
     int		port, trp;
{
  char tmp[255];
  
  snprintf(tmp, sizeof(tmp), "uucp/banner/%d", port);
  plug_set_key(desc, tmp, ARG_STRING, (char*)banner);
  
  register_service(desc, port, "uucp");
  
  snprintf(tmp, sizeof(tmp), "An UUCP server seems to be running on this port%s",
	  get_encaps_through(trp));
  post_note(desc, port, tmp);
}



static void
mark_lpd_server(desc, port, banner, trp)
    struct arglist	*desc;
     const char		*banner;
     int		port, trp;
{
  char tmp[255];
  
  register_service(desc, port, "lpd");
  snprintf(tmp, sizeof(tmp), "A LPD server seems to be running on this port%s",
	  get_encaps_through(trp));
  post_note(desc, port, tmp);
}


/* http://www.lysator.liu.se/lyskom/lyskom-server/ */
static void
mark_lyskom_server(desc, port, banner, trp)
    struct arglist	*desc;
     const char		*banner;
     int		port, trp;
{
  char tmp[255];
  
  register_service(desc, port, "lyskom");
  snprintf(tmp, sizeof(tmp), "A LysKOM server seems to be running on this port%s",
	  get_encaps_through(trp));
  post_note(desc, port, tmp);
}

/* http://www.emailman.com/ph/ */
static void
mark_ph_server(desc, port, banner, trp)
    struct arglist	*desc;
     const char		*banner;
     int		port, trp;
{
  char tmp[255];
  
  register_service(desc, port, "ph");
  snprintf(tmp, sizeof(tmp), "A PH server seems to be running on this port%s",
	  get_encaps_through(trp));
  post_note(desc, port, tmp);
}

static void
mark_time_server(desc, port, banner, trp)
    struct arglist	*desc;
     const char		*banner;
     int		port, trp;
{
  char	tmp[256], *p;
  int	l;

  register_service(desc, port, "time");  
  snprintf(tmp, sizeof(tmp), "A time server seems to be running on this port%s",
	  get_encaps_through(trp));
  post_note(desc, port, tmp);
}


static void
mark_ens_server(desc, port, banner, trp)
     struct arglist	*desc;
     const char		*banner;
     int		port, trp;
{
  char tmp[255];
  register_service(desc, port, "iPlanetENS");
  
  snprintf(tmp, sizeof(tmp), "An iPlanet ENS (Event Notification Server) seems to be running on this port%s",
	  get_encaps_through(trp));
  post_note(desc, port, tmp);
}

static void 
mark_citrix_server(desc, port, banner, trp)
     struct arglist	*desc;
     const char		*banner;
     int		port, trp;
{
 char tmp[255];
 
 register_service(desc, port, "citrix");
 snprintf(tmp, sizeof(tmp), "a Citrix server seems to be running on this port%s", 
   get_encaps_through(trp));
 post_note(desc, port, tmp);
}

static void
mark_giop_server(desc, port, banner, trp)
	struct arglist	* desc;
	const char 	* banner;
	int port, trp;
{
 char tmp[255];
 
 register_service(desc, port, "giop");
 snprintf(tmp, sizeof(tmp),"A GIOP-enabled service is running on this port%s", 
 	get_encaps_through(trp));
	
 post_note(desc, port, tmp);
}

static void
mark_exchg_routing_server(desc, port, buffer, trp)
 struct arglist * desc;
 int port, trp;
 char * buffer;
{
 char ban[255];
 
 register_service(desc, port, "exchg-routing");
 snprintf(ban, sizeof(ban), "exchg-routing/banner/%d", port);
 plug_set_key(desc, ban, ARG_STRING, buffer);
   {
     snprintf(ban, sizeof(ban), "A Microsoft Exchange routing server is running on this port%s",
	     get_encaps_through(trp));
	     post_note(desc, port, ban);
   }
}


static void
mark_tcpmux_server(desc, port, buffer, trp)
 struct arglist * desc;
 int port, trp;
 char * buffer;
{
 char msg[255];
 
 register_service(desc, port, "tcpmux");
 snprintf(msg, sizeof(msg), "A tcpmux server seems to be running on this port%s",
	     get_encaps_through(trp));
  post_note(desc, port, msg);
}


static void
mark_BitTorrent_server(desc, port, buffer, trp)
 struct arglist * desc;
 int port, trp;
 char * buffer;
{
 char msg[255];
 
 register_service(desc, port, "BitTorrent");
 snprintf(msg, sizeof(msg), "A BitTorrent server seems to be running on this port%s",
	     get_encaps_through(trp));
  post_note(desc, port, msg);
}

static void
mark_smux_server(desc, port, buffer, trp)
 struct arglist * desc;
 int port, trp;
 char * buffer;
{
 char msg[255];
 
 register_service(desc, port, "smux");
 snprintf(msg, sizeof(msg), "A SNMP Multiplexer (smux) seems to be running on this port%s",
	     get_encaps_through(trp));
  post_note(desc, port, msg);
}


/*
 * LISa is the LAN Information Server that comes
 * with KDE in Mandrake Linux 9.0. Apparently
 * it usually runs on port 7741.
 */
static void
mark_LISa_server(desc, port, banner, trp)
	struct arglist	* desc;
	const char 	* banner;
	int port, trp;
{
 char tmp[255];
 
 register_service(desc, port, "LISa");
 snprintf(tmp, sizeof(tmp), "A LISa daemon is running on this port%s", 
 	get_encaps_through(trp));
	
 post_note(desc, port, tmp);
}


/*
 * msdtc is Microsoft Distributed Transaction Coordinator
 *
 * Thanks to jtant@shardwebdesigns.com for reporting it
 *
 */
static void
mark_msdtc_server(desc, port, buffer)
 struct arglist * desc;
 int port;
 char * buffer;
{
 register_service(desc, port, "msdtc");
 post_note(desc, port, "A MSDTC server is running on this port");
}

static void
mark_pop3pw_server(desc, port, buffer, trp)
 struct arglist * desc;
 int port, trp;
 char * buffer;
{
 char ban[512];
 register_service(desc, port, "pop3pw");
 snprintf(ban, sizeof(ban), "pop3pw/banner/%d", port);
 plug_set_key(desc, ban, ARG_STRING, buffer);
 snprintf(ban, sizeof(ban), "A pop3pw server is running on this port%s", get_encaps_through(trp));
 post_note(desc, port, ban);
}

/*
 * whois++ server, thanks to Adam Stephens - http://roads.sourceforge.net/index.php
 *
 * 00: 25 20 32 32 30 20 4c 55 54 20 57 48 4f 49 53 2b    % 220 LUT WHOIS+
 * 10: 2b 20 73 65 72 76 65 72 20 76 32 2e 31 20 72 65    + server v2.1 re
 * 20: 61 64 79 2e 20 20 48 69 21 0d 0a 25 20 32 30 30    ady.  Hi!..% 200
 * 30: 20 53 65 61 72 63 68 69 6e 67 20 66 6f 72 20 47     Searching for G
 * 40: 45 54 26 2f 26 48 54 54 50 2f 31 2e 30 0d 0a 25    ET&/&HTTP/1.0..%
 * 50: 20 35 30 30 20 45 72 72 6f 72 20 70 61 72 73 69     500 Error parsi
 * 60: 6e 67 20 42 6f 6f 6c 65 61 6e 20 65 78 70 72 65    ng Boolean expre
 * 70: 73 73 69 6f 6e 0d 0a                               ssion..
 */
 
static void 
mark_whois_plus2_server(desc, port, buffer, trp)
 struct arglist * desc;
 int port, trp;
 char * buffer;
{
 char ban[255];
 register_service(desc, port, "whois++");
 snprintf(ban, sizeof(ban), "whois++/banner/%d", port);
 plug_set_key(desc, ban, ARG_STRING, buffer);
 snprintf(ban, sizeof(ban), "A whois++ server is running on this port%s", get_encaps_through(trp));
 post_note(desc, port, ban);
}

/* 
 * mon server, thanks to Rafe Oxley <rafe.oxley@moving-edge.net>
 * (http://www.kernel.org/software/mon/)
 *
 * An unknown server is running on this port.
 * If you know what it is, please send this banner to the Nessus team:
 * 00: 35 32 30 20 63 6f 6d 6d 61 6e 64 20 63 6f 75 6c 520 command coul
 * 10: 64 20 6e 6f 74 20 62 65 20 65 78 65 63 75 74 65 d not be execute
 * 20: 64 0a d.
 */
static void
mark_mon_server(desc, port, buffer, trp)
 struct arglist * desc;
 int port, trp;
 char * buffer;
{
 char ban[255];
 register_service(desc, port, "mon");
 snprintf(ban, sizeof(ban), "mon/banner/%d", port);
 plug_set_key(desc, ban, ARG_STRING, buffer);
 snprintf(ban, sizeof(ban), "A mon server is running on this port%s", get_encaps_through(trp));
 post_note(desc, port, ban);
}


static void
mark_fw1(desc, port, buffer, trp)
 struct arglist * desc;
 int port, trp;
 char * buffer;
{
 char ban[255];
 register_service(desc, port, "cpfw1");
 plug_set_key(desc, ban, ARG_STRING, buffer);
 snprintf(ban, sizeof(ban), "A CheckPoint FW1 SecureRemote or FW1 FWModule server is running on this port%s", get_encaps_through(trp));
 post_note(desc, port, ban);
}

/*
 * From: Mike Gitarev [mailto:mik@bofh.lv]
 *
 * http://www.psychoid.lam3rz.de
 * 00: 3a 57 65 6c 63 6f 6d 65 21 70 73 79 42 4e 43 40    :Welcome!psyBNC@
 * 10: 6c 61 6d 33 72 7a 2e 64 65 20 4e 4f 54 49 43 45    lam3rz.de NOTICE
 * 20: 20 2a 20 3a 70 73 79 42 4e 43 32 2e 33 2e 31 2d     * :psyBNC2.3.1-
 * 30: 37 0d 0a                                           7..
 */

static void
mark_psybnc(desc, port, buffer, trp)
 struct arglist * desc;
 int port, trp;
 char * buffer;
{
 char ban[255];
 register_service(desc, port, "psybnc");
 plug_set_key(desc, ban, ARG_STRING, buffer);
 snprintf(ban, sizeof(ban), "A PsyBNC IRC proxy is running on this port%s", get_encaps_through(trp));
 post_note(desc, port, ban);
}

/*
 * From "Russ Paton" <russell.paton@blueyonder.co.uk>
 *
 * 00: 49 43 59 20 32 30 30 20 4f 4b 0d 0a 69 63 79 2d ICY 200 OK..icy-
 * 10: 6e 6f 74 69 63 65 31 3a 3c 42 52 3e 54 68 69 73 notice1:<BR>This
 * 20: 20 73 74 72 65 61 6d 20 72 65 71 75 69 72 65 73 stream requires
 */
static void
mark_shoutcast_server(desc, port, buffer, trp)
 struct arglist * desc;
 int port, trp;
 char * buffer;
{
 char ban[255];
 register_service(desc, port, "shoutcast");
 plug_set_key(desc, ban, ARG_STRING, buffer);
 snprintf(ban, sizeof(ban), "A shoutcast server is running on this port%s", get_encaps_through(trp));
 post_note(desc, port, ban);
}


/*
 * From "Hendrickson, Chris" <chendric@qssmeds.com>
 * 00: 41 64 73 47 6f 6e 65 20 42 6c 6f 63 6b 65 64 20    AdsGone Blocked
 * 10: 48 54 4d 4c 20 41 64                               HTML Ad
 */

static void
mark_adsgone(desc, port, buffer, trp)
 struct arglist * desc;
 int port, trp;
 char * buffer;
{
 char ban[255];
 register_service(desc, port, "adsgone");
 plug_set_key(desc, ban, ARG_STRING, buffer);
 snprintf(ban, sizeof(ban),"An AdsGone (a popup banner blocking server) is running on this port%s", get_encaps_through(trp));
 post_note(desc, port, ban);
}



/*
 * Sig by "Peter C. Parrish" <parrish@ukw.com>
 *
 * unknown (5555/tcp)|11154|Security Note|An unknown server is running on this
 * port.\nIf you know what it is, please send this banner to the Nessus team:
 * 00: 48 50 20 4f 70 65 6e 56 69 65 77 20 53 74 6f 72    HP OpenView Stor
 * 61 67 65 20 44 61 74 61 20 50 72 6f 74 65 63 74    age Data Protect
 * 6f 72 20 41 2e 30 35 2e 30 30 3a 20 49 4e 45 54    or A.05.00: INET
 * 2c 20 69 6e 74 65 72 6e 61 6c 20 62 75 69 6c 64    , internal build
 * 20 31 39 30 2c 20 62 75 69 6c 74 20 6f 6e 20 54     190, built on T
 * 75 65 20 4a 75 6c 20 31 36 20 31 37 3a 33 37 3a    ue Jul 16 17:37:
 * 33 32 20 32 30 30 32 0a                            32 2002.
 */
static void
mark_hpov_storage(desc, port, buffer, trp)
 struct arglist * desc;
 int port, trp;
 char * buffer;
{
 char ban[255];
 register_service(desc, port, "hpov-storage");
 plug_set_key(desc, ban, ARG_STRING, buffer);
 snprintf(ban, sizeof(ban), "HP OpenView Storage Data Protector%s", get_encaps_through(trp));
 post_note(desc, port, ban);
}


/* Sig from  harm vos <h.vos@fwn.rug.nl> :
 * 
 * 00: 2a 20 41 43 41 50 20 28 49 4d 50 4c 45 4d 45 4e    * ACAP (IMPLEMEN
 * 10: 54 41 54 49 4f 4e 20 22 43 6f 6d 6d 75 6e 69 47    TATION "CommuniG
 * 20: 61 74 65 20 50 72 6f 20 41 43 41 50 20 34 2e 30    ate Pro ACAP 4.0
 * 30: 62 39 22 29 20 28 53 54 41 52 54 54 4c 53 29 20    b9") (STARTTLS)
 * 40: 28 53 41 53 4c 20 22 4c 4f 47 49 4e 22 20 22 50    (SASL "LOGIN" "P
 * 50: 4c 41 49 4e 22 20 22 43 52 41 4d 2d 4d 44 35 22    LAIN" "CRAM-MD5"
 * 60: 20 22 44 49 47 45 53 54 2d 4d 44 35 22 20 22 4e     "DIGEST-MD5" "N
 * 70: 54 4c 4d 22 29 20 28 43 4f 4e 54 45 58 54 4c 49    TLM") (CONTEXTLI
 * 80: 4d 49 54 20 22 32 30 30 22 29 0d 0a                MIT "200")..
 *
 * The ACAP protocol allows a client (mailer) application to connect to the
 * Server computer and upload and download the application preferences,
 * configuration settings and other datasets (such as personal address books).
 */
static void
mark_acap_server(desc, port, buffer, trp)
 struct arglist * desc;
 int port, trp;
 char * buffer;
{
 char ban[255];
 register_service(desc, port, "acap");
 snprintf(ban, sizeof(ban), "acap/banner/%d", port);
 plug_set_key(desc, ban, ARG_STRING, buffer);
   {
     snprintf(ban, sizeof(ban), "An ACAP server is running on this port%s",
	     get_encaps_through(trp));
	     post_note(desc, port, ban);
   }
}


/* Sig from Cedric Foll <cedric.foll@ac-rouen.fr>
 * 
 * 
 * 00: 53 6f 72 72 79 2c 20 79 6f 75 20 28 31 37 32 2e Sorry, you (172.
 * 10: 33 30 2e 31 39 32 2e 31 30 33 29 20 61 72 65 20 30.192.103)are
 * 20: 6e 6f 74 20 61 6d 6f 6e 67 20 74 68 65 20 61 6c not among the al
 * 30: 6c 6f 77 65 64 20 68 6f 73 74 73 2e 2e 2e 0a lowed hosts....
 *
 * The ACAP protocol allows a client (mailer) application to connect to the
 * Server computer and upload and download the application preferences,
 * configuration settings and other datasets (such as personal address books).
 */
static void
mark_nagiosd_server(desc, port, buffer, trp)
 struct arglist * desc;
 int port, trp;
 char * buffer;
{
 char ban[255];
 register_service(desc, port, "nagiosd");
 snprintf(ban, sizeof(ban), "A nagiosd server is running on this port%s",
	     get_encaps_through(trp));
	     post_note(desc, port, ban);
   
}
 
/* Sig from  Michael Löffler <nimrod@n1mrod.de>
 *
 * 00: 5b 54 53 5d 0a 65 72 72 6f 72 0a                   [TS].error.
 *
 * That's Teamspeak2 rc2 Server - http://www.teamspeak.org/
 */
static void
mark_teamspeak2_server(desc, port, buffer, trp)
 struct arglist * desc;
 int port, trp;
 char * buffer;
{
 char ban[255];
 register_service(desc, port, "teamspeak2");
 snprintf(ban, sizeof(ban), "A teamspeak2 server is running on this port%s",
	     get_encaps_through(trp));
	     post_note(desc, port, ban);
   
}


/* Sig from <Gary.Crowell@experian.com>
 *
 * 
 *
 *
 * 00: 4c 61 6e 67 75 61 67 65 20 72 65 63 65 69 76 65    Language receive
 * 10: 64 20 66 72 6f 6d 20 63 6c 69 65 6e 74 3a 20 47    d from client: G
 * 20: 45 54 20 2f 20 48 54 54 50 2f 31 2e 30 0d 0a 53    ET / HTTP/1.0..S
 * 30: 65 74 6c 6f 63 61 6c 65 3a 20 0a                   etlocale: .     
 *
 * Port 9090 is for WEBSM, the GUI SMIT tool that AIX RMC  (port 657) is
 * configured and used with.  (AIX Version 5.1)
 */
static void
mark_websm_server(desc, port, buffer, trp)
 struct arglist * desc;
 int port, trp;
 char * buffer;
{
 char ban[255];
 register_service(desc, port, "websm");
 snprintf(ban, sizeof(ban), "A WEBSM server is running on this port%s",
	     get_encaps_through(trp));
	     post_note(desc, port, ban);
   
}

/*
 * From Gary Crowell :
 * 00: 43 4e 46 47 41 50 49                               CNFGAPI
 */
static void 
mark_ofa_express_server(desc, port, buffer, trp)
 struct arglist * desc;
 int port, trp;
 char * buffer;
{
 char ban[255];
 register_service(desc, port, "ofa_express");
 snprintf(ban, sizeof(ban), "An OFA/Express server is running on this port%s",
	     get_encaps_through(trp));
	     post_note(desc, port, ban);
   
}



/* From Pierre Abbat <phma@webjockey.net>
 * 00: 53 75 53 45 20 4d 65 74 61 20 70 70 70 64 20 28 SuSE Meta pppd (
 * 10: 73 6d 70 70 70 64 29 2c 20 56 65 72 73 69 6f 6e    smpppd), Version
 * 20: 20 30 2e 37 38 0d 0a                                0.78..
 */
static void 
mark_smppd_server(desc, port, buffer, trp)
 struct arglist * desc;
 int port, trp;
 char * buffer;
{
 char ban[255];
 register_service(desc, port, "smppd");
 snprintf(ban, sizeof(ban), "A SuSE Meta pppd server is running on this port%s",
	     get_encaps_through(trp));
 post_note(desc, port, ban);  
}
 
/*
 * From DaLiV <daliv@apollo.lv
 *
 * 00: 45 52 52 20 55 4e 4b 4e 4f 57 4e 2d 43 4f 4d 4d ERR UNKNOWN-COMM
 * 10: 41 4e 44 0a 45 52 52 20 55 4e 4b 4e 4f 57 4e 2d AND.ERR UNKNOWN-
 * 20: 43 4f 4d 4d 41 4e 44 0a COMMAND.
 */
static void 
mark_upsmon_server(desc, port, buffer, trp)
 struct arglist * desc;
 int port, trp;
 char * buffer;
{
 char ban[255];
 register_service(desc, port, "upsmon");
 snprintf(ban, sizeof(ban), "An upsd/upsmon server is running on this port%s",
	     get_encaps_through(trp));
 post_note(desc, port, ban);  
}

/*
 * From Andrew Yates <pilot1_ace@hotmail.com>
 *
 * 00: 63 6f 6e 6e 65 63 74 65 64 2e 20 31 39 3a 35 31    connected. 19:51
 * 10: 20 2d 20 4d 61 79 20 32 35 2c 20 32 30 30 33 2c     - May 25, 2003,
 * 20: 20 53 75 6e 64 61 79 2c 20 76 65 72 3a 20 4c 65     Sunday, ver: Le
 * 30: 67 65 6e 64 73 20 32 2e 31                         gends 2.1
 */
static void 
mark_sub7_server(desc, port, buffer, trp)
 struct arglist * desc;
 int port, trp;
 char * buffer;
{
 char ban[255];
 register_service(desc, port, "sub7");
 snprintf(ban, sizeof(ban), "The Sub7 trojan is running on this port%s",
	     get_encaps_through(trp));
 post_hole(desc, port, ban);  
}


/*
 * From "Alex Lewis" <alex@sgl.org.au>
 *
 *  00: 53 50 41 4d 44 2f 31 2e 30 20 37 36 20 42 61 64    SPAMD/1.0 76 Bad
 *  10: 20 68 65 61 64 65 72 20 6c 69 6e 65 3a 20 47 45     header line: GE
 *  20: 54 20 2f 20 48 54 54 50 2f 31 2e 30 0d 0d 0a       T /
 */
static void 
mark_spamd_server(desc, port, buffer, trp)
 struct arglist * desc;
 int port, trp;
 char * buffer;
{
 char ban[255];
 register_service(desc, port, "spamd");
 snprintf(ban, sizeof(ban), "a spamd server (part of spamassassin) is running on this port%s",
	     get_encaps_through(trp));
 post_note(desc, port, ban);  
}

/* Thanks to Mike Blomgren */
static void 
mark_quicktime_streaming_server(desc, port, buffer, trp)
 struct arglist * desc;
 int port, trp;
 char * buffer;
{
 char ban[255];
 register_service(desc, port, "quicktime-streaming-server");
 snprintf(ban, sizeof(ban), "a quicktime streaming server is running on this port%s",
	     get_encaps_through(trp));
 post_note(desc, port, ban);  
}

/* Thanks to Allan <als@bpal.com> */
static void 
mark_dameware_server(desc, port, buffer, trp)
 struct arglist * desc;
 int port, trp;
 char * buffer;
{
 char ban[255];
 register_service(desc, port, "dameware");
 snprintf(ban, sizeof(ban), "a dameware server is running on this port%s",
	     get_encaps_through(trp));
 post_note(desc, port, ban);  
}

static void 
mark_stonegate_auth_server(desc, port, buffer, trp)
 struct arglist * desc;
 int port, trp;
 char * buffer;
{
 char ban[255];
 register_service(desc, port, "SG_ClientAuth");
 snprintf(ban, sizeof(ban), "a StoneGate authentication server is running on this port%s",
	     get_encaps_through(trp));
 post_note(desc, port, ban);  
}



void
mark_listserv_server(desc, port, buffer, trp)
 struct arglist * desc;
 int port, trp;
 char * buffer;
{
 char ban[255];
 register_service(desc, port, "listserv");
   {
     snprintf(ban, sizeof(ban), "A LISTSERV daemon seems to be running on this port%s",
	     get_encaps_through(trp));
     post_note(desc, port, ban);
   }
}


void
mark_fssniffer(desc, port, buffer, trp)
 struct arglist * desc;
 int port, trp;
 char * buffer;
{
 char ban[255];
 register_service(desc, port, "FsSniffer");
   {
     snprintf(ban, sizeof(ban), "A FsSniffer backdoor seems to be running on this port%s",
	     get_encaps_through(trp));
     post_hole(desc, port, ban);
   }
}

void
mark_remote_nc_server(desc, port, buffer, trp)
 struct arglist * desc;
 int port, trp;
 char * buffer;
{
 char ban[255];
 register_service(desc, port, "RemoteNC");
   {
     snprintf(ban, sizeof(ban), "A RemoteNC backdoor seems to be running on this port%s",
	     get_encaps_through(trp));
     post_hole(desc, port, ban);
   }
}



/* Do not use register_service for unknown and wrapped services! */

#ifdef DETECT_WRAPPED_SVC
static void
mark_wrapped_svc(desc, port, delta)
     struct arglist	* desc;
     int		port, delta;
{
  char	msg[256];

  snprintf(msg, sizeof(msg), "The service closed the connection after %d seconds without sending any data\n\
It might be protected by some TCP wrapper\n", delta);
  post_note(desc, port, msg);
  plug_set_key(desc, "Services/wrapped", ARG_INT,(void*) port);
}
#endif

static void
mark_unknown_svc(desc, port, banner, trp)
     struct arglist	* desc;
     int		port, trp;
     const unsigned char	*banner;
{
  char		tmp[1600], *norm = NULL;

  plug_set_key(desc, "Services/unknown", ARG_INT,(void*) port);
  snprintf(tmp, sizeof(tmp), "unknown/banner/%d", port);
  plug_set_key(desc, tmp, ARG_STRING, (char*)banner);

  /* Note: only includes services that are recognized by this plugin! */
  switch (port)
    {
    case 4:	norm = "Echo"; break;
    case 19:	norm = "Chargen"; break;
    case 21:	norm = "FTP"; break;
    case 22:	norm = "SSH"; break;
    case 23:	norm = "Telnet"; break;
    case 25:	norm = "SMTP"; break;
    case 37:	norm = "Time"; break;
    case 70:	norm = "Gopher"; break;
    case 79:	norm = "Finger"; break;
    case 80:	norm = "HTTP"; break;
    case 98:	norm = "Linuxconf"; break;
    case 109:	norm = "POP2"; break;
    case 110:	norm = "POP3"; break;
    case 113:	norm = "AUTH"; break;
    case 119:	norm = "NNTP"; break;
    case 143:	norm = "IMAP"; break;
    case 220:	norm = "IMAP3"; break;
    case 443:	norm = "HTTPS"; break;
    case 465:	norm = "SMTPS"; break;
    case 563:	norm = "NNTPS"; break;
    case 593:	norm = "Http-Rpc-Epmap"; break;
    case 873:   norm = "Rsyncd"; break;
    case 901:	norm = "SWAT"; break;
    case 993:	norm = "IMAPS"; break;
    case 995:	norm = "POP3S"; break;
#if 0
    case 1080:	norm = "SOCKS"; break;
#endif
    case 1109:	norm = "KPOP"; break; /* ? */
    case 2309:  norm = "Compaq Management Server"; break;
    case 2401:	norm = "CVSpserver"; break;
    case 3128:	norm = "Squid"; break;
    case 3306:	norm = "MySQL"; break;
    case 5000:  norm = "VTUN"; break;
    case 5432:	norm = "Postgres"; break;
    case 8080:	norm = "HTTP-Alt"; break;
    }
  *tmp = '\0';
  if (norm != NULL)
    {
      snprintf(tmp, sizeof(tmp), "An unknown service is running on this port%s.\n\
It is usually reserved for %s", 
	      get_encaps_through(trp), norm);
    }

#ifdef PRINT_UNKNOWN_SVC_BANNER
  if (banner != NULL && *banner != '\0')
    {
      char	*p;
      int	i, j, n;

      if (*tmp == '\0')
	snprintf(tmp, sizeof(tmp), "An unknown service is running on this port%s.\n",
		get_encaps_through(trp));

      for (p = tmp; *p != '\0'; p ++)
	;
      n = sprintf(p, "\nHere is its%s banner:",
		  strlen(banner) > 256 ? " (truncated)" : "");
      if (n > 0)
	p += n;
      
      for (j = 0; j < 256; j += 16)
	{
	  *p++ = '\n';
	  for (i = j; i < j + 16 && banner[i] != '\0'; i ++)
	    {
	      sprintf(p, "%02x ", banner[i]);
	      p += 3;
	    }
	  /* Fill last line */
	  for (; i < j + 16; i ++)
	    {
	      *p++ = ' '; *p++ = ' '; *p++ = ' '; 
	    }

	  *p++ = ' '; *p++ = ' ';
	  for (i = j; i < j + 16 && banner[i] != '\0'; i ++)
	    if (isspace(banner[i]))
	      *p++ = ' ';
	    else if (isprint(banner[i]))
	      *p++ = banner[i];
	    else
	      *p++ = '.';
	  if (banner[i] == '\0')
	    break;
	}
      *p++ = '\0';
    }
#endif
  if (*tmp != '\0')
    post_note(desc, port, tmp);
}

static void
mark_gnuserv(desc, port)
     struct arglist * desc;
     int		port;
{
  register_service(desc, port, "gnuserv");
  post_note(desc, port, "gnuserv is running on this port");
}

static void
mark_iss_realsecure(desc, port)
     struct arglist * desc;
     int		port;
{
  register_service(desc, port, "issrealsecure");
  post_note(desc, port, "ISS RealSecure is running on this port");
}

static void
mark_vmware_auth(desc, port, buffer, trp)
 struct arglist * desc;
 int port, trp;
 char * buffer;
{
 char ban[512];

 
 register_service(desc, port, "vmware_auth");
 
 snprintf(ban, sizeof(ban), "A VMWare authentication daemon is running on this port%s:\n%s",
	     get_encaps_through(trp), buffer);
 post_note(desc, port, ban);	 
	     
}

static void
mark_interscan_viruswall(desc, port, buffer, trp)
 struct arglist * desc;
 int port, trp;
 char * buffer;
{
  char ban[512];

 register_service(desc, port, "interscan_viruswall");
 
 snprintf(ban, sizeof(ban), "An interscan viruswall is running on this port%s:\n%s",
	     get_encaps_through(trp), buffer);
 post_note(desc, port, ban);	 
}

static void
mark_ppp_daemon(desc, port, buffer, trp)
 struct arglist * desc;
 int port, trp;
 char * buffer;
{
  char ban[512];

 register_service(desc, port, "pppd");
 
 snprintf(ban, sizeof(ban), "A PPP daemon is running on this port%s",
	     get_encaps_through(trp));
 post_note(desc, port, ban);	 
}

static void
mark_zebra_server(desc, port, buffer, trp)
 struct arglist * desc;
 int port, trp;
 char * buffer;
{
  char ban[512];

 register_service(desc, port, "zebra");
 
 snprintf(ban, sizeof(ban), "A zebra daemon (bgpd or zebrad) is running on this port%s",
	     get_encaps_through(trp));
 post_note(desc, port, ban);	 
}

static void
mark_ircxpro_admin_server(desc, port, buffer, trp)
struct arglist * desc;
 int port, trp;
 char * buffer;
{
  char ban[512];

 register_service(desc, port, "ircxpro_admin");
 
 snprintf(ban, sizeof(ban), "An IRCXPro administrative server is running on this port%s",
	     get_encaps_through(trp));
 post_note(desc, port, ban);	 
}


static void
mark_gnocatan_server(desc, port, buffer, trp)
struct arglist * desc;
 int port, trp;
 char * buffer;
{
  char ban[512];

 register_service(desc, port, "gnocatan");
 
 snprintf(ban, sizeof(ban), "A gnocatan game server is running on this port%s",
	     get_encaps_through(trp));
 post_note(desc, port, ban);	 
}

/* Thanks to Owell Crow */
static void
mark_pbmaster_server(desc, port, buffer, trp)
struct arglist * desc;
 int port, trp;
 char * buffer;
{
  char ban[512];

 register_service(desc, port, "power-broker-master");
 
 snprintf(ban, sizeof(ban), "A PowerBroker master server is running on this port%s:\n%s",
	     get_encaps_through(trp), buffer);
 post_note(desc, port, ban);	 
}

/* Thanks to Paulo Jorge */
static void
mark_dictd_server(desc, port, buffer, trp)
struct arglist * desc;
 int port, trp;
 char * buffer;
{
  char ban[512];

 register_service(desc, port, "dicts");
 
 snprintf(ban, sizeof(ban), "A dictd server is running on this port%s:\n%s",
	     get_encaps_through(trp), buffer);
 post_note(desc, port, ban);	 
}


/* Thanks to Tony van Lingen */
static void
mark_pnsclient(desc, port, buffer, trp)
 struct arglist * desc;
 int port, trp;
 char * buffer;
{
 char ban[512];

 register_service(desc, port, "pNSClient");
 
 snprintf(ban, sizeof(ban), "A Netsaint plugin (pNSClient.exe) is running on this port%s:",
	     get_encaps_through(trp), buffer);
 post_note(desc, port, ban);	 
}

/* Thanks to Jesus D. Munoz */
static void
mark_veritas_backup(desc, port, buffer, trp)
 struct arglist * desc;
 int port, trp;
 char * buffer;
{
 char ban[512];
 register_service(desc, port, "VeritasNetBackup");
 
 snprintf(ban, sizeof(ban), "VeritasNetBackup is running on this port%s:",
	     get_encaps_through(trp), buffer);
 post_note(desc, port, ban);	 
}

static void
mark_pblocald_server(desc, port, buffer, trp)
struct arglist * desc;
 int port, trp;
 char * buffer;
{
  char ban[512];

 register_service(desc, port, "power-broker-master");
 
 snprintf(ban, sizeof(ban), "A PowerBroker locald server is running on this port%s:\n%s",
	     get_encaps_through(trp), buffer);
 post_note(desc, port, ban);	 
}

static void
mark_avotus_mm_server(desc, port, buffer, trp)
struct arglist * desc;
 int port, trp;
 char * buffer;
{
  char ban[512];

 register_service(desc, port, "avotus_mm");
 
 snprintf(ban, sizeof(ban), "An avotus 'mm' server is running on this port%s:\n%s",
	     get_encaps_through(trp), buffer);
 post_note(desc, port, ban);	 
}

static void
mark_socks_proxy(desc, port, ver)
     struct arglist	* desc;
     int		port, ver;
{
  char			str[256];

  sprintf(str, "socks%d", ver);
  register_service(desc,port, str);
  sprintf(str, "A SOCKS%d proxy is running on this port. ", ver);
  post_note(desc, port, str);
}

static void
mark_direct_connect_hub(desc, port, trp)
     struct arglist	* desc;
     int		port, trp;
{
  char			str[256];

  register_service(desc,port, "DirectConnectHub");
  snprintf(str, sizeof(str), "A Direct Connect Hub is running on this port%s", get_encaps_through(trp));
  post_note(desc, port, str);
}

/*
 * We determine if the 4 bytes we received look like a date. We
 * accept clocks desynched up to 3 years;
 *
 * MA 2002-09-09 : time protocol (RFC 738) returns number of seconds since 
 * 1900-01-01, while time() returns nb of sec since 1970-01-01. 
 * The difference is 2208988800 seconds.
 * By the way, although the RFC is imprecise, it seems that the returned 
 * integer is in "network byte order" (i.e. big endian)
 */
#define MAX_SHIFT	(3*365*86400)
#define DIFF_1970_1900	2208988800U

static int 
may_be_time(time_t * rtime)
{
#ifndef ABS
# define ABS(x) (((x) < 0) ? -(x):(x))
#endif
 time_t now = time(NULL);
 int	rt70 = ntohl(*rtime) - DIFF_1970_1900;

 if(ABS(now - rt70) < MAX_SHIFT)
   return 1;
 else
  return 0;
}

/*
 * References:
 * IANA assigned number
 *
 * http://www.tivoli.com/support/public/Prodman/public_manuals/td/ITAME/GC32-0848-00/en_US/HTML/amwebmst09.htm
 * http://java.sun.com/webservices/docs/1.0/tutorial/doc/WebAppSecurity6.html
 */

static int
known_ssl_port(int port)
{
  switch(port)
    {
    case 261:			/* Nsiiops = IIOP name service over tls/ssl */
    case 443:			/* HTTPS */
    case 448:			/* ddm-ssl */
    case 465:			/* SMTPS */
    case 563:			/* NNTPS */
    case 585:			/* imap4-ssl (not recommended) */
    case 614:			/* SSLshell */
    case 636:			/* LDAPS */
    case 684:			/* Corba IIOP SSL */
    case 902:			/* VMWare auth daemon */
    case 989:			/* FTPS data */
    case 990:			/* FTPS control */
    case 992:			/* telnets */
    case 993:			/* IMAPS */
    case 994:			/* IRCS */
    case 995:			/* POP3S */
    case 1241:			/* Nessus */
    case 2478:			/* SecurSight Authentication Server (SSL) */
    case 2479:			/* SecurSight Event Logging Server (SSL) */
    case 2482:			/* Oracle GIOP SSL */
    case 2484:			/* Oracle TTC SSL */
    case 2679:			/* Sync Server SSL */
    case 3077:			/* Orbix 2000 Locator SSL */
    case 3078:			/* Orbix 2000 Locator SSL */
    case 3269:			/* Microsoft Global Catalog w/ LDAP/SSL */
    case 3471:			/* jt400 SSL */
    case 5007:			/* WSM Server SSL */
    case 7135:			/* IBM Tivoli Access Manager runtime environment - SSL Server Port */
    case 8443:			/* Tomcat */
    case 9443:			/* Websphere internal secure server */
    case 10000: 		/* WebMin+SSL */
    case 19201:			/* SilkPerformer agent (secure connection) */
      return 1;
    default:
      return 0;
    }
  /*NOTREACHED*/
}


#ifndef MSG_DONTWAIT
/* From http://www.kegel.com/dkftpbench/nonblocking.html */
static int
setNonblocking(int fd)
{
  int flags;

  /* If they have O_NONBLOCK, use the Posix way to do it */
#if defined(O_NONBLOCK)
  /* Fixme: O_NONBLOCK is defined but broken on SunOS 4.1.x and AIX 3.2.5. */
  if (-1 == (flags = fcntl(fd, F_GETFL, 0)))
    flags = 0;
  return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#else
  /* Otherwise, use the old way of doing it */
  flags = 1;
  return ioctl(fd, FIONBIO, &flags);
#endif
}     
#endif





static int plugin_do_run(desc, h, test_ssl)
 struct arglist * desc;
 struct arglist * h;
 int test_ssl;
{
 char * head = "Ports/tcp/";
 u_short unknown[65535];
 int num_unknown = 0;
 int len_head = strlen(head);
 int	might_be_socks = 0;
 
 int	rw_timeout = 5, cnx_timeout = 5, wrap_timeout = 3;
 int	x, timeout;
 char	*rw_timeout_s = get_plugin_preference(desc, RW_TIMEOUT_PREF);
 char	*cnx_timeout_s = get_plugin_preference(desc, CNX_TIMEOUT_PREF);
#ifdef DETECT_WRAPPED_SVC
 char	*wrap_timeout_s = get_plugin_preference(desc, WRAP_TIMEOUT_PREF);
#endif
  unsigned char	*p;
  time_t	t1, t2;
  int		delta_t;
  fd_set	rfds, wfds, xfds;
  struct timeval tv;
  

  if (rw_timeout_s != NULL && (x = atoi(rw_timeout_s)) > 0)
    rw_timeout = x;
  if (cnx_timeout_s != NULL && (x = atoi(cnx_timeout_s)) > 0)
    cnx_timeout = x;
#ifdef DETECT_WRAPPED_SVC
  if (wrap_timeout_s != NULL && (x = atoi(wrap_timeout_s)) >= 0)
    wrap_timeout = x;
#endif
 
 bzero(unknown, sizeof(unknown));



 while(h && h->next)
 {
  if((strlen(h->name) > len_head)&&
     !strncmp(h->name, head, len_head))
  {
    int		cnx;
    char	* line;
    char 	* origline;
    int		trp, i;
    char	buffer[2049];
    unsigned char * banner = NULL;
    int port = atoi(h->name+len_head);
    int flg = 0;
    int	unindentified_service = 0;
    int maybe_wrapped = 0;

    if (test_ssl == 2 || 
	test_ssl == 1 && known_ssl_port(port))
      cnx = open_stream_connection_unknown_encaps(desc, port, cnx_timeout, &trp);
    else
      {
	trp = NESSUS_ENCAPS_IP;
	cnx = open_stream_connection(desc, port, trp, cnx_timeout);
      }
  
  if(cnx >= 0)
   {
    int		len;
    int		realfd = nessus_get_socket_from_connection(cnx);
    
#ifdef DEBUG    
    fprintf(stderr, "Port %d is open. \"Transport\" is %d\n", port, trp);
#endif    
    plug_set_port_transport(desc, port, trp);
    (void) stream_set_timeout(port, rw_timeout);

#ifdef HAVE_SSL
    if (IS_ENCAPS_SSL(trp))
      {
	char	report[160];
        snprintf(report, sizeof(report), "A %s server answered on this port\n", 
		get_encaps_name(trp));
	post_note(desc, port, report);
	plug_set_key(desc, "Transport/SSL", ARG_INT, (void*) port);
      }
#endif
    
 
#define HTTP_GET	"GET / HTTP/1.0\r\n\r\n"

    len = 0; timeout = 0;
    bzero(buffer, sizeof(buffer));
#ifdef SMART_TCP_RW
    if (trp == NESSUS_ENCAPS_IP && realfd >= 0)
      {
	FD_ZERO(&rfds); FD_ZERO(&wfds);
	FD_SET(realfd, &rfds); FD_SET(realfd, &wfds); 

	t1 = time(NULL);
	tv.tv_usec = 0; tv.tv_sec = rw_timeout;
	x = select(realfd+1, &rfds, &wfds, NULL, &tv);
	if (x < 0)
	  perror("select");
	else if (x == 0)
	  timeout = 1;
	else if (x > 0)
	  {
	    if (FD_ISSET(realfd, &rfds))
	      {
		len = read_stream_connection_min(cnx, buffer, 1, sizeof(buffer)-2);
	      }
	  }
	t2 = time(NULL);
	delta_t = t2 - t1;
      }

    if (len <= 0 && ! timeout)
#endif
      {
	write_stream_connection(cnx, HTTP_GET, sizeof(HTTP_GET)-1);
	t1 = time(NULL);
	len = read_stream_connection(cnx, buffer, sizeof(buffer)-1);
	t2 = time(NULL);
	delta_t = t2 - t1;
      }

   if (len > 0)
     {
     banner = estrdup(buffer);
   for(i=0;i<len;i++)buffer[i] = tolower(buffer[i]);      
   line = estrdup(buffer);
  
   if(strchr(line, '\n')){
   	char * t = strchr(line, '\n');
	t[0]='\0';
	}
	
   origline = estrdup(banner);
   if(strchr(origline, '\n')){
   	char * t = strchr(origline, '\n');
	t[0] = '\0';
	}
    
    /*
     * Many services run on the top of an HTTP protocol,
     * so the HTTP test is not an 'ELSE ... IF'
     */
    if((!strncmp(line, "http/1.", 7) ||
       strstr(banner, "<title>Not supported</title>"))) /* <- broken hp jetdirect*/
    {  
      flg++;
      if(!(port == 5000 && (strstr(line, "http/1.1 400 bad request") != NULL)) &&
         !(strncmp(line, "http/1.0 403 forbidden", strlen("http/1.0 403 forbidden")) == 0 && strstr(buffer, "server: adsubtract") != NULL))
	 mark_http_server(desc, port, banner, trp); 
	
    }
    

   

    /*
     * RFC 854 defines commands between 240 and 254
     * shouldn't we look for them too? 
     */
    if(((u_char)buffer[0]==255) && (((u_char)buffer[1]==251) || ((u_char)buffer[1]==252) || ((u_char)buffer[1]==253) || ((u_char)buffer[1]==254)))
      mark_telnet_server(desc, port, origline, trp);
    else if(((u_char)buffer[0]==0) && ((u_char)buffer[1]==1) && ((u_char)buffer[2]==1) && ((u_char)buffer[3]==0))
      mark_gnome14_server(desc, port, origline, trp);
    else if(strncmp(line, "http/1.0 403 forbidden", strlen("http/1.0 403 forbidden")) == 0 && strstr(buffer, "server: adsubtract") != NULL)
       {
        mark_locked_adsubtract_server(desc, port, banner, trp);
       }
    else if(strstr(banner, "Eggdrop") != NULL &&
            strstr(banner, "Eggheads") != NULL )
      mark_eggdrop_server(desc, port, origline, trp);	    
    else if(strncmp(line, "$lock ", strlen("$lock ")) == 0 )
	mark_direct_connect_hub(desc, port, trp);
    else if(len > 34 && strstr(&(buffer[34]), "iss ecnra"))
    	mark_iss_realsecure(desc, port, origline, trp); 
    else if(len == 4 && origline[0] == 'Q' && origline[1] == 0 && origline[2] == 0 && origline[3] == 0)
    	mark_fw1(desc, port, origline, trp);  
    else if(strstr(line, "adsgone blocked html ad") != NULL)
        mark_adsgone(desc, port, origline, trp);
    else if(strncmp(line, "icy 200 ok", strlen("icy 200 ok")) == 0)
        mark_shoutcast_server(desc, port, origline, trp);
    else  if((strstr(line, "smtp") || strstr(line, "simple mail transfer") || strstr(line, "mail server") || strstr(line, "messaging") || strstr(line, "Weasel")) && !strncmp(line, "220", 3))
    	mark_smtp_server(desc, port, origline, trp);
    else if(strstr(line, "220 ***************")) /* CISCO SMTP (?) - see bug #175 */
        mark_smtp_server(desc, port, origline, trp);
    else if(strstr(line, "220 esafealert") != NULL )
    	mark_smtp_server(desc, port, origline, trp);	
    else if(strncmp(line, "220", 3) == 0 &&
	    strstr(line, "groupwise internet agent") != NULL)
      	mark_smtp_server(desc, port, origline, trp);
    else if(strncmp(line, "220", 3) == 0 && strstr(line, " SNPP ") != NULL)
      	mark_snpp_server(desc, port, origline, trp);
     else if(strncmp(line, "200", 3) == 0 &&
      	    strstr(line, "mail ") != NULL)
	mark_smtp_server(desc, port, origline, trp);
    else if((!strncmp(line, "hhost '", 7) || !strncmp(line, "khost '", 7) || !strncmp(line, "whost '", 7)) && strstr(line, "mysql"))
        mark_mysql(desc, port, origline, trp);
    else if(!strncmp(line, "efatal", 6) || !strncmp(line, "einvalid packet length", strlen("einvalid packet length")))
        mark_postgresql(desc, port, origline, trp);
    else if (strstr(line, "cvsup server ready") != NULL )
    	mark_cvsupserver(desc, port, origline, trp);
    else if(!strncmp(line, "cvs [pserver aborted]:", 22) ||
       	    !strncmp(line, "cvs [server aborted]:", 21))
        mark_cvspserver(desc, port, origline, trp);
    else if (!strncmp(line, "cvslock ", 8))
        mark_cvslockserver(desc, port, origline, trp);
    else if(!strncmp(line, "@rsyncd", 7))
         mark_rsyncd(desc, port, origline, trp); 
    else if((len == 4) && may_be_time((time_t*)banner))
        mark_time_server(desc, port, banner, trp);
    else if(strstr(buffer, "rmserver")||strstr(buffer, "realserver"))
        mark_rmserver(desc, port, origline, trp);
    else if((strstr(line, "ftp") || strstr(line, "netpresenz") || strstr(line, "serv-u") || strstr(line, "service ready for new user")) && !strncmp(line, "220", 3))
    	mark_ftp_server(desc, port, origline, trp);	
    else if(strncmp(line, "220-", 4) == 0) 	/* FTP server with a long banner */
    	mark_ftp_server(desc, port, NULL, trp);	
    else if(strstr(line, "220") && strstr(line, "whois+"))
    	mark_whois_plus2_server(desc, port, origline, trp);
    else if(strstr(line, "520 command could not be executed"))
    	mark_mon_server(desc, port, origline, trp);
    else if(strstr(line, "ssh-"))
    	mark_ssh_server(desc, port, origline);
    else if(!strncmp(line, "+ok", 3) || (!strncmp(line, "+", 1) && strstr(line, "pop")))
    	mark_pop_server(desc, port, origline);
    else if(strstr(line, "imap4") && !strncmp(line, "* ok", 4))
    	mark_imap_server(desc, port, origline, trp);
    else if(strstr(line, "*ok iplanet messaging multiplexor"))
        mark_imap_server(desc, port, origline, trp);
    else if(strstr(line, "* ok courier-imap"))
        mark_imap_server(desc, port, origline, trp);
    else if(strncmp(line, "giop", 4) == 0)
    	mark_giop_server(desc, port, origline, trp);
    else if(strstr(line, "microsoft routing server"))
        mark_exchg_routing_server(desc, port, origline, trp);	
    /* Apparently an iPlanet ENS server */
    else if(strstr(line, "gap service ready"))
    	mark_ens_server(desc, port, origline, trp);	
    else if(strstr(line, "-service not available"))
    	mark_tcpmux_server(desc, port, origline, trp);	
    /* Citrix sends 7f 7f 49 43 41, that we converted to lowercase */
    else if(line[0] == 0x7F && line[1] == 0x7F && strncmp(&line[2], "ica", 3) == 0)
        mark_citrix_server(desc, port, origline, trp);	
	
    else if(strstr(origline, " INN ") || strstr(origline, " Leafnode ") ||
	    strstr(line, "  nntp daemon") ||
	    strstr(line, " nnrp service ready") ||
	    strstr(line, "posting ok") || strstr(line, "posting allowed") ||
	    strstr(line, "502 no permission") ||
	    (strcmp(line, "502") == 0 && strstr(line, "diablo") != NULL))
    	mark_nntp_server(desc, port, origline, trp);	
    else if(strstr(buffer, "networking/linuxconf") || strstr(buffer, "networking/misc/linuxconf") || strstr(buffer, "server: linuxconf"))
        mark_linuxconf(desc, port, banner);
    else if (strncmp(buffer, "gnudoit:", 8) == 0)
      mark_gnuserv(desc, port);
    else if ((buffer[0] == '0' && strstr(buffer, "error.host\t1") != NULL) ||
      	     (buffer[0] == '3' && strstr(buffer, "That item is not currently available")))
      mark_gopher_server(desc, port);
   else if(strstr(buffer, "www-authenticate: basic realm=\"swat\""))
   	mark_swat_server(desc, port, banner);
   else if(strstr(buffer, "vqserver") &&
           strstr(buffer, "www-authenticate: basic realm=/"))
	 mark_vqserver(desc,port, banner);
   else if(strstr(buffer, "1invalid request") != NULL )
   	 mark_mldonkey(desc, port, banner);	 
   else if(strstr(buffer, "get: command not found"))
   	mark_wild_shell(desc, port, origline);	
   else if(strstr(buffer, "microsoft windows") != NULL &&
   	   strstr(buffer, "c:\\") != NULL &&
	   strstr(buffer, "(c) copyright 1985-") != NULL &&
	   strstr(buffer, "microsoft corp.") != NULL)
	   mark_wild_shell(desc, port, origline);
   else if(strstr(buffer, "netbus"))
   	mark_netbus_server(desc, port, origline);	
   else if(strstr(line, "0 , 0 : error : unknown-error") ||
	   strstr(line, "get : error : unknown-error") ||
	   strstr(line, "0 , 0 : error : invalid-port") )
   	mark_auth_server(desc, port, origline);
    else if(!strncmp(line, "http/1.", 7) && strstr(line, "proxy")) /* my proxy "HTTP/1.1 502 Proxy Error" */
	mark_http_proxy(desc, port, banner, trp);	
    else if(!strncmp(line, "http/1.", 7) && strstr(buffer, "via: "))
	mark_http_proxy(desc, port, banner, trp);	
    else if(!strncmp(line, "http/1.", 7) && strstr(buffer, "proxy-connection: "))
	mark_http_proxy(desc, port, banner, trp);	
    else if(!strncmp(line, "http/1.", 7) &&strstr(buffer, "cache")&&
    	    strstr(line, "bad request"))
	mark_http_proxy(desc, port, banner, trp);
#if 0
    else if (strncmp(line, "http/1.", 7) == 0 && 
	     strstr(buffer, "gnutella") != NULL)
      mark_gnutella_servent(desc, port, banner, trp);
#endif
    else if(!strncmp(origline, "RFB 00", 6) && strstr(line, ".00"))
   	mark_vnc_server(desc, port, origline);
    else if(!strncmp(line, "ncacn_http/1.", 13))
   	mark_ncacn_http_server(desc, port, origline);
    else if(!strncmp(origline, "GET / HTTP/1.0", 14))
    	mark_echo_server(desc, port ,origline);	
    else if(strstr(banner, "!\"#$%&'()*+,-./") && strstr(banner, "ABCDEFGHIJ") && strstr(banner, "abcdefghij") && strstr(banner, "0123456789"))
    	mark_chargen_server(desc, port, banner);
    else if(strstr(line, "vtun server"))
    	mark_vtun_server(desc, port, banner, trp);	
    else if(strcmp(line, "login: password: ") == 0)
        mark_uucp_server(desc, port, banner, trp);	
    else if(strcmp(line, "bad request") == 0 ||			/* See bug # 387 */
             strstr(line, "invalid protocol request (71): gget / http/1.0") ||
            (strncmp(line, "lpd:", 4) == 0) ||
	    (strstr(line, "lpsched") != NULL) ||
	    (strstr(line, "malformed from address") != NULL) ||
	    (strstr(line, "no connect permissions") != NULL) || /* <- RH 8 lpd */
	    strcmp(line, "bad request") == 0 ) 
         mark_lpd_server(desc, port, banner, trp);
    else if(strstr(line, "%%lyskom unsupported protocol"))
    	 mark_lyskom_server(desc, port, banner, trp);
    else if(strstr(line, "598:get:command not recognized"))
    	 mark_ph_server(desc, port, banner, trp);	 	
    else if(strstr(line, "BitTorrent prot"))
    	mark_BitTorrent_server(desc, port, banner, trp);	  
    else if(banner[0] == 'A' && banner[1] == 0x01 && banner[2] == 0x02 && banner[3] == '\0')
    	 mark_smux_server(desc, port, banner, trp);
    else if(!strncmp(line, "0 succeeded\n", strlen("0 succeeded\n")))
    	 mark_LISa_server(desc, port, banner, trp);
    else if(strlen(banner) == 3 && banner[2] == '\n')
    	 mark_msdtc_server(desc, port, banner, trp);
    else if((!strncmp(line, "220", 3) && strstr(line, "poppassd")))
    	mark_pop3pw_server(desc, port, origline, trp);
    else if(strstr(line, "welcome!psybnc@") != NULL)
    	mark_psybnc(desc, port, origline, trp);
    else if(strstr(line, "hp openview storage protect") != NULL)
	mark_hpov_storage(desc, port, origline, trp);
    else if(strncmp(line, "* acap ", strlen("* acap ")) == 0)
      	mark_acap_server(desc, port, origline, trp);
    else if(strstr(origline, "Sorry, you (") != NULL &&
            strstr(origline, "are not among the allowed hosts...\n") != NULL)
	mark_nagiosd_server(desc, port, origline, trp);
    else if(strstr(line, "[ts].error") != NULL ||
	    strstr(line, "[ts].\n") != NULL)
      	mark_teamspeak2_server(desc, port, origline, trp);
    else if(strstr(origline, "Language received from client:") &&
            strstr(origline, "Setlocale:"))
	 mark_websm_server(desc, port, origline, trp);
    else if(strncmp(origline, "CNFGAPI", 7) == 0)
    	mark_ofa_express_server(desc, port, origline, trp);
    else if(strstr(line, "suse meta pppd") != NULL)
    	mark_smppd_server(desc, port, origline, trp);
    else if(strncmp(origline, "ERR UNKNOWN-COMMAND", strlen("ERR UNKNOWN-COMMAND")) == 0)
    	mark_upsmon_server(desc, port, origline, trp);
    else if(strncmp(line, "connected. ", strlen("connected. ")) == 0 &&
    	    strstr(line, "legends") != NULL )
	 mark_sub7_server(desc, port, origline, trp);
   else if(strncmp(line, "spamd/", strlen("spamd/")) == 0)
   	mark_spamd_server(desc, port, origline, trp); 
   else if(strstr(line, " dictd ") && strncmp(line, "220", 3) == 0 )
   	  mark_dictd_server(desc, port, origline, trp);	  	
   else if(strncmp(line, "220 ", 4) == 0 &&
           strstr(line, "vmware authentication daemon") != NULL)
	 mark_vmware_auth(desc, port, origline, trp);
   else if(strncmp(line, "220 ", 4) == 0 &&
   	   strstr(line, "interscan version") != NULL)
	 mark_interscan_viruswall(desc, port, origline, trp); 	
    else if(banner[0] == '~' && banner[strlen(banner) - 1] == '~' &&
            strchr(banner, '}') != NULL)
	    mark_ppp_daemon(desc, port, origline, trp);	
   else if(strstr(banner, "Hello, this is zebra ") != NULL)
   	    mark_zebra_server(desc, port, origline, trp);
   else if(strstr(line, "ircxpro ") != NULL )
   	    mark_ircxpro_admin_server(desc, port, origline, trp);	
   else if(strncmp(origline, "version report", strlen("version report")) == 0)
   	    mark_gnocatan_server(desc, port, origline, trp);     
   else if(strncmp(origline, "RTSP/1.0", strlen("RTSP/1.0")) &&
     	   strstr(origline, "QTSS/") != NULL )
	   mark_quicktime_streaming_server(desc, port, origline, trp);
   else if(origline[0] == 0x30 && origline[1] == 0x11 && origline[2] == 0)
   	   mark_dameware_server(desc, port, origline, trp);	
   else if (strstr(line, "stonegate firewall")	 != NULL )
   	   mark_stonegate_auth_server(desc, port, origline, trp);
   else if(strncmp(line, "pbmasterd", strlen("pbmasterd")) == 0)
   	   mark_pbmaster_server(desc, port, origline, trp);
   else if(strncmp(line, "pblocald", strlen("pblocald")) == 0)
   	  mark_pblocald_server(desc, port, origline, trp);
   else if(strncmp(line, "/c -2 get ctgetoptions", strlen("/c -2 get ctgetoptions")) == 0)
	  mark_avotus_mm_server(desc, port, origline, trp);
   else if(strncmp(line, "error:wrong password", strlen("error:wrong password")) == 0)
   	  mark_pnsclient(desc, port, origline, trp);	
   else if(strncmp(line, "1000      2", strlen("1000      2")) == 0 )
   	  mark_veritas_backup(desc, port, origline, trp);
   else if(strstr(line, "the file name you specified is invalid") && 
           strstr(line, "listserv"))	  
	  mark_listserv_server(desc, port, origline, trp);  
   else if(strncmp(line, "control password:", strlen("control password:")) ==  0)
    	  mark_fssniffer(desc, port, origline, trp);
   else if(strncmp(line, "remotenc control password:", strlen("remotenc control password:")) == 0)
   	 mark_remote_nc_server(desc, port, origline, trp);
    else if(((p = strstr(banner, "finger: GET: no such user")) != NULL &&
	    strstr(banner, "finger: /: no such user") != NULL &&
	    strstr(banner, "finger: HTTP/1.0: no such user") != NULL) ||
	    strstr(banner, "Login       Name               TTY         Idle    When    Where") ||
	    strstr(banner, "Line     User") ||
	    strstr(banner, "Login name: GET"))
      {
	char	c;
	if(p != NULL)
	{
	while (p - banner > 0 && isspace(*p))
	  p --;
	c= *p; *p = '\0';
	}
	mark_finger_server(desc, port, p ? banner : NULL, trp);
	
	if(p != NULL)*p = c;
      }
    else if (banner[0] == 5 && banner[1] <= 8 && 
	     banner[2] == 0 && banner[3] <= 4)
      mark_socks_proxy(desc, port, 5);
    else if (banner[0] == 0 && banner[1] >= 90 && banner[1] <= 93)
      mark_socks_proxy(desc, port, 4);
    else
      unindentified_service = ! flg;
    efree(&line);
   efree(&origline); 
   } /* len >= 0 */
   else
   {
#ifdef DEBUG
     fprintf(stderr, "Could not read anything from port %d\n", port);
#endif
     unindentified_service = 1;
#define TESTSTRING	"Nessus Wrap Test"
     if (trp == NESSUS_ENCAPS_IP && wrap_timeout > 0)
#if 0
       if (write_stream_connection(cnx, TESTSTRING, sizeof(TESTSTRING)-1) <= 0)
#endif
	 maybe_wrapped = 1;
   }
   close_stream_connection(cnx);

#ifdef DETECT_WRAPPED_SVC
   /*
    * I'll clean this later. Meanwhile, we will not print a silly message
    * for rsh and rlogin.
    */
   if (port == 513 /*rlogin*/ || port == 514 /*rsh*/)
     maybe_wrapped = 0;

   if (maybe_wrapped /*&& trp == NESSUS_ENCAPS_IP && wrap_timeout > 0*/)
     {
       time_t	t;
       int	nfd, fd, x, flag = 0;
       char	b;

#ifdef DEBUG
       fprintf(stderr, "Potentially wrapped service on port %d\n", port);
#endif
       nfd = open_stream_connection(desc, port, NESSUS_ENCAPS_IP, cnx_timeout);
       if ( nfd >= 0 )
	 {
	   fd = nessus_get_socket_from_connection(nfd);
#if 0
	   fprintf(stderr, "open_stream_connection(port=%d) succeeded\n", port);
#endif
	   FD_ZERO(&rfds); FD_ZERO(&xfds);
	   FD_SET(fd, &rfds); FD_SET(fd, &xfds);
	   tv.tv_sec = wrap_timeout; tv.tv_usec = 0;

#ifndef MSG_DONTWAIT
	   setNonblocking(fd);
#endif
	   signal(SIGALRM, SIG_IGN);

	   t1 = time(NULL);
	   x = select(fd+1, &rfds, NULL, &xfds, &tv);
	   t2 = time(NULL);
#ifdef DEBUG
	   fprintf(stderr, "select(port=%d)=%d after %d s on %d\n",
		   port, x, t2 - t1, wrap_timeout);
#endif
	   if (x < 0)
	     perror("select");
	   else if (x > 0)
	     {
	       errno = 0;
#ifdef MSG_DONTWAIT	       
	       x = recv(fd, &b, 1, MSG_DONTWAIT);
#else
	       x = recv(fd, &b, 1, 0);
#endif
		 
#if 0
	       fprintf(stderr, "recv(port=%d)=%d\n", port, x);

	       if (x < 0)
		 perror("recv");
		 
#endif

		 
	       if (x == 0 || (x < 0 && errno == EPIPE))
		 {
		   /*
		    * If the service quickly closes the connection when we
		    * send garbage but not when we don't send anything, it 
		    * is not wrapped
		    */
		   flag = 1;
		 }
	     }
	   else
	     {
	       /* Timeout - one last check */
	       errno = 0;
#ifdef MSG_DONTWAIT
	       if (send(fd, "Z", 1,  MSG_DONTWAIT) < 0)
#else
	       if (send(fd, "Z", 1,  0) < 0)
#endif
		 {
		   perror("send");
		   if (errno == EPIPE)
		     flag = 1;
		 }
	     }
	   close_stream_connection(nfd);
	   if (flag)
	     {
	       if ((t2 - t1) <= (2 * delta_t + 1))
		 {
		   mark_wrapped_svc(desc, port, t2 - t1);
		   unindentified_service = 0;
		 }
#ifdef DEBUG
	       else
		 fprintf(stderr, "\
The service on port %d closes the connection in %d s when we send garbage,\n\
and in %d when we just wait. It is  probably not wrapped\n",
			 port, delta_t, t2 - t1);
#endif
	     }
	 }
     }
#endif

   if (unindentified_service && port != 139)
     /* port 139 can't be marked as 'unknown' */
    {
      char	ban[256];
      unknown[num_unknown++] = port;
      mark_unknown_svc(desc, port, banner, trp);
    }
   efree(&banner); 
   }
#ifdef DEBUG   
  else
    fprintf(stderr, "Could not connect to port %d\n", port);
#endif   

  }
  if(h)h = h->next;
  }
    
 return(0);
}



#define MAX_SONS 128

static pid_t sons[MAX_SONS];

static void sigterm(int s)
{
 int i;
 for(i=0;i<MAX_SONS;i++)
 {
  if(sons[i] != 0)kill(sons[i], SIGTERM);
 }
}

static void sigchld(int s)
{
 int i;
 for(i=0;i<MAX_SONS;i++)
 {
  waitpid(sons[i], NULL, WNOHANG);
 }
}

static int fwd_data(int in, int out, pid_t sender)
{
 fd_set rd;
 struct timeval tv;
 char buf[65535];
 
 for(;;)
 {
 tv.tv_sec = 0;
 tv.tv_usec = 1000;
 FD_ZERO(&rd);
 FD_SET(in, &rd);
 if(select(in + 1, &rd, NULL, NULL, &tv) > 0)
 {
  int n = recv_line(in, buf, sizeof(buf));
  int m = 0, e;
  if( n <= 1 )
   return -1;
  else
   {
    while ( m != n )
    {
     e = send(out, buf + m, n - m , 0);
     if( e <= 0 )
      return -1;
     else
      m += e;
    }
   }  
 }
 else break;
 }
 return 0; 
}

int plugin_run(desc)
 struct arglist * desc;
{
 struct arglist * h =  arg_get_value(desc, "key");
 struct arglist * ag;
 struct arglist * sons_args[MAX_SONS];
 int sons_pipe[MAX_SONS][2];
 int num_ports = 0;
 char * num_sons_s = get_plugin_preference(desc, NUM_CHILDREN);
 int num_sons = 10;
 int port_per_son;
 int i;
 char * head = "Ports/tcp/";
 int one_true_pipe = (int)arg_get_value(desc, "pipe");
 int	test_ssl = 0;
 #ifdef HAVE_SSL
  char * key   = get_plugin_preference(desc, KEY_FILE);
  char * cert  = get_plugin_preference(desc, CERT_FILE);
  char * pempass = get_plugin_preference(desc, PEM_PASS);
  char * cafile  = get_plugin_preference(desc, CA_FILE);
  char * test_ssl_s = get_plugin_preference(desc, TEST_SSL_PREF);


 
  if(key && key[0] != '\0')key = (char*)get_plugin_preference_fname(desc, key);
  else key = NULL;
  
  if(cert && cert[0] != '\0')cert = (char*)get_plugin_preference_fname(desc, cert);
  else cert = NULL;
 
  if (cafile && cafile[0] != '\0')cafile = (char*)get_plugin_preference_fname(desc, cafile);
  else cafile = NULL;
  
  test_ssl = 2;
  if (test_ssl_s != NULL)
    if (strcmp(test_ssl_s, "None") == 0)
      test_ssl = 0;
    else if (strcmp(test_ssl_s, "Known SSL ports") == 0)
      test_ssl = 1;

  if(key || cert)
  {
   if(!key)key = cert;
   if(!cert)cert = key;
   plug_set_ssl_cert(desc, cert);
   plug_set_ssl_key(desc, key);
  }

  if (pempass != NULL)
    plug_set_ssl_pem_password(desc, pempass);
  if (cafile != NULL)
    plug_set_ssl_CA_file(desc, cafile);
#endif /* HAVE_SSL */  
  
  
 
  signal(SIGTERM, sigterm);
  signal(SIGCHLD, sigchld);
 if( num_sons_s != NULL )
  num_sons = atoi(num_sons_s);
 
 if(num_sons <= 0)
  num_sons = 10;
  
 if(num_sons > MAX_SONS)
  num_sons = MAX_SONS;
  
 
 
 
 for(i=0;i<num_sons;i++)
 	{
	sons[i] = 0;
	sons_args[i] = NULL;
	}
 
 if( h == NULL ) 
  return 1;
  
 ag = h;
 
 while ( ag->next != NULL )
 {
  if(strncmp(ag->name, head, strlen(head)) == 0)
  	num_ports ++;
  ag = ag->next;
 }

 
 ag = h;
 
 port_per_son = num_ports / num_sons;
 
 
 for (i = 0 ; i < num_sons ; i = i + 1)
 {
  int j;
  
  if( ag->next != NULL)
  {
  for (j = 0 ; j < port_per_son && ag->next != NULL;)
    {
    if(strncmp(ag->name, head, strlen(head)) == 0)	
    	{
	 if(sons_args[i] == NULL)
	  sons_args[i] = emalloc(sizeof(struct arglist));
    	arg_add_value(sons_args[i], ag->name, ag->type, ag->length, ag->value);
	j++;
	}
    ag = ag->next;
   }
  }
  else break;
 }
 
 
 for(i = 0 ; (i < num_ports % num_sons) && ag->next != NULL ; )
 {
  if(strncmp(ag->name, head, strlen(head)) == 0)	
  {
  if(sons_args[i] == NULL)
   sons_args[i] = emalloc(sizeof(struct arglist));
  arg_add_value(sons_args[i], ag->name, ag->type, ag->length, ag->value);
  i ++;
  }
  ag = ag->next;
 }
 
 for(i = 0;i < num_sons; i ++)
 	if(sons_args[i] == NULL)
		break;
	
	
 num_sons = i;		
 

 for (i = 0; i < num_sons; i ++)
 {
  usleep(5000);
  if( sons_args[i] != NULL )
  { 
   socketpair(AF_UNIX, SOCK_STREAM, 0, sons_pipe[i]);
   sons[i] = fork();
   if(sons[i] == 0)
   {
    int old = (int)arg_get_value(desc, "pipe");
    close(old);
    arg_set_value(desc, "pipe", -1, (void*)sons_pipe[i][0]);
    close(sons_pipe[i][1]);
    signal(SIGTERM, _exit);
    plugin_do_run(desc, sons_args[i], test_ssl);
    exit(0);
   }
   else close(sons_pipe[i][0]);
  }
 }
 
 
 
 for(;;)
 {
  int flag = 0;
  fd_set rd;
  struct timeval tv;
  int max = -1;
  int e;
  
  
  FD_ZERO(&rd);
  for (i = 0; i < num_sons ; i ++ )
  { 
   if(sons[i] != 0 && (sons_pipe[i][1] >= 0))
   {
   FD_SET(sons_pipe[i][1], &rd);
   if(sons_pipe[i][1] > max)max = sons_pipe[i][1];
   }
  }
  
again:
  tv.tv_usec = 5000;
  tv.tv_sec  = 0;
  e = select(max + 1, &rd, NULL, NULL, &tv);
  if ( e < 0 && errno == EINTR ) goto again;

  if(e > 0)
  {
   for( i = 0; i< num_sons ; i ++ )
   {
     if(sons[i] != 0 && sons_pipe[i][1] >= 0 && FD_ISSET(sons_pipe[i][1], &rd) != 0)
     { 
      if(fwd_data(sons_pipe[i][1], one_true_pipe, sons[i]) < 0)
      {
       close(sons_pipe[i][1]);
       sons_pipe[i][1] = -1;
       while(waitpid(sons[i], NULL, WNOHANG) && errno == EINTR);
       sons[i] = 0;
      }
     }
  }
 }
 
  for(i=0;i<num_sons;i++)
  {
   if(sons[i] != 0)
   {
    while(waitpid(sons[i], NULL, WNOHANG) && errno == EINTR);
	
    if(kill(sons[i], 0) < 0)
    	{
	fwd_data(sons_pipe[i][1], one_true_pipe, sons[i]);
	close(sons_pipe[i][1]);
	sons_pipe[i][1] = -1;
    	sons[i] = 0;
       }
     else flag ++;
   }
  }
  
  
  if(flag == 0)
  	break;
 }
 
 return 0;
}
