#include <upnp/upnp.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <signal.h>
#include <sys/stat.h>
#include <time.h>
#include "config.h"
#include "gatedevice.h"
#include "util.h"
#include "pmlist.h"
#include "globals.h"

#define STATE_FILE "/var/run/upnpd.state"

int  g_debug;
char g_downstreamBitrate[10];
char g_extInterfaceName[10];
char g_forwardChainName[20];
int  g_forwardRules;
char g_intInterfaceName[10];
char g_iptables[50];
char g_preroutingChainName[20];
char g_upstreamBitrate[10];

void cleanup(void)
{
	unlink(STATE_FILE);
}

int main (int argc, char** argv)
{
	int ret = UPNP_E_SUCCESS;
	int signal;	
	char descDocUrl[50];
	char descDocName[20];
	char xmlPath[50];
	char intIpAddress[16];     // Server internal ip address
	char extIpAddress[16];     // Server internal ip address
	sigset_t sigsToCatch;
	FILE *f;

	pid_t pid,sid;

	if (argc != 3)
   {
      printf("Usage: upnpd <external ifname> <internal ifname>\n");
      printf("Example: upnpd ppp0 eth0\n");
      printf("Example: upnpd eth1 eth0\n");
      exit(0);
   }

	parseConfigFile(&g_forwardRules,&g_debug,g_iptables,
		        g_forwardChainName,g_preroutingChainName,
			g_upstreamBitrate,g_downstreamBitrate,
			descDocName,xmlPath);
	// Save the interface names for later uses
	strcpy(g_extInterfaceName, argv[1]);
	strcpy(g_intInterfaceName, argv[2]);

	openlog("upnpd", LOG_PID | LOG_CONS, LOG_USER);

	// Get the internal ip address to start the daemon on
	GetIpAddressStr(intIpAddress, g_intInterfaceName);	
	GetIpAddressStr(extIpAddress, g_extInterfaceName);	

	// Put igd in the background as a daemon process.
	pid = fork();
	if (pid < 0)
	{
		perror("Error forking a new process.");
		cleanup();
		exit(EXIT_FAILURE);
	}

	if (pid > 0)
		exit(EXIT_SUCCESS);

	/* if we are here, we know we are the demonized version */

	//open a state file
	f = fopen(STATE_FILE, "w");
	if (!f) {
		syslog(LOG_ERR, "failed to open %s: %m", STATE_FILE);
	} else {
		fprintf(f, "external %s %s\ninternal %s %s\n", g_extInterfaceName,
				extIpAddress, g_intInterfaceName, intIpAddress);
		fclose(f);
	}
	atexit(cleanup);

	if ((sid = setsid()) < 0)
	{
		perror("Error running setsid");
		exit(EXIT_FAILURE);
	}
	if ((chdir("/")) < 0)
	{
		perror("Error setting root directory");
		exit(EXIT_FAILURE);
	}
	
	umask(0);
	close(STDERR_FILENO);
	close (STDIN_FILENO);
	close (STDOUT_FILENO);	


// End Daemon initialization

	// Initialize UPnP SDK on the internal Interface
	if (g_debug) syslog(LOG_DEBUG, "Initializing UPnP SDK ... ");
	if ( (ret = UpnpInit(intIpAddress,0) ) != UPNP_E_SUCCESS)
	{
		syslog (LOG_ERR, "Error Initializing UPnP SDK on IP %s ",intIpAddress);
		syslog (LOG_ERR, "  UpnpInit returned %d", ret);
		UpnpFinish();
		exit(1);
	}
	if (g_debug) syslog(LOG_DEBUG, "UPnP SDK Successfully Initialized.");

	// Set the Device Web Server Base Directory
	if (g_debug) syslog(LOG_DEBUG, "Setting the Web Server Root Directory to %s",xmlPath);
	if ( (ret = UpnpSetWebServerRootDir(xmlPath)) != UPNP_E_SUCCESS )
	{
		syslog (LOG_ERR, "Error Setting Web Server Root Directory to: %s", xmlPath);
		syslog (LOG_ERR, "  UpnpSetWebServerRootDir returned %d", ret); 
		UpnpFinish();
		exit(1);
	}
	if (g_debug) syslog(LOG_DEBUG, "Succesfully set the Web Server Root Directory.");


	// Form the Description Doc URL to pass to RegisterRootDevice
	sprintf(descDocUrl, "http://%s:%d/%s", UpnpGetServerIpAddress(),
				UpnpGetServerPort(), descDocName);

	// Register our IGD as a valid UPnP Root device
	if (g_debug) syslog(LOG_DEBUG, "Registering the root device with descDocUrl %s", descDocUrl);
	if ( (ret = UpnpRegisterRootDevice(descDocUrl, EventHandler, &deviceHandle,
													&deviceHandle)) != UPNP_E_SUCCESS )
	{
		syslog(LOG_ERR, "Error registering the root device with descDocUrl: %s", descDocUrl);
		syslog(LOG_ERR, "  UpnpRegisterRootDevice returned %d", ret);
		UpnpFinish();
		exit(1);
	}

	syslog (LOG_DEBUG, "IGD root device successfully registered.");
	
	// Initialize the state variable table.
	StateTableInit(descDocUrl);
	
	// Record the startup time, for uptime
	startup_time = time(NULL);
	
	// Send out initial advertisements of our device's services with timeouts of 30 minutes
	if ( (ret = UpnpSendAdvertisement(deviceHandle, 1800) != UPNP_E_SUCCESS ))
	{
		syslog(LOG_ERR, "Error Sending Advertisements.  Exiting ...");
		UpnpFinish();
		exit(1);
	}
	syslog(LOG_DEBUG, "Advertisements Sent.  Listening for requests ... ");
	
	// Loop until program exit signals recieved
	// and now also recreate the current portmappings on SIGUSR1
	while (1) {
		sigemptyset(&sigsToCatch);
		sigaddset(&sigsToCatch, SIGINT);
		sigaddset(&sigsToCatch, SIGTERM);
		sigaddset(&sigsToCatch, SIGQUIT);
		sigaddset(&sigsToCatch, SIGABRT);
		sigaddset(&sigsToCatch, SIGHUP);
		sigaddset(&sigsToCatch, SIGUSR1);
		sigaddset(&sigsToCatch, SIGUSR2);
		//sigwait(&sigsToCatch, &signal);
		pthread_sigmask(SIG_SETMASK, &sigsToCatch, NULL);
		sigwait(&sigsToCatch, &signal);
		if (signal == SIGUSR1) {
			syslog(LOG_DEBUG, "signal SIGUSR1 received - rebuilding portmappings\n");
			//rebuild all the portmappings
			pmlist_RecreateAll();
		} else if (signal == SIGHUP || signal == SIGUSR2) {
			//nothing
		} else {
			break;
		}
	}
	syslog(LOG_DEBUG, "Shutting down on signal %d...\n", signal);

	// Cleanup UPnP SDK and free memory
	pmlist_FreeList(); 

	UpnpUnRegisterRootDevice(deviceHandle);
	UpnpFinish();

	// Exit normally
	return (1);
}
