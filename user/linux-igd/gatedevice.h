#ifndef _GATEDEVICE_H_
	#define _GATEDEVICE_H_ 1

#include <upnp/upnp.h>


// IGD Device Globals
extern UpnpDevice_Handle deviceHandle;
extern char *gateUDN;
extern long int startup_time;

// State Variables
extern char ConnectionType[50];
extern char PossibleConnectionTypes[50];
extern char ConnectionStatus[20];
extern long int StartupTime;
extern char LastConnectionError[35];
extern long int AutoDisconnectTime;
extern long int IdleDisconnectTime;
extern long int WarnDisconnectDelay;
extern int RSIPAvailable;
extern int NATEnabled;
extern char ExternalIPAddress[20];
extern int PortMappingNumberOfEntries;
extern int PortMappingEnabled;

// Helper routines
extern char* GetFirstDocumentItem( IN IXML_Document * doc, const char *item );

// Linked list for portmapping entries
extern struct portMap *pmlist_Head;
extern struct portMap *pmlist_Current;

// WanIPConnection Actions 
extern int EventHandler(Upnp_EventType EventType, void *Event, void *Cookie);
extern int StateTableInit(char *descDocUrl);
extern int HandleSubscriptionRequest(struct Upnp_Subscription_Request *sr_event);
extern int HandleGetVarRequest(struct Upnp_State_Var_Request *gv_event);
extern int HandleActionRequest(struct Upnp_Action_Request *ca_event);

extern int GetConnectionTypeInfo(struct Upnp_Action_Request *ca_event);
extern int GetNATRSIPStatus(struct Upnp_Action_Request *ca_event);
extern int SetConnectionType(struct Upnp_Action_Request *ca_event);
extern int RequestConnection(struct Upnp_Action_Request *ca_event);
extern int GetTotalBytesSent(struct Upnp_Action_Request *ca_event);
extern int GetTotalBytesReceived(struct Upnp_Action_Request *ca_event);
extern int GetTotalPacketsSent(struct Upnp_Action_Request *ca_event);
extern int GetTotalPacketsReceived(struct Upnp_Action_Request *ca_event);
extern int GetCommonLinkProperties(struct Upnp_Action_Request *ca_event);
extern int InvalidAction(struct Upnp_Action_Request *ca_event);
extern int GetStatusInfo(struct Upnp_Action_Request *ca_event);
extern int AddPortMapping(struct Upnp_Action_Request *ca_event);
extern int GetGenericPortMappingEntry(struct Upnp_Action_Request *ca_event);
extern int GetSpecificPortMappingEntry(struct Upnp_Action_Request *ca_event);
extern int GetExternalIPAddress(struct Upnp_Action_Request *ca_event);
extern int DeletePortMapping(struct Upnp_Action_Request *ca_event);

#endif //_GATEDEVICE_H
