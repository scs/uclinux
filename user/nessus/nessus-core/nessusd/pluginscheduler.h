#ifndef PLUGINSCHEDULER_H
#define PLUGINSCHEDULER_H

#ifndef IN_SCHEDULER_CODE
typedef void * plugins_scheduler_t;
#else

struct hash {
	char * name;
	struct arglist * plugin;
	char ** dependencies;
	int num_deps;
	char ** ports;
	struct hash * next;
	};

struct list {
	char * name;
	struct arglist * plugin;
	struct list * next;
	struct list * prev;
	};
	
struct plist {
	char name[32];
	int occurences;
	struct plist * next;
	struct plist * prev;
	};	

struct plugins_scheduler_struct {
	struct hash  * hash;			/* Hash list of the plugins   */
	struct list  * list[ACT_LAST+1];	/* Linked list of the plugins */
	struct plist * plist; 			/* Ports currently in use     */
	};
	
typedef struct plugins_scheduler_struct * plugins_scheduler_t;

#endif


#define PLUG_RUNNING ((struct arglist*)0x02)
#define PLUGIN_STATUS_UNRUN 		1
#define PLUGIN_STATUS_RUNNING		2
#define PLUGIN_STATUS_DONE		3
#define PLUGIN_STATUS_DONE_AND_CLEANED 	4



void plugin_set_running_state(struct arglist * , int);


plugins_scheduler_t plugins_scheduler_init(struct arglist*, int);
struct arglist * plugins_scheduler_next(plugins_scheduler_t);

void plugins_scheduler_free(plugins_scheduler_t);

#endif
