
/*
	bug description
	
	if we use the pthread_attr_setstackaddr( ), then 
	the event signaled status can not be detected by the
	thread
*/


#include <stdio.h>
#include <unistd.h> 
#include <pthread.h>
#include <stdlib.h>
#define SHOW_BUG

static pthread_mutex_t tst_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  tst_event = PTHREAD_COND_INITIALIZER ;

static pthread_t tst_pid;
static void* tst_thread(void*);
static char stackaddr[32*1024];

//-------------------------------------------------------------------------
int main( int argc, char **argv , char **env )
{
	
	pthread_attr_t attr ;
	pthread_attr_init( &attr );
	pthread_attr_setstacksize( &attr, 32*1024 ); 			

	pthread_attr_setstackaddr( &attr, stackaddr + sizeof stackaddr); 
	
	pthread_create( &tst_pid, &attr, tst_thread, 0 );		
	pthread_attr_destroy( &attr);

	sleep( 2 );
	pthread_cond_signal( &tst_event );
	sleep( 2 );
	pthread_join( tst_pid, 0 ) ;

	return 0 ;
}
//----------------------------------------------------------------------------------------
void* tst_thread(void*ref)
{
	pthread_mutex_lock( &tst_mutex );
	pthread_cond_wait(&tst_event, &tst_mutex);
	pthread_mutex_unlock( &tst_mutex );

	fprintf( stdout, "PASS\n" );

	return 0;
}
//------------------------------------------------------------------------------
