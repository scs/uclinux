/* $Id$ */
/* Snort Preprocessor Plugin Source File for XLINK2STATE */

/* spp_xlink2state 
 * 
 * Copyright (C) 2005 Sourcefire,Inc.
 *
 */

#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>
#include <rpc/types.h>

/*
 * If you're going to issue any alerts from this preproc you 
 * should include generators.h and event_wrapper.h
 */
#include "generators.h"
#include "event_wrapper.h"

#include "util.h"
#include "plugbase.h"
#include "parser.h"

/*
 * put in other includes as necessary
 */
#include "debug.h"

/* 
 * your preprocessor header file goes here if necessary, don't forget
 * to include the header file in plugbase.h too!
 */
#include "spp_xlink2state.h"

/*
 * define any needed data structs for things like configuration
 */
#include "xlink2state.h"

/* 
 * If you need to instantiate the preprocessor's 
 * data structure, do it here 
 */

/* 
 * function prototypes go here
 */

static void XLINK2STATEInit(u_char *);
static void XLINK2STATEDetect(Packet *);
static void XLINK2STATECleanExitFunction(int, void *);
static void XLINK2STATERestartFunction(int, void *);



/*
 * Function: SetupXLINK2STATE()
 *
 * Purpose: Registers the preprocessor keyword and initialization 
 *          function into the preprocessor list.  This is the function that
 *          gets called from InitPreprocessors() in plugbase.c.
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 */
void SetupXLINK2STATE()
{
    /* 
     * link the preprocessor keyword to the init function in
     * the preproc list
     */
    RegisterPreprocessor("xlink2state", XLINK2STATEInit);
}


/*
 * Function: XLINK2STATEInit(u_char *)
 *
 * Purpose: Calls the argument parsing function, performs final setup on data
 *          structs, links the preproc function into the function list.
 *
 * Arguments: args => ptr to argument string
 *
 * Returns: void function
 *
 */
static void XLINK2STATEInit(u_char *args)
{
    int bFirstConfig = 1;

    /* 
     * Parse the argument list from the rules file 
     */
    XLINK2STATE_ParseArgs(args);

    /* 
     * Perform any other initialization functions that are required here
     */
    XLINK2STATE_Init();

    /* 
     * Put the preprocessor function into the function list 
     */
    if ( bFirstConfig )
    {
        AddFuncToPreprocList(XLINK2STATEDetect);
        AddFuncToCleanExitList(XLINK2STATECleanExitFunction, NULL);
        AddFuncToRestartList(XLINK2STATERestartFunction, NULL);
        bFirstConfig = 0;
    }
}




/*
 * Function: XLINK2STATEDetect(Packet *)
 *
 * Purpose: Perform the preprocessor's intended function.  This can be
 *          simple (statistics collection) or complex (IP defragmentation)
 *          as you like.  Try not to destroy the performance of the whole
 *          system by trying to do too much....
 *
 * Arguments: p => pointer to the current packet data struct 
 *
 * Returns: void function
 *
 */
static void XLINK2STATEDetect(Packet *p)
{
    if(!PacketIsTCP(p))
    {
        return;
    }

    SnortXLINK2STATE(p);

    /* 
     * if you need to issue an alert from your preprocessor, check out 
     * event_wrapper.h, there are some useful helper functions there
     */
}


/* 
 * Function: XLINK2STATECleanExitFunction(int, void *)
 *
 * Purpose: This function gets called when Snort is exiting, if there's
 *          any cleanup that needs to be performed (e.g. closing files)
 *          it should be done here.
 *
 * Arguments: signal => the code of the signal that was issued to Snort
 *            data => any arguments or data structs linked to this 
 *                    function when it was registered, may be
 *                    needed to properly exit
 *       
 * Returns: void function
 */                   
static void XLINK2STATECleanExitFunction(int signal, void *data)
{    
    
}


/* 
 * Function: XLINK2STATERestartFunction(int, void *)
 *
 * Purpose: This function gets called when Snort is restarting on a SIGHUP,
 *          if there's any initialization or cleanup that needs to happen
 *          it should be done here.
 *
 * Arguments: signal => the code of the signal that was issued to Snort
 *            data => any arguments or data structs linked to this 
 *                    functioin when it was registered, may be
 *                    needed to properly exit
 *       
 * Returns: void function
 */                   
static void XLINK2STATERestartFunction(int signal, void *foo)
{
       /* restart code goes here */
}


