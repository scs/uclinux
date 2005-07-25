/**
**  @file       preproc_setup.c
**  
**  @author     Daniel Roelker <droelker@sourcefire.com>
**
**  @brief      This file initializes HttpInspect as a Snort 
**              preprocessor.
**
**  This file registers the HttpInspect initialization function,
**  adds the HttpInspect function into the preprocessor list, reads
**  the user configuration in the snort.conf file, and prints out
**  the configuration that is read.
**
**  In general, this file is a wrapper to HttpInspect functionality,
**  by interfacing with the Snort preprocessor functions.  The rest
**  of HttpInspect should be separate from the preprocessor hooks.
**
**  NOTES
**
**  - 2.10.03:  Initial Development.  DJR
*/

#include <string.h>
#include <sys/types.h>

#include "decode.h"
#include "plugbase.h"
#include "debug.h"
#include "util.h"

#include "hi_ui_config.h"
#include "hi_client.h"
#include "hi_norm.h"
#include "snort_httpinspect.h"

/*
**  Defines for preprocessor initialization
*/
/**
**  snort.conf preprocessor keyword
*/
#define GLOBAL_KEYWORD   "http_inspect"
#define SERVER_KEYWORD   "http_inspect_server"

/**
**  The length of the error string buffer.
*/
#define ERRSTRLEN 1000

/*
**  External Global Variables
**  Variables that we need from Snort to log errors correctly and such.
*/
extern char *file_name;
extern char *file_line;
extern HttpUri UriBufs[URI_COUNT];

/*
**  Global Variables
**  This is the only way to work with Snort preprocessors because
**  the user configuration must be kept between the Init function
**  the actual preprocessor.  There is no interaction between the
**  two except through global variable usage.
*/
HTTPINSPECT_GLOBAL_CONF GlobalConf;

/*
**  NAME
**    HttpInspect::
*/
/**
**  This function wraps the functionality in the generic HttpInspect
**  processing.  We get a Packet structure and pass this into the
**  HttpInspect module where the first stage in HttpInspect is the
**  Session Inspection stage where most of the other Snortisms are
**  taken care of.  After that, the modules should be fairly generic,
**  and that's what we're trying to do here.
**
**  @param p a Packet structure that contains Snort info about the
**  packet.
**
**  @return void
*/
static void HttpInspect(Packet *p)
{
    /*
    **  IMPORTANT:
    **  This is where we initialize any variables that can impact other
    **  aspects of detection/processing.
    **
    **  First thing that we do is reset the p->uri_count to zero, so there
    **  is no way that we would inspect a buffer that was completely bogus.
    */
    p->uri_count = 0;
    UriBufs[0].decode_flags = 0;

    /*
    **  Check for valid packet
    **  if neither header or data is good, then we just abort.
    */
    if(!p->iph || !p->tcph || !p->data || !p->dsize)
    {
        return;
    }

    if(!(p->preprocessors & PP_HTTPINSPECT))
        return;

    /*
    **  Pass in the configuration and the packet.
    */
    SnortHttpInspect(&GlobalConf, p);

    p->uri_count = 0;
    UriBufs[0].decode_flags = 0;

    return;
}

/*
**  NAME
**    HttpInspectInit::
*/
/**
**  This function initializes HttpInspect with a user configuration.
**
**  The function is called when HttpInspect is configured in 
**  snort.conf.  It gets passed a string of arguments, which gets
**  parsed into configuration constructs that HttpInspect understands.
**
**  This function gets called for every HttpInspect configure line.  We
**  use this characteristic to split up the configuration, so each line
**  is a configuration construct.  We need to keep track of what part
**  of the configuration has been configured, so we don't configure one
**  part, then configure it again.
**
**  Any upfront memory is allocated here (if necessary).
**
**  @param args a string to the preprocessor arguments.
**
**  @return void
*/
static void HttpInspectInit(u_char *args)
{
    char ErrorString[ERRSTRLEN];
    int  iErrStrLen = ERRSTRLEN;
    int  iRet;
    static int siFirstConfig = 1;
    int  iGlobal = 0;

    if(siFirstConfig)
    {
        if((iRet = hi_ui_config_init_global_conf(&GlobalConf)))
        {
            snprintf(ErrorString, iErrStrLen,
                    "Error initializing Global Configuration.");
            FatalError("%s(%d) => %s\n", file_name, file_line, ErrorString);

            return;
        }

        if((iRet = hi_ui_config_default(&GlobalConf)))
        {
            snprintf(ErrorString, iErrStrLen,
                    "Error configuring default global configuration.");
            FatalError("%s(%d) => %s\n", file_name, file_line, ErrorString);

            return;
        }

        if((iRet = hi_client_init(&GlobalConf)))
        {
            snprintf(ErrorString, iErrStrLen,
                    "Error initializing client module.");
            FatalError("%s(%d) => %s\n", file_name, file_line, ErrorString);

            return;
        }

        if((iRet = hi_norm_init(&GlobalConf)))
        {
            snprintf(ErrorString, iErrStrLen,
                     "Error initializing normalization module.");
            FatalError("%s(%d) => %s\n", file_name, file_line, ErrorString);

            return;
        }

        /*
        **  We set the global configuration variable
        */
        iGlobal = 1;
    }
    
    if((iRet = HttpInspectSnortConf(&GlobalConf, args, iGlobal,
                    ErrorString, iErrStrLen)))
    {
        if(iRet > 0)
        {
            /*
            **  Non-fatal Error
            */
            if(ErrorString)
            {
                ErrorMessage("%s(%d) => %s\n", 
                        file_name, file_line, ErrorString);
            }
        }
        else
        {
            /*
            **  Fatal Error, log error and exit.
            */
            if(ErrorString)
            {
                FatalError("%s(%d) => %s\n", 
                        file_name, file_line, ErrorString);
            }
            else
            {
                /*
                **  Check if ErrorString is undefined.
                */
                if(iRet == -2)
                {
                    FatalError("%s(%d) => ErrorString is undefined.\n", 
                            file_name, file_line);
                }
                else
                {
                    FatalError("%s(%d) => Undefined Error.\n", 
                            file_name, file_line);
                }
            }
        }
    }

    /*
    **  Only add the functions one time to the preproc list.
    */
    if(siFirstConfig)
    {
        /*
        **  Add HttpInspect into the preprocessor list
        */
        AddFuncToPreprocList(HttpInspect);

        /*
        **  Remember to add any cleanup functions into the appropriate
        **  lists.
        */

        siFirstConfig = 0;
    }
    
    return;
}

/*
**  NAME
**    SetupHttpInspect::
*/
/**
**  This function initializes HttpInspect as a Snort preprocessor.
**
**  It registers the preprocessor keyword for use in the snort.conf
**  and sets up the initialization module for the preprocessor, in
**  case it is configured.
**
**  This function must be called in InitPreprocessors() in plugbase.c
**  in order to be recognized by Snort.
**
**  @param none
**
**  @return void
*/
void SetupHttpInspect()
{
    RegisterPreprocessor(GLOBAL_KEYWORD, HttpInspectInit);
    RegisterPreprocessor(SERVER_KEYWORD, HttpInspectInit);

    DEBUG_WRAP(DebugMessage(DEBUG_HTTPINSPECT, "Preprocessor: HttpInspect is "
                "setup . . .\n"););
}
