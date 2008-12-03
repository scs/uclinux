///////////////////////////////////////////////////////////////////////////////
//
//  FILE: getopt.h
//
//      Header for the GetOption function
//
//
///////////////////////////////////////////////////////////////////////////////

#ifdef __cplusplus
extern "C" {
#endif

// function prototypes
int GetOption (int argc, char** argv, const char* pszValidOpts, char** ppszParam);

#ifdef __cplusplus
}
#endif
